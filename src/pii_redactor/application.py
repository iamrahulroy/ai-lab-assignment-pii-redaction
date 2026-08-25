import hashlib
import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pii_redactor.configuration import RedactionConfig
from pii_redactor.domain import (
    DocumentRedactor,
    MappingDocument,
    MappingMetadata,
    OutputBundle,
    RedactionResult,
    TextPseudonymizer,
    ValidationResult,
)
from pii_redactor.mapping_store import MappingEncryptionKey
from pii_redactor.pseudonyms import DocumentPseudonymRegistry


OUTPUT_DOCUMENT_NAME = "redacted_prospectus.docx"
MAPPING_NAME = "redaction_mapping.json.enc"
AUDIT_NAME = "audit_report.json"


class RedactDocument:
    def __init__(
        self,
        document_redactor: DocumentRedactor,
        text_pseudonymizer: TextPseudonymizer,
        seed: int,
    ) -> None:
        self._document_redactor = document_redactor
        self._text_pseudonymizer = text_pseudonymizer
        self._seed = seed

    def execute(self, source_path: Path, output_path: Path) -> RedactionResult:
        source_path = Path(source_path)
        output_path = Path(output_path)
        if source_path.resolve() == output_path.resolve():
            raise ValueError("Input and output paths must be different")

        registry = DocumentPseudonymRegistry(self._seed)
        self._document_redactor.redact(
            source_path,
            output_path,
            lambda text: self._text_pseudonymizer.pseudonymize(text, registry),
        )
        return RedactionResult(output_path=output_path, mappings=registry.records)


class MappingStore(Protocol):
    def save(
        self,
        path: Path,
        document: MappingDocument,
        key: MappingEncryptionKey,
    ) -> None:
        ...

    def load(
        self, path: Path, key: MappingEncryptionKey
    ) -> MappingDocument:
        ...


class RedactionExecutor(Protocol):
    def execute(self, source_path: Path, output_path: Path) -> RedactionResult:
        ...


class ValidationSuite(Protocol):
    def validate(
        self,
        source_path: Path,
        output_path: Path,
        mapping: MappingDocument,
    ) -> ValidationResult:
        ...


class BundlePublisher(Protocol):
    def publish(
        self, destination: Path, build: Callable[[Path], None]
    ) -> Path:
        ...


@dataclass(frozen=True)
class BundleServices:
    redact_document: RedactionExecutor
    mapping_store: MappingStore
    validator: ValidationSuite
    publisher: BundlePublisher


class CreateRedactionBundle:
    def __init__(
        self,
        config: RedactionConfig,
        services: BundleServices,
    ) -> None:
        self._config = config
        self._services = services

    def execute(
        self,
        source_path: Path,
        output_directory: Path,
        key: MappingEncryptionKey,
    ) -> OutputBundle:
        source_path = Path(source_path)
        output_directory = Path(output_directory)
        source_hash = _sha256(source_path)

        def build(stage: Path) -> None:
            self._build_stage(stage, source_path, source_hash, key)

        published = self._services.publisher.publish(output_directory, build)
        return OutputBundle(
            directory=published,
            document_path=published / OUTPUT_DOCUMENT_NAME,
            mapping_path=published / MAPPING_NAME,
            audit_path=published / AUDIT_NAME,
        )

    def _build_stage(
        self,
        stage: Path,
        source_path: Path,
        source_hash: str,
        key: MappingEncryptionKey,
    ) -> None:
        started = time.perf_counter()
        output_path = stage / OUTPUT_DOCUMENT_NAME
        redaction_started = time.perf_counter()
        result = self._services.redact_document.execute(source_path, output_path)
        redaction_ms = _elapsed_ms(redaction_started)
        mapping = MappingDocument(
            metadata=MappingMetadata(
                source_sha256=source_hash,
                output_sha256=_sha256(output_path),
                config_version=self._config.config_version,
                model_version=self._config.model_version,
            ),
            mappings=result.mappings,
        )
        validation_started = time.perf_counter()
        validation = self._services.validator.validate(
            source_path, output_path, mapping
        )
        validation_ms = _elapsed_ms(validation_started)
        mapping_path = stage / MAPPING_NAME
        self._services.mapping_store.save(mapping_path, mapping, key)
        if self._services.mapping_store.load(mapping_path, key) != mapping:
            raise ValueError("Encrypted mapping verification failed")
        audit = _safe_audit(
            mapping,
            validation,
            redaction_ms=redaction_ms,
            validation_ms=validation_ms,
            staging_ms=_elapsed_ms(started),
        )
        serialized_audit = json.dumps(audit, indent=2, sort_keys=True) + "\n"
        _assert_audit_is_safe(serialized_audit, mapping)
        (stage / AUDIT_NAME).write_text(serialized_audit, encoding="utf-8")


def _safe_audit(
    mapping: MappingDocument,
    validation: ValidationResult,
    **timings_ms: int,
) -> dict[str, object]:
    counts = Counter()
    for record in mapping.mappings:
        counts[record.entity_type] += record.occurrences
    metadata = mapping.metadata
    return {
        "status": "success",
        "source_sha256": metadata.source_sha256,
        "output_sha256": metadata.output_sha256,
        "config_version": metadata.config_version,
        "model_version": metadata.model_version,
        "mapping_schema_version": metadata.schema_version,
        "entity_counts": dict(sorted(counts.items())),
        "total_entities": sum(counts.values()),
        "unique_mappings": len(mapping.mappings),
        "warnings": list(validation.warnings),
        "timings_ms": timings_ms,
    }


def _elapsed_ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1_000)


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _assert_audit_is_safe(audit: str, mapping: MappingDocument) -> None:
    sensitive_values = (
        value.casefold()
        for record in mapping.mappings
        for value in (record.original, record.replacement)
    )
    normalized_audit = audit.casefold()
    if any(value in normalized_audit for value in sensitive_values):
        raise ValueError("Audit contains sensitive mapping values")
