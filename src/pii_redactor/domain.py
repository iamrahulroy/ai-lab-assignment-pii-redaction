from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


@dataclass(frozen=True)
class MappingRecord:
    entity_type: str
    original: str
    replacement: str


@dataclass(frozen=True)
class DetectedEntity:
    entity_type: str
    start: int
    end: int
    score: float
    recognizer_name: str
    context: str | None = None


@dataclass(frozen=True)
class TextReplacement:
    start: int
    end: int
    value: str


@dataclass(frozen=True)
class PseudonymizedText:
    text: str
    replacements: tuple[TextReplacement, ...]


@dataclass(frozen=True)
class RedactionResult:
    output_path: Path
    mappings: tuple[MappingRecord, ...]


class TextPseudonymizer(Protocol):
    def pseudonymize(
        self, text: str, registry: "PseudonymRegistry"
    ) -> PseudonymizedText:
        ...


class DocumentRedactor(Protocol):
    def redact(
        self,
        source_path: Path,
        output_path: Path,
        transform: Callable[[str], PseudonymizedText],
    ) -> None:
        ...


class PseudonymRegistry(Protocol):
    def replacement_for(self, entity_type: str, original: str) -> str:
        ...

    @property
    def records(self) -> tuple[MappingRecord, ...]:
        ...


class PiiDetector(Protocol):
    def detect(
        self, text: str, entities: tuple[str, ...] | None = None
    ) -> tuple[DetectedEntity, ...]:
        ...
