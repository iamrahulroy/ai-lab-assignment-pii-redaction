from pathlib import Path

from pii_redactor.domain import DocumentRedactor, RedactionResult, TextPseudonymizer
from pii_redactor.pseudonyms import DocumentPseudonymRegistry


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
