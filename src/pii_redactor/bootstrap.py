from pii_redactor.application import RedactDocument
from pii_redactor.docx_adapter import DocxRedactor
from pii_redactor.presidio_adapter import (
    PresidioDetector,
    build_presidio_detector,
    build_presidio_pseudonymizer,
)


def build_pii_detector() -> PresidioDetector:
    return build_presidio_detector()


def build_redact_document(seed: int) -> RedactDocument:
    detector = build_pii_detector()
    return RedactDocument(
        document_redactor=DocxRedactor(),
        text_pseudonymizer=build_presidio_pseudonymizer(detector),
        seed=seed,
    )
