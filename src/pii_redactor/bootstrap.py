from pii_redactor.application import RedactDocument
from pii_redactor.docx_adapter import DocxRedactor
from pii_redactor.presidio_adapter import build_presidio_email_pseudonymizer


def build_redact_document(seed: int) -> RedactDocument:
    return RedactDocument(
        document_redactor=DocxRedactor(),
        text_pseudonymizer=build_presidio_email_pseudonymizer(),
        seed=seed,
    )
