from pii_redactor.application import (
    BundleServices,
    CreateRedactionBundle,
    RedactDocument,
)
from pii_redactor.configuration import RedactionConfig
from pii_redactor.docx_adapter import DocxRedactor
from pii_redactor.mapping_store import EncryptedMappingStore
from pii_redactor.publishing import AtomicBundlePublisher
from pii_redactor.presidio_adapter import (
    PresidioDetector,
    build_presidio_detector,
    build_presidio_pseudonymizer,
)
from pii_redactor.validation import DocxValidationSuite


SUPPORTED_CONFIG_VERSION = "1"
SUPPORTED_MODEL_VERSION = "en_core_web_lg-3.8.0"


def build_pii_detector(deny_lists=None) -> PresidioDetector:
    return build_presidio_detector(deny_lists)


def build_redact_document(seed: int, deny_lists=None) -> RedactDocument:
    detector = build_pii_detector(deny_lists)
    return RedactDocument(
        document_redactor=DocxRedactor(),
        text_pseudonymizer=build_presidio_pseudonymizer(detector),
        seed=seed,
    )


def build_redaction_bundle(
    config: RedactionConfig, seed: int
) -> CreateRedactionBundle:
    if config.config_version != SUPPORTED_CONFIG_VERSION:
        raise ValueError("Unsupported redaction configuration version")
    if config.model_version != SUPPORTED_MODEL_VERSION:
        raise ValueError("Configured model version is not installed")
    return CreateRedactionBundle(
        config=config,
        services=BundleServices(
            redact_document=build_redact_document(seed, config.deny_lists),
            mapping_store=EncryptedMappingStore(),
            validator=DocxValidationSuite(),
            publisher=AtomicBundlePublisher(),
        ),
    )
