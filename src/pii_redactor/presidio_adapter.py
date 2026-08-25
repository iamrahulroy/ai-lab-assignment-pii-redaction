from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    InAadhaarRecognizer,
    InPanRecognizer,
    IpRecognizer,
    PhoneRecognizer,
    UsSsnRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from pii_redactor.detection import (
    SUPPORTED_ENTITY_TYPES,
    DeterministicDetectionResolver,
)
from pii_redactor.domain import (
    DetectedEntity,
    PiiDetector,
    PseudonymizedText,
    PseudonymRegistry,
    TextReplacement,
)
from pii_redactor.recognizers import build_custom_recognizers


class PresidioDetector:
    def __init__(
        self, analyzer: AnalyzerEngine, resolver: DeterministicDetectionResolver
    ) -> None:
        self._analyzer = analyzer
        self._resolver = resolver

    def detect(
        self, text: str, entities: tuple[str, ...] | None = None
    ) -> tuple[DetectedEntity, ...]:
        requested = list(entities or SUPPORTED_ENTITY_TYPES)
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=requested,
            return_decision_process=True,
        )
        return self._resolver.resolve(text, results)


class PresidioPseudonymizer:
    def __init__(self, detector: PiiDetector, anonymizer: AnonymizerEngine) -> None:
        self._detector = detector
        self._anonymizer = anonymizer

    def pseudonymize(
        self, text: str, registry: PseudonymRegistry
    ) -> PseudonymizedText:
        findings = self._detector.detect(text)
        if not findings:
            return PseudonymizedText(text=text, replacements=())

        operators = {
            item.entity_type: self._operator_for(item.entity_type, registry)
            for item in findings
        }
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=[self._as_anonymizer_result(item) for item in findings],
            operators=operators,
        )
        replacements = tuple(
            TextReplacement(
                start=item.start,
                end=item.end,
                value=registry.existing_replacement_for(
                    item.entity_type, text[item.start : item.end]
                ),
            )
            for item in findings
        )
        return PseudonymizedText(text=anonymized.text, replacements=replacements)

    @staticmethod
    def _operator_for(
        entity_type: str, registry: PseudonymRegistry
    ) -> OperatorConfig:
        return OperatorConfig(
            "custom",
            {
                "lambda": lambda original: registry.replacement_for(
                    entity_type, original
                )
            },
        )

    @staticmethod
    def _as_anonymizer_result(entity: DetectedEntity) -> RecognizerResult:
        return RecognizerResult(
            entity_type=entity.entity_type,
            start=entity.start,
            end=entity.end,
            score=entity.score,
        )


def build_presidio_detector() -> PresidioDetector:
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": {
                    "PER": "PERSON",
                    "PERSON": "PERSON",
                    "ORG": "ORGANIZATION",
                },
                "default_score": 0.85,
                "labels_to_ignore": [
                    "CARDINAL",
                    "DATE",
                    "EVENT",
                    "FAC",
                    "GPE",
                    "LANGUAGE",
                    "LAW",
                    "LOC",
                    "MONEY",
                    "NORP",
                    "ORDINAL",
                    "PERCENT",
                    "PRODUCT",
                    "QUANTITY",
                    "TIME",
                    "WORK_OF_ART",
                ],
            },
        }
    ).create_engine()
    registry = RecognizerRegistry(supported_languages=["en"])
    recognizers = (
        *build_custom_recognizers(),
        PhoneRecognizer(
            context=["phone", "telephone", "mobile", "contact"],
            supported_regions=("IN", "US", "GB"),
        ),
        CreditCardRecognizer(),
        UsSsnRecognizer(),
        IpRecognizer(),
        InPanRecognizer(),
        InAadhaarRecognizer(),
    )
    for recognizer in recognizers:
        registry.add_recognizer(recognizer)
    registry.add_nlp_recognizer(nlp_engine)
    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["en"],
        default_score_threshold=0,
        log_decision_process=False,
    )
    return PresidioDetector(analyzer, DeterministicDetectionResolver())


def build_presidio_pseudonymizer(
    detector: PiiDetector,
) -> PresidioPseudonymizer:
    return PresidioPseudonymizer(detector, AnonymizerEngine())
