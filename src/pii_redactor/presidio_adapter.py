from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from pii_redactor.domain import (
    PseudonymizedText,
    PseudonymRegistry,
    TextReplacement,
)


EMAIL_ADDRESS = "EMAIL_ADDRESS"


class PresidioEmailPseudonymizer:
    def __init__(self, analyzer: AnalyzerEngine, anonymizer: AnonymizerEngine) -> None:
        self._analyzer = analyzer
        self._anonymizer = anonymizer

    def pseudonymize(
        self, text: str, registry: PseudonymRegistry
    ) -> PseudonymizedText:
        findings = self._analyzer.analyze(
            text=text,
            language="en",
            entities=[EMAIL_ADDRESS],
        )
        if not findings:
            return PseudonymizedText(text=text, replacements=())

        operator = OperatorConfig(
            "custom",
            {
                "lambda": lambda original: registry.replacement_for(
                    EMAIL_ADDRESS, original
                )
            },
        )
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators={EMAIL_ADDRESS: operator},
        )
        replacements = tuple(
            TextReplacement(
                start=finding.start,
                end=finding.end,
                value=registry.replacement_for(
                    finding.entity_type, text[finding.start : finding.end]
                ),
            )
            for finding in findings
        )
        return PseudonymizedText(text=anonymized.text, replacements=replacements)


def build_presidio_email_pseudonymizer() -> PresidioEmailPseudonymizer:
    recognizer = PatternRecognizer(
        supported_entity=EMAIL_ADDRESS,
        name="Assignment email recognizer",
        patterns=[
            Pattern(
                name="Email address",
                regex=r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
                score=0.85,
            )
        ],
        context=["email", "contact"],
    )
    registry = RecognizerRegistry(
        recognizers=[recognizer], supported_languages=["en"]
    )
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        }
    ).create_engine()
    analyzer = AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["en"],
    )
    return PresidioEmailPseudonymizer(analyzer, AnonymizerEngine())
