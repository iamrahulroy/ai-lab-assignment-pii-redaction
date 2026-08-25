from datetime import datetime

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


EMAIL_ADDRESS = "EMAIL_ADDRESS"
PHYSICAL_ADDRESS = "PHYSICAL_ADDRESS"
DATE_OF_BIRTH = "DATE_OF_BIRTH"
IN_DIN = "IN_DIN"
IN_CIN = "IN_CIN"

EMAIL_PATTERN = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b"
ADDRESS_PATTERN = (
    r"\b(?:[A-Z0-9][A-Za-z0-9 .#/-]{1,40},[ \t]*(?:\r?\n)?){0,2}"
    r"\d{1,5}[A-Za-z]?(?:[ \t]+[A-Za-z0-9.-]+){0,6}[ \t]+"
    r"(?:Road|Rd|Street|St|Avenue|Ave|Lane|Ln|Boulevard|Blvd|Highway|Nagar)"
    r"(?:,[ \t]*(?:\r?\n)?[A-Za-z][A-Za-z.-]*"
    r"(?:[ \t]+[A-Za-z][A-Za-z.-]*)*){1,3}"
    r"(?:[ \t]+\d{5,6}(?:-\d{4})?)?\b"
)

DOB_PATTERNS = (
    Pattern(
        "Day month name year",
        r"\b(?:0?[1-9]|[12]\d|3[01])\s+[A-Z]{3,9}\s+(?:19|20)\d{2}\b",
        0.75,
    ),
    Pattern(
        "Day month year",
        r"\b(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])"
        r"[-/.](?:19|20)\d{2}\b",
        0.75,
    ),
    Pattern(
        "ISO date",
        r"\b(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])"
        r"[-/.](?:0[1-9]|[12]\d|3[01])\b",
        0.75,
    ),
)
DOB_FORMATS = (
    "%d %B %Y",
    "%d %b %Y",
    "%d/%m/%Y",
    "%d-%m-%Y",
    "%d.%m.%Y",
    "%Y/%m/%d",
    "%Y-%m-%d",
    "%Y.%m.%d",
)


class DateOfBirthRecognizer(PatternRecognizer):
    def __init__(self) -> None:
        super().__init__(
            supported_entity=DATE_OF_BIRTH,
            name="Context-required date of birth recognizer",
            patterns=list(DOB_PATTERNS),
        )
        self._required_context = ("date of birth", "birth date", "born", "dob")

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts=None, regex_flags=None
    ) -> list[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        return [item for item in results if self._has_context(text, item)]

    def validate_result(self, pattern_text: str) -> bool:
        return any(
            self._matches_format(pattern_text, item) for item in DOB_FORMATS
        )

    def _has_context(self, text: str, result: RecognizerResult) -> bool:
        window = text[max(0, result.start - 40) : result.end + 10].casefold()
        context = next(
            (item for item in self._required_context if item in window), None
        )
        if context is None:
            return False
        result.analysis_explanation.set_supportive_context_word(context)
        return True

    @staticmethod
    def _matches_format(value: str, date_format: str) -> bool:
        try:
            datetime.strptime(value, date_format)
        except ValueError:
            return False
        return True


def build_custom_recognizers() -> tuple[PatternRecognizer, ...]:
    return (
        PatternRecognizer(
            supported_entity=EMAIL_ADDRESS,
            name="Assignment email recognizer",
            patterns=[Pattern("Email address", EMAIL_PATTERN, 0.85)],
            context=["email", "contact"],
        ),
        PatternRecognizer(
            supported_entity=PHYSICAL_ADDRESS,
            name="Structured physical address recognizer",
            patterns=[Pattern("Street and locality address", ADDRESS_PATTERN, 0.75)],
            context=["address", "office", "registered", "mailing"],
        ),
        DateOfBirthRecognizer(),
        PatternRecognizer(
            supported_entity=IN_DIN,
            name="Indian director identification number recognizer",
            patterns=[Pattern("Eight digit DIN", r"\b\d{8}\b", 0.45)],
            context=["din", "director identification number"],
        ),
        PatternRecognizer(
            supported_entity=IN_CIN,
            name="Indian corporate identity number recognizer",
            patterns=[
                Pattern(
                    "Twenty-one character CIN",
                    r"\b[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b",
                    0.75,
                )
            ],
            context=["cin", "corporate identity number"],
        ),
    )
