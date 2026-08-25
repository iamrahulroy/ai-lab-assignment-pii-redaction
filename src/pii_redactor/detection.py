import re
from collections.abc import Iterable

from presidio_analyzer import RecognizerResult

from pii_redactor.domain import DetectedEntity


MANDATORY_ENTITY_TYPES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "ORGANIZATION",
    "PHYSICAL_ADDRESS",
    "US_SSN",
    "CREDIT_CARD",
    "DATE_OF_BIRTH",
    "IP_ADDRESS",
)

DOCUMENT_EXTENSION_TYPES = ("IN_PAN", "IN_AADHAAR", "IN_DIN", "IN_CIN")
SUPPORTED_ENTITY_TYPES = MANDATORY_ENTITY_TYPES + DOCUMENT_EXTENSION_TYPES

MINIMUM_SCORES = {
    "PERSON": 0.60,
    "EMAIL_ADDRESS": 0.80,
    "PHONE_NUMBER": 0.60,
    "ORGANIZATION": 0.55,
    "PHYSICAL_ADDRESS": 0.70,
    "US_SSN": 0.50,
    "CREDIT_CARD": 0.70,
    "DATE_OF_BIRTH": 0.70,
    "IP_ADDRESS": 0.60,
    "IN_PAN": 0.60,
    "IN_AADHAAR": 0.60,
    "IN_DIN": 0.60,
    "IN_CIN": 0.70,
}

ENTITY_PRECEDENCE = {
    "CREDIT_CARD": 90,
    "US_SSN": 90,
    "EMAIL_ADDRESS": 85,
    "IP_ADDRESS": 85,
    "IN_PAN": 90,
    "IN_AADHAAR": 90,
    "IN_DIN": 90,
    "IN_CIN": 90,
    "PHONE_NUMBER": 80,
    "DATE_OF_BIRTH": 75,
    "PHYSICAL_ADDRESS": 70,
    "PERSON": 50,
    "ORGANIZATION": 50,
}

GENERIC_ORGANIZATIONS = frozenset(
    {
        "aadhaar",
        "cin",
        "company",
        "corporation",
        "din",
        "dob",
        "ip",
        "organisation",
        "pan",
        "private limited",
        "limited",
        "ltd",
        "llp",
        "inc",
        "incorporated",
        "plc",
        "ssn",
    }
)


class DeterministicDetectionResolver:
    def resolve(
        self, text: str, results: Iterable[RecognizerResult]
    ) -> tuple[DetectedEntity, ...]:
        candidates = [self._convert(text, item) for item in results]
        candidates = [item for item in candidates if self._is_allowed(text, item)]
        accepted: list[DetectedEntity] = []
        for candidate in sorted(candidates, key=self._rank, reverse=True):
            if not any(self._overlaps(candidate, item) for item in accepted):
                accepted.append(candidate)
        return tuple(sorted(accepted, key=lambda item: (item.start, item.end)))

    @staticmethod
    def _is_allowed(text: str, entity: DetectedEntity) -> bool:
        if entity.score < MINIMUM_SCORES[entity.entity_type]:
            return False
        value = text[entity.start : entity.end].strip().casefold()
        if entity.entity_type == "PERSON":
            return len(re.findall(r"[^\W\d_]+", value)) >= 2
        if entity.entity_type == "ORGANIZATION":
            return (
                sum(character.isalpha() for character in value) >= 2
                and value not in GENERIC_ORGANIZATIONS
            )
        return True

    @staticmethod
    def _rank(entity: DetectedEntity) -> tuple[float, int, int, int, str]:
        return (
            entity.score,
            ENTITY_PRECEDENCE[entity.entity_type],
            entity.end - entity.start,
            -entity.start,
            entity.entity_type,
        )

    @staticmethod
    def _overlaps(left: DetectedEntity, right: DetectedEntity) -> bool:
        return left.start < right.end and right.start < left.end

    @staticmethod
    def _convert(text: str, result: RecognizerResult) -> DetectedEntity:
        explanation = result.analysis_explanation or {}
        if not isinstance(explanation, dict):
            explanation = explanation.to_dict()
        metadata = result.recognition_metadata or {}
        recognizer = metadata.get("recognizer_name")
        start, end = DeterministicDetectionResolver._clean_boundaries(text, result)
        return DetectedEntity(
            entity_type=result.entity_type,
            start=start,
            end=end,
            score=result.score,
            recognizer_name=recognizer or explanation.get("recognizer", "unknown"),
            context=explanation.get("supportive_context_word") or None,
        )

    @staticmethod
    def _clean_boundaries(text: str, result: RecognizerResult) -> tuple[int, int]:
        start, end = result.start, result.end
        if result.entity_type in {"PERSON", "ORGANIZATION"}:
            line_break = text.find("\n", start, end)
            end = line_break if line_break >= 0 else end
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        return start, end
