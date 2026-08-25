import hashlib
import ipaddress
import re
import unicodedata
from collections.abc import Callable
from dataclasses import replace

from faker import Faker

from pii_redactor.domain import (
    MappingDocument,
    MappingMetadata,
    MappingRecord,
    PseudonymizedText,
    PseudonymRegistry,
    TextReplacement,
)


Generator = Callable[[Faker, str], str]
DIGIT_NORMALIZED_TYPES = frozenset(
    {"PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IN_AADHAAR", "IN_DIN"}
)


def normalize_pii(entity_type: str, value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    normalized = re.sub(r"\s+", " ", normalized)
    if entity_type in DIGIT_NORMALIZED_TYPES:
        return "".join(character for character in normalized if character.isdigit())
    if entity_type == "IP_ADDRESS":
        return ipaddress.ip_address(normalized).compressed
    return normalized.casefold()


class TypeAwarePseudonymGenerator:
    def __init__(self, seed: int) -> None:
        self._seed = seed

    def generate(
        self, entity_type: str, normalized_original: str, attempt: int
    ) -> str:
        generator = GENERATORS.get(entity_type)
        if generator is None:
            raise ValueError(f"Unsupported entity type: {entity_type}")
        faker = Faker("en_IN")
        derived_seed = self._derived_seed(
            entity_type, normalized_original, attempt
        )
        faker.seed_instance(derived_seed)
        return generator(faker, normalized_original)

    def _derived_seed(self, entity_type: str, value: str, attempt: int) -> int:
        material = f"{self._seed}\0{entity_type}\0{value}\0{attempt}".encode()
        return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


class DocumentPseudonymRegistry:
    """Maintains stable, collision-free mappings within one document run."""

    def __init__(self, seed: int) -> None:
        self._generator = TypeAwarePseudonymGenerator(seed)
        self._records: dict[tuple[str, str], MappingRecord] = {}

    def replacement_for(self, entity_type: str, original: str) -> str:
        normalized = normalize_pii(entity_type, original)
        key = (entity_type, normalized)
        if key in self._records:
            record = self._records[key]
            self._records[key] = replace(record, occurrences=record.occurrences + 1)
            return record.replacement
        replacement = self._generate_unique(entity_type, normalized)
        self._records[key] = MappingRecord(
            entity_type=entity_type,
            original=original,
            normalized_original=normalized,
            replacement=replacement,
        )
        return replacement

    def existing_replacement_for(self, entity_type: str, original: str) -> str:
        key = (entity_type, normalize_pii(entity_type, original))
        return self._records[key].replacement

    @property
    def records(self) -> tuple[MappingRecord, ...]:
        return tuple(self._records.values())

    def snapshot(self, metadata: MappingMetadata) -> MappingDocument:
        return MappingDocument(metadata=metadata, mappings=self.records)

    def _generate_unique(self, entity_type: str, normalized: str) -> str:
        used = {item.replacement.casefold() for item in self._records.values()}
        for attempt in range(1_000):
            replacement = self._generator.generate(entity_type, normalized, attempt)
            is_unused = replacement.casefold() not in used
            differs_from_original = replacement.casefold() != normalized
            if is_unused and differs_from_original:
                return replacement
        raise RuntimeError(f"Could not generate a unique {entity_type} replacement")


class KnownValuePseudonymizer:
    """Replays established mappings where contextual NER was inconsistent."""

    def __init__(self, registry: PseudonymRegistry) -> None:
        records = registry.records
        replacements = tuple(item.replacement.casefold() for item in records)
        by_original: dict[str, MappingRecord] = {}
        ambiguous: set[str] = set()
        for record in records:
            key = record.original.casefold()
            if key in by_original and by_original[key].entity_type != record.entity_type:
                ambiguous.add(key)
            elif len(record.original.strip()) >= 5 and not any(
                key in replacement for replacement in replacements
            ):
                by_original[key] = record
        for key in ambiguous:
            by_original.pop(key, None)
        self._records = by_original
        alternatives = sorted(by_original, key=len, reverse=True)
        self._pattern = (
            re.compile("|".join(re.escape(value) for value in alternatives), re.I)
            if alternatives
            else None
        )

    def pseudonymize(
        self, text: str, registry: PseudonymRegistry
    ) -> PseudonymizedText:
        if self._pattern is None:
            return PseudonymizedText(text, ())
        replacements = tuple(
            TextReplacement(
                match.start(),
                match.end(),
                registry.replacement_for(
                    self._records[match.group().casefold()].entity_type,
                    match.group(),
                ),
            )
            for match in self._pattern.finditer(text)
        )
        redacted = text
        for item in reversed(replacements):
            redacted = redacted[: item.start] + item.value + redacted[item.end :]
        return PseudonymizedText(redacted, replacements)


def _person(faker: Faker, _: str) -> str:
    return faker.name()


def _email(faker: Faker, _: str) -> str:
    return f"{faker.user_name()}@example.invalid"


def _phone(faker: Faker, _: str) -> str:
    return f"+1 202-555-{faker.random_int(100, 199):04d}"


def _organization(faker: Faker, _: str) -> str:
    identifier = faker.random_int(0, 999_999)
    return f"{faker.last_name()} {identifier:06d} Test Systems Private Limited"


def _address(faker: Faker, _: str) -> str:
    number = faker.random_int(1, 999)
    return f"{number} Example Road, Test Nagar, Bengaluru, Karnataka 560001"


def _ssn(faker: Faker, _: str) -> str:
    group = faker.random_int(1, 99)
    serial = faker.random_int(1, 9_999)
    return f"000-{group:02d}-{serial:04d}"


def _credit_card(faker: Faker, _: str) -> str:
    body = f"000000{faker.random_int(0, 999_999_999):09d}"
    digits = body + _luhn_check_digit(body)
    return " ".join(digits[index : index + 4] for index in range(0, 16, 4))


def _date_of_birth(faker: Faker, _: str) -> str:
    value = faker.date_of_birth(minimum_age=18, maximum_age=80)
    return value.strftime("%d %B %Y")


def _ip_address(faker: Faker, normalized: str) -> str:
    if ":" in normalized:
        base = int(ipaddress.IPv6Address("2001:db8::"))
        return str(ipaddress.IPv6Address(base + faker.random.getrandbits(64) + 1))
    return f"192.0.2.{faker.random_int(1, 254)}"


def _pan(faker: Faker, _: str) -> str:
    return f"AAAPA{faker.random_int(0, 9_999):04d}A"


def _aadhaar(faker: Faker, _: str) -> str:
    return f"0000 0000 {faker.random_int(1, 9_999):04d}"


def _din(faker: Faker, _: str) -> str:
    return f"DIN-TEST-{faker.random_int(0, 99_999_999):08d}"


def _cin(faker: Faker, _: str) -> str:
    return f"L00000ZZ2000PLC{faker.random_int(0, 999_999):06d}"


def _luhn_check_digit(body: str) -> str:
    for candidate in "0123456789":
        if _passes_luhn(body + candidate):
            return candidate
    raise RuntimeError("Unable to calculate credit-card check digit")


def _passes_luhn(value: str) -> bool:
    checksum = 0
    parity = len(value) % 2
    for index, character in enumerate(value):
        digit = int(character)
        doubled = digit * 2 if index % 2 == parity else digit
        checksum += doubled - 9 if doubled > 9 else doubled
    return checksum % 10 == 0


GENERATORS: dict[str, Generator] = {
    "PERSON": _person,
    "EMAIL_ADDRESS": _email,
    "PHONE_NUMBER": _phone,
    "ORGANIZATION": _organization,
    "PHYSICAL_ADDRESS": _address,
    "US_SSN": _ssn,
    "CREDIT_CARD": _credit_card,
    "DATE_OF_BIRTH": _date_of_birth,
    "IP_ADDRESS": _ip_address,
    "IN_PAN": _pan,
    "IN_AADHAAR": _aadhaar,
    "IN_DIN": _din,
    "IN_CIN": _cin,
}
