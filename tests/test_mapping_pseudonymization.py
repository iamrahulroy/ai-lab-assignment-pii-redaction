import ipaddress
import re
from datetime import datetime

import pytest
from cryptography.fernet import Fernet
from presidio_anonymizer import AnonymizerEngine

from pii_redactor.domain import DetectedEntity, MappingMetadata
from pii_redactor.mapping_store import (
    MAPPING_KEY_ENV_VAR,
    EncryptedMappingStore,
    MappingDecryptionError,
    MappingEncryptionKey,
    MappingKeyLoader,
)
from pii_redactor.pseudonyms import (
    DocumentPseudonymRegistry,
    KnownValuePseudonymizer,
)
from pii_redactor.presidio_adapter import PresidioPseudonymizer


def test_reuses_normalized_values_and_isolates_entity_types():
    registry = DocumentPseudonymRegistry(seed=17)

    first_email = registry.replacement_for(
        "EMAIL_ADDRESS", " Rashi.Patil@Example.com "
    )
    second_email = registry.replacement_for(
        "EMAIL_ADDRESS", "rashi.patil@example.com"
    )
    person = registry.replacement_for("PERSON", "Acme Limited")
    organization = registry.replacement_for("ORGANIZATION", "Acme Limited")

    assert first_email == second_email
    assert person != organization
    records = {item.entity_type: item for item in registry.records}
    assert records["EMAIL_ADDRESS"].normalized_original == (
        "rashi.patil@example.com"
    )
    assert records["EMAIL_ADDRESS"].occurrences == 2


def test_generates_unique_reproducible_type_appropriate_values():
    samples = (
        ("PERSON", "Rahul Sharma"),
        ("EMAIL_ADDRESS", "rahul@example.com"),
        ("PHONE_NUMBER", "+91 98765 43210"),
        ("ORGANIZATION", "Acme Limited"),
        ("PHYSICAL_ADDRESS", "12 MG Road, Bengaluru 560001"),
        ("US_SSN", "219-09-9999"),
        ("CREDIT_CARD", "4111 1111 1111 1111"),
        ("DATE_OF_BIRTH", "14 September 1988"),
        ("IP_ADDRESS", "192.0.2.10"),
        ("IP_ADDRESS", "2001:db8::1234"),
        ("IN_PAN", "AAAPA1234A"),
        ("IN_AADHAAR", "2345 6789 0124"),
        ("IN_DIN", "01234567"),
        ("IN_CIN", "L12345MH2020PLC123456"),
    )

    first = DocumentPseudonymRegistry(seed=23)
    second = DocumentPseudonymRegistry(seed=23)
    replacements = tuple(first.replacement_for(*item) for item in samples)
    repeated = tuple(second.replacement_for(*item) for item in samples)

    assert replacements == repeated
    assert len(set(replacements)) == len(replacements)
    assert all(
        fake.casefold() != original.casefold()
        for fake, (_, original) in zip(replacements, samples)
    )

    generated = dict(zip((item[0] for item in samples), replacements))
    assert len(generated["PERSON"].split()) >= 2
    assert generated["EMAIL_ADDRESS"].endswith("@example.invalid")
    assert re.fullmatch(r"\+1 202-555-01\d{2}", generated["PHONE_NUMBER"])
    assert generated["ORGANIZATION"].endswith("Test Systems Private Limited")
    assert re.fullmatch(
        r".+ \d{6} Test Systems Private Limited",
        generated["ORGANIZATION"],
    )
    assert "Example Road, Test Nagar" in generated["PHYSICAL_ADDRESS"]
    assert generated["US_SSN"].startswith("000-")
    assert _passes_luhn(generated["CREDIT_CARD"])
    datetime.strptime(generated["DATE_OF_BIRTH"], "%d %B %Y")
    assert ipaddress.ip_address(replacements[8]) in ipaddress.ip_network(
        "192.0.2.0/24"
    )
    assert ipaddress.ip_address(replacements[9]) in ipaddress.ip_network(
        "2001:db8::/32"
    )
    assert re.fullmatch(r"AAAPA\d{4}A", generated["IN_PAN"])
    assert generated["IN_AADHAAR"].startswith("0000 0000 ")
    assert generated["IN_DIN"].startswith("DIN-TEST-")
    assert re.fullmatch(r"L00000ZZ2000PLC\d{6}", generated["IN_CIN"])


def test_encrypted_mapping_round_trips_without_plaintext_leakage(
    tmp_path, caplog
):
    registry = DocumentPseudonymRegistry(seed=31)
    registry.replacement_for("EMAIL_ADDRESS", "private@example.com")
    document = registry.snapshot(
        MappingMetadata(
            source_sha256="a" * 64,
            output_sha256="b" * 64,
            config_version="1",
            model_version="en_core_web_lg-3.8.0",
        )
    )
    key_text = Fernet.generate_key().decode("ascii")
    key = MappingKeyLoader.from_environment({MAPPING_KEY_ENV_VAR: key_text})
    key_path = tmp_path / "mapping.key"
    key_path.write_text(key_text, encoding="ascii")
    encrypted_path = tmp_path / "redaction_mapping.json.enc"
    store = EncryptedMappingStore()

    store.save(encrypted_path, document, key)

    encrypted = encrypted_path.read_bytes()
    assert b"private@example.com" not in encrypted
    assert document.mappings[0].replacement.encode() not in encrypted
    assert "private@example.com" not in caplog.text
    assert encrypted_path.stat().st_mode & 0o077 == 0
    assert MappingKeyLoader.from_file(key_path) == key
    assert store.load(encrypted_path, key) == document
    with pytest.raises(MappingDecryptionError):
        store.load(encrypted_path, MappingEncryptionKey.generate())


def test_pseudonymizes_adjacent_same_type_findings_without_merging_mappings():
    text = "The Registrar of Companies, Maharashtra"
    detector = _FixedDetector(
        (
            DetectedEntity("ORGANIZATION", 0, 27, 0.85, "stub"),
            DetectedEntity("ORGANIZATION", 28, 39, 0.85, "stub"),
        )
    )
    registry = DocumentPseudonymRegistry(seed=17)

    result = PresidioPseudonymizer(detector, AnonymizerEngine()).pseudonymize(
        text, registry
    )

    assert len(result.replacements) == 2
    assert len(registry.records) == 2
    assert all(record.occurrences == 1 for record in registry.records)
    assert "Registrar" not in result.text
    assert "Maharashtra" not in result.text


def test_replays_known_values_missed_in_later_contexts():
    registry = DocumentPseudonymRegistry(seed=17)
    replacement = registry.replacement_for("PERSON", "Rashi Patil")

    result = KnownValuePseudonymizer(registry).pseudonymize(
        "Director RASHI PATIL signed.", registry
    )

    assert result.text == f"Director {replacement} signed."
    assert registry.records[0].occurrences == 2


class _FixedDetector:
    def __init__(self, findings: tuple[DetectedEntity, ...]) -> None:
        self._findings = findings

    def detect(
        self, text: str, entities: tuple[str, ...] | None = None
    ) -> tuple[DetectedEntity, ...]:
        return self._findings


def _passes_luhn(value: str) -> bool:
    digits = [int(item) for item in value if item.isdigit()]
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        doubled = digit * 2 if index % 2 == parity else digit
        checksum += doubled - 9 if doubled > 9 else doubled
    return checksum % 10 == 0
