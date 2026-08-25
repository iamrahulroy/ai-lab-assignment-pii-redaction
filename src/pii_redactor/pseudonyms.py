from faker import Faker

from pii_redactor.domain import MappingRecord


class DocumentPseudonymRegistry:
    """Keeps one stable original-to-fake mapping for a document run."""

    def __init__(self, seed: int) -> None:
        self._faker = Faker("en_IN")
        self._faker.seed_instance(seed)
        self._records: dict[tuple[str, str], MappingRecord] = {}

    def replacement_for(self, entity_type: str, original: str) -> str:
        key = (entity_type, original.casefold())
        if key not in self._records:
            self._records[key] = MappingRecord(
                entity_type=entity_type,
                original=original,
                replacement=self._generate(entity_type),
            )
        return self._records[key].replacement

    @property
    def records(self) -> tuple[MappingRecord, ...]:
        return tuple(self._records.values())

    def _generate(self, entity_type: str) -> str:
        if entity_type != "EMAIL_ADDRESS":
            raise ValueError(f"Unsupported entity type: {entity_type}")

        used = {record.replacement for record in self._records.values()}
        while True:
            replacement = f"{self._faker.user_name()}@example.invalid"
            if replacement not in used:
                return replacement
