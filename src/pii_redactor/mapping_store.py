import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from pii_redactor.domain import MappingDocument, MappingMetadata, MappingRecord


MAPPING_KEY_ENV_VAR = "PII_REDACTOR_MAPPING_KEY"


class MappingDecryptionError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class MappingEncryptionKey:
    _value: bytes

    def __post_init__(self) -> None:
        Fernet(self._value)

    @classmethod
    def generate(cls) -> "MappingEncryptionKey":
        return cls(Fernet.generate_key())

    def encrypt(self, plaintext: bytes) -> bytes:
        return Fernet(self._value).encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return Fernet(self._value).decrypt(ciphertext)


class MappingKeyLoader:
    @staticmethod
    def from_environment(environment: Mapping[str, str]) -> MappingEncryptionKey:
        value = environment.get(MAPPING_KEY_ENV_VAR)
        if not value:
            raise ValueError(f"Missing {MAPPING_KEY_ENV_VAR}")
        return MappingEncryptionKey(value.strip().encode("ascii"))

    @staticmethod
    def from_file(path: Path) -> MappingEncryptionKey:
        value = Path(path).read_text(encoding="ascii").strip()
        return MappingEncryptionKey(value.encode("ascii"))


class EncryptedMappingStore:
    def save(
        self,
        path: Path,
        document: MappingDocument,
        key: MappingEncryptionKey,
    ) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        ciphertext = key.encrypt(self._serialize(document))
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(ciphertext)

    def load(
        self, path: Path, key: MappingEncryptionKey
    ) -> MappingDocument:
        try:
            plaintext = key.decrypt(Path(path).read_bytes())
        except InvalidToken as error:
            raise MappingDecryptionError(
                "Mapping key is invalid or artifact is corrupted"
            ) from error
        return self._deserialize(plaintext)

    @staticmethod
    def _serialize(document: MappingDocument) -> bytes:
        payload = {
            "metadata": asdict(document.metadata),
            "mappings": [asdict(item) for item in document.mappings],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @staticmethod
    def _deserialize(plaintext: bytes) -> MappingDocument:
        payload = json.loads(plaintext.decode("utf-8"))
        metadata = MappingMetadata(**payload["metadata"])
        mappings = tuple(MappingRecord(**item) for item in payload["mappings"])
        return MappingDocument(metadata=metadata, mappings=mappings)
