import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RedactionConfig:
    config_version: str
    model_version: str

    @classmethod
    def load(cls, path: Path) -> "RedactionConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Configuration must be a JSON object")
        config = cls(
            config_version=payload.get("config_version", ""),
            model_version=payload.get("model_version", ""),
        )
        if not config.config_version or not config.model_version:
            raise ValueError(
                "Configuration requires config_version and model_version"
            )
        return config
