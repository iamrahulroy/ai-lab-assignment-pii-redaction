import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RedactionConfig:
    config_version: str
    model_version: str
    deny_lists: Mapping[str, tuple[str, ...]]

    @classmethod
    def load(cls, path: Path) -> "RedactionConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Configuration must be a JSON object")
        raw_deny_lists = payload.get("deny_lists", {})
        if not isinstance(raw_deny_lists, dict):
            raise ValueError("Configuration deny_lists must be an object")
        deny_lists = {
            str(entity_type): tuple(str(value) for value in values)
            for entity_type, values in raw_deny_lists.items()
            if isinstance(values, list)
        }
        config = cls(
            config_version=payload.get("config_version", ""),
            model_version=payload.get("model_version", ""),
            deny_lists=deny_lists,
        )
        if not config.config_version or not config.model_version:
            raise ValueError(
                "Configuration requires config_version and model_version"
            )
        return config
