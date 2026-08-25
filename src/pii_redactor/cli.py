import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from pii_redactor.application import CreateRedactionBundle, OUTPUT_DOCUMENT_NAME
from pii_redactor.bootstrap import build_redaction_bundle
from pii_redactor.configuration import RedactionConfig
from pii_redactor.mapping_store import (
    MAPPING_KEY_ENV_VAR,
    MappingEncryptionKey,
    MappingKeyLoader,
)


ApplicationFactory = Callable[[RedactionConfig, int], CreateRedactionBundle]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-redactor",
        description=(
            "Create an all-or-nothing DOCX redaction bundle without modifying "
            "the input document."
        ),
        epilog=(
            "Example: conda run -n pii-redactor pii-redactor --input input.docx "
            "--output-dir output-bundle --config config/default.json --seed 17. "
            f"Provide the mapping key with --key-file or {MAPPING_KEY_ENV_VAR}. "
            "Failures return non-zero and publish no partial bundle."
        ),
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="New directory for the DOCX, encrypted mapping, and safe audit",
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument(
        "--key-file",
        type=Path,
        help=f"Fernet key file; otherwise read {MAPPING_KEY_ENV_VAR}",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    application_factory: ApplicationFactory = build_redaction_bundle,
    environment: Mapping[str, str] | None = None,
    stderr: TextIO | None = None,
) -> int:
    arguments = build_parser().parse_args(argv)
    error_stream = stderr or sys.stderr
    active_environment = os.environ if environment is None else environment
    try:
        config = RedactionConfig.load(arguments.config)
        key = _load_key(arguments.key_file, active_environment)
        _validate_paths(arguments.input, arguments.output_dir)
        application = application_factory(config, arguments.seed)
        application.execute(arguments.input, arguments.output_dir, key)
    except Exception as error:
        print(
            f"pii-redactor: redaction failed ({type(error).__name__})",
            file=error_stream,
        )
        return 1
    return 0


def _load_key(
    key_file: Path | None, environment: Mapping[str, str]
) -> MappingEncryptionKey:
    if key_file is not None:
        return MappingKeyLoader.from_file(key_file)
    return MappingKeyLoader.from_environment(environment)


def _validate_paths(source: Path, output_directory: Path) -> None:
    if not source.is_file() or source.suffix.casefold() != ".docx":
        raise ValueError("Input must be an existing DOCX file")
    if output_directory.exists():
        raise FileExistsError("Output directory must not already exist")
    output_path = output_directory / OUTPUT_DOCUMENT_NAME
    if source.resolve() == output_path.resolve():
        raise ValueError("Input and output paths must be different")


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
