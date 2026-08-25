from hashlib import sha256
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HASHES = {
    "Red Herring Prospectus (3).docx": (
        "8b5c93f7642d659e64b51be9f6172c86c2825417f376ca1800ed331515e6f929"
    ),
    "Enterprise Data - Assignment (2).pdf": (
        "62a888db0cd060dc939008db597dcebbeaa5726b24398576d9d3ce3e0cf9f12d"
    ),
}


def test_supplied_inputs_match_recorded_hashes() -> None:
    actual = {
        filename: _sha256(PROJECT_ROOT / filename) for filename in EXPECTED_HASHES
    }

    assert actual == EXPECTED_HASHES


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()
