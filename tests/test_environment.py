from importlib import import_module


def test_required_runtime_dependencies_are_available() -> None:
    modules = (
        "cryptography",
        "docx",
        "en_core_web_lg",
        "faker",
        "pii_redactor",
        "presidio_analyzer",
        "presidio_anonymizer",
    )

    unavailable = [name for name in modules if not _can_import(name)]

    assert unavailable == []


def _can_import(module_name: str) -> bool:
    try:
        import_module(module_name)
    except ImportError:
        return False
    return True
