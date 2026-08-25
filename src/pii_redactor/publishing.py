import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path


class AtomicBundlePublisher:
    """Publishes a staged directory with one same-filesystem rename."""

    def __init__(
        self, move: Callable[[Path, Path], None] | None = None
    ) -> None:
        self._move = move or os.replace

    def publish(
        self, destination: Path, build: Callable[[Path], None]
    ) -> Path:
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError("Output directory already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.", dir=destination.parent
            )
        )
        try:
            build(stage)
            self._move(stage, destination)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return destination
