"""A fixture directory the native runtime does not treat as transient.

The resident refuses to bake a launcher under a temporary root (``/tmp``,
``/var/folders``, ``pytest-of-*`` or ``$TMPDIR``) into a durable shim, so a
test that needs a desktop core or official CLI to be chosen places it under
the checkout's ignored ``build/`` directory instead.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent / "build" / "durable-fixtures"


@pytest.fixture
def durable_tmp_path() -> Iterator[Path]:
    _ROOT.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=_ROOT))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
