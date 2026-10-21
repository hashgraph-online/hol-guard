"""The custom extension block vectors match the daemon's Python.

The resident's port replays ``local_cli_block_vectors.json``; this test fails
when the Python copy changes without re-recording the vectors.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "record_local_cli_block_vectors.py"


def test_local_cli_block_vectors_are_current() -> None:
    spec = importlib.util.spec_from_file_location("record_local_cli_block_vectors", _SCRIPT)
    assert spec is not None and spec.loader is not None
    recorder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recorder)

    assert recorder.OUT.read_text(encoding="utf-8") == recorder.render()
    assert len(recorder.cases()) >= 40
