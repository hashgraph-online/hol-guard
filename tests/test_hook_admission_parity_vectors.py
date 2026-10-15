"""The Python hook admission helpers must keep matching the recorded parity vectors."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "record_hook_admission_parity.py"
SPEC = importlib.util.spec_from_file_location("record_hook_admission_parity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


PATH_FAMILIES = ("workspace_string", "exec_command_workdir", "directory_authority")


def _is_platform_dependent(entry: object) -> bool:
    # Separators are recorded POSIX-style, and "~user" expands differently per platform.
    text = json.dumps(entry)
    return "/" in text or "~" in text


def test_python_hook_admission_helpers_match_recorded_vectors() -> None:
    recorded = json.loads(MODULE.FIXTURE.read_text(encoding="utf-8"))
    built = MODULE.build()
    if sys.platform == "win32":
        # Separator- and tilde-dependent path vectors are recorded on POSIX; the
        # platform-neutral ones (sentinels, non-strings, empty values) still run here.
        for family in PATH_FAMILIES:
            recorded[family] = [entry for entry in recorded[family] if not _is_platform_dependent(entry)]
            built[family] = [entry for entry in built[family] if not _is_platform_dependent(entry)]

    assert built == recorded


def test_recorded_vectors_cover_every_helper_family() -> None:
    recorded = json.loads(MODULE.FIXTURE.read_text(encoding="utf-8"))

    for family in (
        "lane",
        "client_key",
        "payload_size",
        "remaining_hint",
        "workspace_string",
        "exec_command_workdir",
        "deadline",
        "directory_authority",
    ):
        assert recorded[family], family
