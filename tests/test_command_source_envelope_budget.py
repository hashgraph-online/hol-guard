"""The acceptance contribution must fit the shipped canonical source budget."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_LIMIT = re.compile(r"8 \* 1024 \* 1024")


def _acceptance():
    path = ROOT / "scripts/ci/check_extension_fixture_isolation.py"
    spec = importlib.util.spec_from_file_location("check_extension_fixture_isolation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _limits() -> dict[str, str]:
    return {
        "build.rs": (ROOT / "rust/crates/guard-command/build.rs").read_text(),
        "decoder": (ROOT / "rust/crates/guard-command/src/native_command_source_json.rs").read_text(),
        "stdin": (ROOT / "rust/crates/guard-command/src/bin/guard-command-source.rs").read_text(),
        "python": (
            ROOT / "src/codex_plugin_scanner/guard/extension_builder/native_source_compiler.py"
        ).read_text(),
    }


def test_acceptance_envelope_fits_the_shipped_budget_and_not_the_old_one() -> None:
    limits = _limits()
    assert all(_LIMIT.search(text) for text in limits.values())
    assert all("4 * 1024 * 1024 + 64 * 1024" not in text for text in limits.values())
    assert ".take(8 * 1024 * 1024 + 1)" in limits["stdin"]
    envelope = _acceptance().projected_acceptance_envelope_length(ROOT)
    shipped = 8 * 1024 * 1024
    previous = 4 * 1024 * 1024
    assert previous < envelope <= shipped
