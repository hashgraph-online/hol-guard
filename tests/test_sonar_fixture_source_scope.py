"""Offline adversarial corpus generators are tests, not production networking."""

from __future__ import annotations

import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_offline_generators_are_test_sources_without_hiding_runtime_enforcement() -> None:
    properties = dict(
        line.split("=", 1)
        for line in (ROOT / "sonar-project.properties").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    patterns = properties["sonar.test.inclusions"].split(",")
    recorders = sorted((ROOT / "rust/crates/guard-runtime/testdata").rglob("*.py"))
    assert recorders
    for path in recorders:
        assert any(fnmatch.fnmatchcase(path.relative_to(ROOT).as_posix(), pattern) for pattern in patterns)
    for path in (
        "rust/crates/guard-runtime/src/resident_state.rs",
        "src/codex_plugin_scanner/guard/resident_state_prune.py",
        "rust/crates/guard-command/src/native_command_program_admission.rs",
        "rust/crates/guard-command/src/native_command_controls.rs",
        "src/codex_plugin_scanner/guard/daemon/hook_native_review_binding.py",
    ):
        assert not any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    assert properties["sonar.sources"] == "src,rust"
    assert "sonar.coverage.exclusions" not in properties
    assert "sonar.issue.ignore.multicriteria" not in properties
