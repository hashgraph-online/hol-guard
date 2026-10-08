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
    generators = sorted((ROOT / "rust/crates/guard-command/testdata").glob("generate_*_fixtures.py"))
    assert len(generators) == 2
    for path in generators:
        assert any(fnmatch.fnmatchcase(path.relative_to(ROOT).as_posix(), pattern) for pattern in patterns)
    for path in (
        "rust/crates/guard-command/src/native_command_program_admission.rs",
        "rust/crates/guard-command/src/native_command_controls.rs",
        "src/codex_plugin_scanner/guard/daemon/hook_native_review_binding.py",
    ):
        assert not any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    assert properties["sonar.sources"] == "src,rust"
    assert "sonar.coverage.exclusions" not in properties
    assert "sonar.issue.ignore.multicriteria" not in properties
