"""The acceptance harness uses real contributor entry points and complete inputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from scripts.ci import check_extension_fixture_isolation as acceptance


def test_descriptor_inventory_uses_all_json_sources_and_authored_ids(tmp_path):
    sources = tmp_path / "contributions/command-sources"
    sources.mkdir(parents=True)
    for name, identity in (("command.demo.json", "command.demo"), ("another-name.json", "command.another")):
        (sources / name).write_text(json.dumps({"extension": {"extension_id": identity}}))
    (sources / "README.md").write_text("Not a contribution document")
    assert acceptance.command_descriptor_names(tmp_path) == {"command.demo.json", "command.another.json"}


def test_malformed_contribution_is_not_silently_excluded(tmp_path):
    sources = tmp_path / "contributions/command-sources"
    sources.mkdir(parents=True)
    (sources / "malformed.json").write_text("{}")
    with pytest.raises(KeyError):
        acceptance.command_descriptor_names(tmp_path)


def test_missing_portable_fixtures_has_an_explicit_error(tmp_path):
    with pytest.raises(RuntimeError, match="no portable command fixtures found"):
        acceptance.portable_fixture_paths(tmp_path)


def test_portable_fixture_selection_is_deterministic_and_preserves_rust_fixture(tmp_path):
    fixtures = tmp_path / "tests/fixtures"
    fixtures.mkdir(parents=True)
    for name in ("b", "a"):
        (fixtures / f"command-source-{name}.v1.json").write_text("{}")
    assert acceptance.portable_fixture_paths(tmp_path) == [
        fixtures / "command-source-a.v1.json",
        tmp_path / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json",
    ]


def test_console_entry_point_comes_from_the_active_environment(tmp_path, monkeypatch):
    python = tmp_path / "python"
    expected = python.with_name("hol-guard.exe" if os.name == "nt" else "hol-guard")
    monkeypatch.setattr(sys, "executable", str(python))
    with pytest.raises(RuntimeError, match="no hol-guard console entry point"):
        acceptance.contributor_cli()
    expected.write_text("console script")
    assert acceptance.contributor_cli() == expected


def test_real_contributor_handoff_help_is_reachable_without_executing_commands():
    result = subprocess.run(
        [str(acceptance.contributor_cli()), "extensions", "handoff", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--source" in result.stdout and "--fixture" in result.stdout
