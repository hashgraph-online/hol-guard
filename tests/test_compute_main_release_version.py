from __future__ import annotations

import io
import json
import sys

import pytest

from scripts.compute_main_release_version import compute_main_release_version, latest_main_release_version, main


@pytest.mark.parametrize(
    ("base", "existing", "expected"),
    [
        ("2.0.1117", ["2.0.1116"], "2.0.1117"),
        ("2.0.1117", ["2.0.1117"], "2.0.1118"),
        ("2.0.1117", ["2.0.1120"], "2.0.1121"),
        ("2.0.1117", ["2.0.1117.dev4", "2.2.0a1", "3.1.0a5"], "2.0.1117"),
        ("2.1.0", ["2.1.0a30", "2.1.0a31", "3.1.0a5"], "2.1.0"),
        ("3.1.0", ["2.0.2000", "3.1.0a5"], "3.1.0"),
    ],
)
def test_computes_monotonic_version_for_repository_release_line(
    base: str,
    existing: list[str],
    expected: str,
) -> None:
    assert compute_main_release_version(base, existing) == expected


@pytest.mark.parametrize("base", ["2.0", "2.0.1a1", "2.0.1.dev1", "v2.0.1", "not-a-version"])
def test_rejects_noncanonical_repository_versions(base: str) -> None:
    with pytest.raises(ValueError, match="Repository version"):
        compute_main_release_version(base, [])


def test_rejects_noncanonical_registry_versions() -> None:
    with pytest.raises(ValueError, match="Registry version"):
        compute_main_release_version("2.0.1", ["2.0.01"])


def test_reports_latest_stable_version_for_source_monotonicity() -> None:
    assert latest_main_release_version("2.0.1117", ["2.0.1116", "2.0.1117.dev4", "3.1.0a5"]) == "2.0.1116"
    assert latest_main_release_version("2.0.1117", ["2.2.0a1", "3.1.0a5"]) is None


def test_cli_reports_latest_existing_stable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["compute_main_release_version.py", "--base-version", "2.0.1117", "--latest-existing"],
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["2.0.1116", "3.1.0a5"])))

    assert main() == 0
    assert capsys.readouterr().out == "2.0.1116\n"


def test_cli_reads_registry_versions_from_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_main_release_version.py", "--base-version", "2.0.1117"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["2.0.1116"])))

    assert main() == 0
    assert capsys.readouterr().out == "2.0.1117\n"


def test_cli_fails_closed_for_invalid_registry_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_main_release_version.py", "--base-version", "2.0.1117"])
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"version":"2.0.1116"}'))

    assert main() == 1
    assert "JSON array of strings" in capsys.readouterr().err
