from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.compute_alpha_release_version import compute_alpha_release_version, main, validate_alpha_phase_open


@pytest.mark.parametrize(
    ("existing", "expected"),
    [
        ([], "2.2.0a1"),
        (["2.2.0a1"], "2.2.0a2"),
        (["2.2.0a1", "2.2.0a7", "2.2.0a3"], "2.2.0a8"),
        (["2.0.1117", "2.1.0a9", "3.0.0a12"], "2.2.0a1"),
    ],
)
def test_computes_the_next_alpha_across_all_registry_sources(existing: list[str], expected: str) -> None:
    assert compute_alpha_release_version("2.2", existing) == expected


@pytest.mark.parametrize(
    ("release_train", "existing", "expected"),
    [
        ("3.0", ["3.0.0", "3.0.0a290"], "3.0.1a1"),
        ("3.0", ["3.0.0", "3.0.1a1", "3.0.1a4"], "3.0.1a5"),
        ("3.1", ["3.1.0a2"], "3.1.0a3"),
    ],
)
def test_computes_the_next_alpha_for_3x_release_trains(release_train: str, existing: list[str], expected: str) -> None:
    assert compute_alpha_release_version(release_train, existing) == expected


@pytest.mark.parametrize("release_train", ["2", "2.2.0", "not-a-train"])
def test_rejects_unsupported_or_noncanonical_release_train(release_train: str) -> None:
    with pytest.raises(ValueError, match="release train"):
        _ = compute_alpha_release_version(release_train, [])


@pytest.mark.parametrize("existing", [["2.2.0a01"], ["v2.2.0a1"], ["not-a-version"]])
def test_rejects_noncanonical_or_malformed_existing_versions(existing: list[str]) -> None:
    with pytest.raises(ValueError, match="Existing version"):
        _ = compute_alpha_release_version("2.2", existing)


def test_same_train_stable_release_blocks_an_alpha() -> None:
    with pytest.raises(ValueError, match="stable release"):
        _ = compute_alpha_release_version("2.2", ["2.2.0"])


@pytest.mark.parametrize("version", ["2.2.0b1", "2.2.0rc1"])
def test_same_train_beta_or_release_candidate_blocks_an_alpha(version: str) -> None:
    with pytest.raises(ValueError, match="non-alpha prerelease"):
        _ = compute_alpha_release_version("2.2", [version])


@pytest.mark.parametrize("version", ["2.2.0.post1", "2.2.0a2.post1"])
def test_same_train_post_release_blocks_an_alpha(version: str) -> None:
    with pytest.raises(ValueError, match="post release"):
        _ = compute_alpha_release_version("2.2", [version])


def test_same_train_alpha_development_release_fails_closed() -> None:
    with pytest.raises(ValueError, match="alpha development release"):
        _ = compute_alpha_release_version("2.2", ["2.2.0a2.dev1"])


def test_phase_only_validation_allows_newer_public_alphas_but_not_later_phases() -> None:
    validate_alpha_phase_open("2.2", ["2.2.0a2", "2.2.0a3"])
    with pytest.raises(ValueError, match="non-alpha prerelease"):
        validate_alpha_phase_open("2.2", ["2.2.0rc1"])


def test_cli_reads_combined_versions_from_stdin(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_alpha_release_version.py", "--release-train", "2.2"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["2.2.0a1", "2.2.0a2"])))

    assert main() == 0
    assert capsys.readouterr().out == "2.2.0a3\n"


def test_cli_fails_closed_for_invalid_registry_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_alpha_release_version.py", "--release-train", "2.2"])
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"version":"2.2.0a1"}'))

    assert main() == 1
    assert "JSON array of strings" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("base", "existing", "expected"),
    [
        ("3.42.0", [], "3.43.0a1"),
        ("3.42.0", ["3.42.0", "3.1.0a13", "3.43.0a1", "3.43.0a4"], "3.43.0a5"),
        ("3.43.0", ["3.43.0", "3.43.0a5"], "3.44.0a1"),
    ],
)
def test_main_train_alphas_target_the_minor_after_the_stable_base(
    base: str, existing: list[str], expected: str
) -> None:
    assert compute_alpha_release_version("main", existing, base) == expected


def test_main_train_requires_a_canonical_stable_base() -> None:
    with pytest.raises(ValueError, match="requires --base-version"):
        _ = compute_alpha_release_version("main", [])
    with pytest.raises(ValueError, match="canonical stable"):
        _ = compute_alpha_release_version("main", [], "3.43.0a1")


def test_main_train_closes_once_its_stable_release_exists() -> None:
    with pytest.raises(ValueError, match="closes release train"):
        _ = compute_alpha_release_version("main", ["3.43.0"], "3.42.0")


def test_cli_computes_main_train_alpha(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["compute_alpha_release_version.py", "--release-train", "main", "--base-version", "3.42.0"],
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["3.42.0", "3.43.0a1"])))

    assert main() == 0
    assert capsys.readouterr().out == "3.43.0a2\n"


def test_cli_runs_directly_as_a_script() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "compute_alpha_release_version.py"
    result = subprocess.run(
        [sys.executable, str(script), "--release-train", "main", "--base-version", "3.42.0"],
        input=json.dumps(["3.42.0"]),
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout == "3.43.0a1\n"
