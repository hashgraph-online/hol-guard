"""An unavailable comparison base must never look like unchanged contributions."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import detect_pending_extension_regen as detector

BASE = "abcdef12" * 5


def _git_results(monkeypatch: pytest.MonkeyPatch, events: list[object]) -> list[list[str]]:
    """Record Git commands and inject bounded, deterministic process outcomes."""
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Return one fixture outcome without invoking a real remote."""
        calls.append(command)
        assert kwargs["timeout"] == 30
        assert kwargs["cwd"] == detector.ROOT
        assert kwargs["capture_output"] is True
        event = events.pop(0)
        if isinstance(event, Exception):
            raise event
        code, stdout = event
        return subprocess.CompletedProcess(command, code, stdout, "private-git-error")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


@pytest.mark.parametrize("sha", [BASE, BASE.upper(), BASE[:20].upper() + BASE[20:]])
def test_known_base_is_compared_without_fetch(monkeypatch: pytest.MonkeyPatch, sha: str) -> None:
    """Case-insensitive SHA inputs retain exact contribution detection."""
    calls = _git_results(monkeypatch, [(0, "contributions/command-sources/command.fixture.json\n")])
    assert detector._contributions_changed(sha) == ["contributions/command-sources/command.fixture.json"]
    assert calls == [["git", "diff", "--name-only", BASE, "HEAD", "--", "contributions/"]]


def test_successful_empty_diff_is_the_only_unchanged_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """A verified empty comparison is distinct from an unavailable comparison."""
    calls = _git_results(monkeypatch, [(0, "")])
    assert detector._contributions_changed(BASE) == []
    assert len(calls) == 1


def test_shallow_checkout_fetches_once_then_rechecks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fetching a missing base must be followed by a successful comparison."""
    calls = _git_results(monkeypatch, [(128, ""), (0, ""), (0, "contributions/extensions/fixture.json\n")])
    assert detector._contributions_changed(BASE) == ["contributions/extensions/fixture.json"]
    assert calls[1] == ["git", "fetch", "--depth=1", "origin", BASE]
    assert calls[0] == calls[2]


@pytest.mark.parametrize(
    "events,expected_calls", [([(128, ""), (128, "")], 2), ([(128, ""), (0, ""), (128, "")], 3)]
)
def test_failed_base_lookup_never_returns_unchanged(
    monkeypatch: pytest.MonkeyPatch, events: list[object], expected_calls: int
) -> None:
    """Fetch and post-fetch comparison failures both stop verification."""
    calls = _git_results(monkeypatch, events)
    with pytest.raises(RuntimeError, match="Cannot compare contribution sources") as caught:
        detector._contributions_changed(BASE)
    assert "private-git-error" not in str(caught.value)
    assert len(calls) == expected_calls


@pytest.mark.parametrize("phase", [0, 1, 2])
@pytest.mark.parametrize(
    "error", [OSError("private-os-error"), subprocess.TimeoutExpired("private-command", 30), UnicodeError("private-bytes")]
)
def test_git_transport_errors_are_bounded_and_redacted(
    monkeypatch: pytest.MonkeyPatch, phase: int, error: Exception
) -> None:
    """Any interrupted Git phase fails closed without exposing process output."""
    events = [(128, ""), (0, "")][:phase] + [error]
    calls = _git_results(monkeypatch, events)
    with pytest.raises(RuntimeError, match="Cannot compare contribution sources") as caught:
        detector._contributions_changed(BASE)
    assert "private" not in str(caught.value)
    expected_code = {
        OSError: "git_process",
        subprocess.TimeoutExpired: "git_timeout",
        UnicodeError: "git_encoding",
    }
    assert f"[{expected_code[type(error)]}]" in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert len(calls) == phase + 1


@pytest.mark.parametrize("sha", ["main", "--upload-pack=bad", "a" * 39, "g" * 40, BASE + "\n", ""])
def test_invalid_base_is_rejected_before_git(monkeypatch: pytest.MonkeyPatch, sha: str) -> None:
    """Only complete commit identities may reach Git argument parsing."""
    calls = _git_results(monkeypatch, [])
    with pytest.raises(RuntimeError, match="full Git commit SHA"):
        detector._contributions_changed(sha)
    assert calls == []


def test_detector_cli_exits_without_a_false_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """The CLI must not print false when its comparison could not be performed."""
    monkeypatch.setattr(detector, "contribution_ids", set)
    monkeypatch.setattr(detector, "catalog_ids", set)
    monkeypatch.setattr(sys, "argv", ["detect", "--flag", "--changed-from", BASE])
    _git_results(monkeypatch, [(128, ""), (128, "")])
    assert detector.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "Cannot compare contribution sources" in output.err
    assert "private-git-error" not in output.err


@pytest.mark.parametrize("missing_base", [False, True])
def test_real_shallow_checkout_distinguishes_changed_and_unavailable_bases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing_base: bool
) -> None:
    """Exercise local Git objects and a depth-one clone without network access."""
    source = tmp_path / "source"
    source.mkdir()

    def git(*arguments: str, cwd: Path = source) -> str:
        """Run a bounded command against this test's disposable repository."""
        result = subprocess.run(["git", *arguments], cwd=cwd, capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()

    git("init", "--initial-branch=main")
    contribution = source / "contributions/command-sources/command.fixture.json"
    contribution.parent.mkdir(parents=True)
    contribution.write_text('{"version":1}\n')
    git("add", ".")
    git("-c", "user.name=CI Fixture", "-c", "user.email=ci-fixture@example.invalid", "commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    contribution.write_text('{"version":2}\n')
    git("add", ".")
    git("-c", "user.name=CI Fixture", "-c", "user.email=ci-fixture@example.invalid", "commit", "-m", "edit")
    checkout = tmp_path / "shallow"
    git("clone", "--depth=1", source.as_uri(), str(checkout))
    assert git("rev-list", "--count", "HEAD", cwd=checkout) == "1"
    monkeypatch.setattr(detector, "ROOT", checkout)
    if missing_base:
        with pytest.raises(detector.ContributionDiffError, match="fetching the PR base failed"):
            detector._contributions_changed("0" * 40)
    else:
        assert detector._contributions_changed(base.upper()) == [contribution.relative_to(source).as_posix()]
        assert git("cat-file", "-t", base, cwd=checkout) == "commit"
