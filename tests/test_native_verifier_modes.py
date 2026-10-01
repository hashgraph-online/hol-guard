"""Keep contribution validation distinct from strict generated-file freshness."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from scripts.ci import detect_pending_extension_regen as real_detector
from scripts.ci import verify_native_command_program as verifier


@pytest.mark.parametrize("base_sha", [None, "a" * 40])
@pytest.mark.parametrize("pending,changed", [(False, False), (True, False), (False, True)])
def test_shared_verifier_compiles_pending_pr_sources_and_keeps_other_runs_strict(
    monkeypatch: pytest.MonkeyPatch, base_sha: str | None, pending: bool, changed: bool
) -> None:
    """Compile pending PR contributions while retaining strict checks for other runs."""
    detector = ModuleType("detect_pending_extension_regen")
    detector.ContributionDiffError = real_detector.ContributionDiffError
    detector.contribution_ids = lambda: {"command.fixture"} if pending else set()
    detector.catalog_ids = set
    detector._contributions_changed = (
        lambda _sha: ["contributions/command-sources/command.fixture.json"] if changed else []
    )
    detector._regen_inputs_changed = detector._contributions_changed
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "path", list(sys.path))
    arguments = ["verify", "--compiler", "fixture-compiler"]
    if base_sha:
        arguments += ["--changed-from", base_sha]
    monkeypatch.setattr(sys, "argv", arguments)
    calls: list[list[str]] = []
    monkeypatch.setattr(verifier, "_run", calls.append)

    assert verifier.main() == 0

    generate = [sys.executable, "scripts/build_native_command_program.py", "--compiler", "fixture-compiler"]
    if base_sha and (pending or changed):
        assert calls == [
            generate,
            ["git", "checkout", "--", *verifier.GENERATED_PATHS],
            ["git", "clean", "-fdq", "--", *verifier.GENERATED_PATHS],
        ]
    else:
        assert calls == [[*generate, "--check"]]


def test_invalid_pending_source_stays_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Propagate a compiler rejection without proceeding to the next command."""
    detector = ModuleType("detect_pending_extension_regen")
    detector.ContributionDiffError = real_detector.ContributionDiffError
    detector.contribution_ids = lambda: {"command.fixture"}
    detector.catalog_ids = set
    detector._contributions_changed = lambda _sha: []
    detector._regen_inputs_changed = lambda _sha: []
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "fixture-compiler", "--changed-from", "a" * 40])
    calls: list[list[str]] = []

    def invalid_source(command: list[str]) -> None:
        """Simulate a source compiler rejecting an invalid contribution."""
        calls.append(command)
        raise SystemExit(37)

    monkeypatch.setattr(verifier, "_run", invalid_source)
    with pytest.raises(SystemExit) as failure:
        verifier.main()
    assert failure.value.code == 37
    assert calls == [[sys.executable, "scripts/build_native_command_program.py", "--compiler", "fixture-compiler"]]


@pytest.mark.parametrize("pending", [False, True])
def test_unavailable_base_stops_before_generation_or_freshness_checks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, pending: bool
) -> None:
    """Neither verification mode may be selected from a failed base comparison."""
    detector = ModuleType("detect_pending_extension_regen")
    detector.ContributionDiffError = real_detector.ContributionDiffError
    detector.contribution_ids = lambda: {"command.fixture"} if pending else set()
    detector.catalog_ids = set

    def unavailable(_sha: str) -> list[str]:
        """Simulate the shared detector's explicit comparison failure."""
        raise real_detector.ContributionDiffError("Cannot compare contribution sources: fetching the PR base failed")

    detector._contributions_changed = unavailable
    detector._regen_inputs_changed = unavailable
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "fixture", "--changed-from", "a" * 40])
    monkeypatch.setattr(verifier, "_run", lambda _command: pytest.fail("Verification must not run"))
    assert verifier.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "Cannot compare contribution sources" in output.err
