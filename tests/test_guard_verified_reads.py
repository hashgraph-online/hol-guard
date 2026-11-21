"""Execution-bound positive proof for local and public GitHub reads."""

from __future__ import annotations

import argparse
import inspect
import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command
from codex_plugin_scanner.guard.runtime import verified_github_reads as github_reads
from codex_plugin_scanner.guard.runtime import verified_read_execution as local_reads
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.verified_github_reads import try_read_verified_public_github_pull_request
from codex_plugin_scanner.guard.runtime.verified_read_execution import try_execute_verified_local_read
from tests.guard_command_corpus import iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_benign_oracle
from tests.native_command_test_support import iter_native_command_evaluations, real_native_command_evaluation


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    workspace = repository / "workspace"
    cwd = workspace / "service"
    cwd.mkdir(parents=True)
    (repository / ".git").mkdir()
    _ = (repository / ".git" / "HEAD").write_text("ref: refs/heads/test\n", encoding="utf-8")
    return workspace, repository, cwd


def _requires_read_proof(evaluation: object) -> bool:
    reasons = evaluation.decision_plane.reasons
    return any(reason.reason_code == "verified-read-proof-required" for reason in reasons)


def test_every_cdx_060_corpus_case_requires_proof_instead_of_inheriting_allow() -> None:
    records = (
        (case, oracle)
        for case, oracle in zip(iter_benign_corpus(), iter_benign_oracle(), strict=True)
        if oracle.owner == "CDX-060"
    )
    evaluations = tuple(
        reviewed.evaluation
        for reviewed in iter_native_command_evaluations(
            (case.command for case, _oracle in records), cwd=Path("workspace"), home_dir=Path("home")
        )
    )
    assert len(evaluations) == 350
    assert {item.minimum_action for item in evaluations} == {"review"}
    assert {item.decision_plane.action for item in evaluations} == {"review", "require-reapproval"}
    assert all(
        any(reason.reason_code == "verified-read-proof-required" for reason in item.decision_plane.reasons)
        for item in evaluations
    )


def test_raw_shell_candidates_never_mint_positive_proof(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cwd = home / "workspace"
    (cwd / "src").mkdir(parents=True)
    (cwd / "workspace" / "service-1" / "src").mkdir(parents=True)
    commands = (
        "pwd",
        "rg -n GuardAction src",
        "cd workspace/service-1 && rg -n GuardAction src | head -40",
        "gh pr view 17 --repo hol-fake/example --json number,state,mergeable",
    )
    for command in commands:
        evaluation = real_native_command_evaluation(command, cwd=cwd, home_dir=home).evaluation
        assert _requires_read_proof(evaluation)
        assert evaluation.decision_plane.action == "review"
        assert evaluation.decision_plane.proof_routes == frozenset()


def test_raw_search_without_cwd_evidence_retains_approval_floor(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    missing = home / "missing-workspace"
    assert not missing.exists()

    evaluation = real_native_command_evaluation("rg -n GuardAction src", cwd=missing, home_dir=home).evaluation

    assert _requires_read_proof(evaluation)
    assert evaluation.decision_plane.action == "require-reapproval"
    assert evaluation.decision_plane.proof_routes == frozenset()
    assert any(reason.reason_code == "critical.local-script-execution" for reason in evaluation.decision_plane.reasons)


def test_git_read_overlap_reaches_the_frozen_cdx_064_pair_baseline() -> None:
    evaluation = real_native_command_evaluation(
        "git diff --check", cwd=Path("workspace"), home_dir=Path("home")
    ).evaluation

    assert _requires_read_proof(evaluation)
    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.proof_routes == frozenset()


def test_owned_direct_local_execution_returns_silent_verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    monkeypatch.chdir(cwd)

    result = try_execute_verified_local_read(("pwd",))

    assert result is not None
    assert result.exit_code == 0
    assert result.stdout.strip() == str(cwd)
    assert result.proof.route is ProofRoute.VERIFIED
    assert result.decision.action == "allow"
    assert result.decision.disposition is FinalDisposition.SILENT_VERIFIED
    assert result.decision.proof_routes == frozenset({ProofRoute.VERIFIED})
    assert set(inspect.signature(try_execute_verified_local_read).parameters) == {"argv"}


def test_local_executor_rejects_shell_composition_and_boundary_drift(tmp_path: Path) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    source = cwd / "main.py"
    _ = source.write_text("print('ok')\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    _ = outside.write_text("private\n", encoding="utf-8")
    symlink = cwd / "linked.py"
    symlink.symlink_to(outside)
    previous = Path.cwd()
    try:
        os.chdir(cwd)
        assert try_execute_verified_local_read(("head", "-40", "main.py")) is not None
        assert try_execute_verified_local_read(("head", "-40", "linked.py")) is None
        assert try_execute_verified_local_read(("head", "-40", "../outside.py")) is None
        assert try_execute_verified_local_read(("head -40 main.py",)) is None
        assert try_execute_verified_local_read(("head", "-1001", "main.py")) is None
        assert try_execute_verified_local_read(("head", "-40", ".env")) is None
    finally:
        os.chdir(previous)


def test_local_executor_shows_the_slice_the_resident_planned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    source = cwd / "main.py"
    _ = source.write_text("".join(f"line{number}\n" for number in range(1, 11)), encoding="utf-8")
    monkeypatch.chdir(cwd)

    view = try_execute_verified_local_read(("sed", "-n", "3,5p", "main.py"))
    leading = try_execute_verified_local_read(("head", "--lines=2", "main.py"))
    trailing = try_execute_verified_local_read(("tail", "-2", "main.py"))

    assert view is not None and view.operation_id == "bounded-source-view"
    assert view.stdout == "line3\nline4\nline5\n"
    assert leading is not None and leading.operation_id == "bounded-head"
    assert leading.stdout == "line1\nline2\n"
    assert trailing is not None and trailing.operation_id == "bounded-tail"
    assert trailing.stdout == "line9\nline10\n"


def test_local_executor_has_no_grammar_of_its_own(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the resident's read there is no read, and no Python fallback."""

    _workspace_path, _repository, cwd = _workspace(tmp_path)
    _ = (cwd / "main.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    def unavailable(*_args: object) -> object:
        raise local_reads.NativeVerifiedReadExecuteError("native_verified_read_execute_unavailable")

    monkeypatch.setattr(local_reads, "resident_decide", unavailable)

    assert try_execute_verified_local_read(("head", "-40", "main.py")) is None
    assert try_execute_verified_local_read(("pwd",)) is None


def test_local_executor_rejects_a_directory_outside_any_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = _workspace(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert try_execute_verified_local_read(("pwd",)) is None


def test_verified_read_cli_owns_local_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    monkeypatch.chdir(cwd)
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(("verified-read", "local", "--", "pwd"))
    output = io.StringIO()

    assert run_guard_command(args, output_stream=output) == 0
    assert output.getvalue() == f"{cwd}\n"


def test_local_executor_accepts_a_bound_git_worktree_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "worktree"
    cwd = repository / "service"
    git_directory = tmp_path / "common.git" / "worktrees" / "feature"
    cwd.mkdir(parents=True)
    git_directory.mkdir(parents=True)
    common_directory = tmp_path / "common.git"
    _ = (git_directory / "HEAD").write_text("ref: refs/heads/feature\n", encoding="utf-8")
    _ = (git_directory / "commondir").write_text("../..\n", encoding="utf-8")
    _ = (common_directory / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    _ = (repository / ".git").write_text(f"gitdir: {git_directory}\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    result = try_execute_verified_local_read(("pwd",))

    assert result is not None
    assert result.stdout == f"{cwd}\n"


_BINDING = "ab" * 32


def _native(answer: object, requests: list[tuple[dict[str, object], float]] | None = None) -> Callable[..., object]:
    def runtime_answer(feature: str, command: str, request: dict[str, object], **kwargs: object) -> object:
        assert (feature, command) == ("native-verified-github-read-v2", "verified-github-read")
        if requests is not None:
            requests.append((request, cast(float, kwargs["timeout_seconds"])))
        if isinstance(answer, BaseException):
            raise answer
        return answer

    return runtime_answer


def test_owned_public_github_read_returns_silent_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[dict[str, object], float]] = []
    stdout = '{"mergeable":true,"number":17,"state":"open"}\n'
    answer = {"stdout": stdout, "binding_digest": _BINDING}
    monkeypatch.setattr(github_reads, "runtime_answer", _native(answer, requests))
    result = try_read_verified_public_github_pull_request("public-owner", "public-repo", 17)

    assert result is not None
    assert result.stdout == stdout
    assert requests == [
        (
            {
                "op": "read",
                "owner": "public-owner",
                "repository": "public-repo",
                "pull_number": 17,
                "fields": ["number", "state", "mergeable"],
                "timeout_seconds": 15.0,
            },
            40.0,
        )
    ]
    assert result.proof.route is ProofRoute.VERIFIED
    assert result.proof.binding_digest == _BINDING
    assert result.decision.action == "allow"
    assert result.decision.disposition is FinalDisposition.SILENT_VERIFIED


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"verified": False},
        {"stdout": "x\n"},
        {"stdout": 1, "binding_digest": _BINDING},
        OSError("runtime unavailable"),
    ],
)
def test_github_read_without_a_native_proof_is_unverified(answer: object, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(github_reads, "runtime_answer", _native(answer))
    assert try_read_verified_public_github_pull_request("public-owner", "public-repo", 17) is None


def test_github_read_refuses_an_unbounded_timeout_or_untyped_request_before_the_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[dict[str, object], float]] = []
    monkeypatch.setattr(github_reads, "runtime_answer", _native(None, requests))
    read = try_read_verified_public_github_pull_request
    assert read("owner", "repo", 17, timeout_seconds=0) is None
    assert read("owner", "repo", 17, timeout_seconds=31) is None
    assert read("owner", "repo", 17, timeout_seconds=float("nan")) is None
    assert read("owner", "repo", 17, timeout_seconds=cast(float, "15")) is None
    assert read("owner", "repo", cast(int, True)) is None
    assert read("owner", "repo", 17, fields=cast(tuple[str, ...], ["state"])) is None
    assert requests == []
