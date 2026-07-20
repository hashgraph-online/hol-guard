"""Execution-bound positive proof for local and public GitHub reads."""

from __future__ import annotations

import argparse
import inspect
import io
import os
from pathlib import Path
from typing import BinaryIO

import pytest

from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command
from codex_plugin_scanner.guard.runtime import verified_github_reads as github_reads
from codex_plugin_scanner.guard.runtime import verified_read_execution as local_reads
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_verified_read_candidates import (
    verified_read_candidate_operation,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.launch_identity_binding import (
    RuleVersionBinding,
    observe_launch_identity_binding,
)
from codex_plugin_scanner.guard.runtime.verified_github_reads import (
    try_read_verified_public_github_pull_request,
)
from codex_plugin_scanner.guard.runtime.verified_read_execution import try_execute_verified_local_read
from tests.guard_command_corpus import iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_benign_oracle


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    workspace = repository / "workspace"
    cwd = workspace / "service"
    cwd.mkdir(parents=True)
    (repository / ".git").mkdir()
    _ = (repository / ".git" / "HEAD").write_text("ref: refs/heads/test\n", encoding="utf-8")
    return workspace, repository, cwd


def test_every_cdx_060_corpus_case_requires_proof_instead_of_inheriting_allow() -> None:
    records = (
        (case, oracle)
        for case, oracle in zip(iter_benign_corpus(), iter_benign_oracle(), strict=True)
        if oracle.owner == "CDX-060"
    )
    evaluations = tuple(
        evaluate_command(case.command, cwd=Path("workspace"), home_dir=Path("home")) for case, _oracle in records
    )
    assert len(evaluations) == 350
    assert {item.minimum_action for item in evaluations} == {"review"}
    assert {item.decision_plane.action for item in evaluations} == {"review"}
    assert all(
        any(reason.reason_code == "verified-read-proof-required" for reason in item.decision_plane.reasons)
        for item in evaluations
    )


def test_raw_shell_candidates_never_mint_positive_proof() -> None:
    commands = (
        "pwd",
        "rg -n GuardAction src",
        "cd workspace/service-1 && rg -n GuardAction src | head -40",
        "gh pr view 17 --repo hol-fake/example --json number,state,mergeable",
    )
    for command in commands:
        evaluation = evaluate_command(command, cwd=Path("workspace"), home_dir=Path("home"))
        assert verified_read_candidate_operation(evaluation.command) is not None
        assert evaluation.decision_plane.action == "review"
        assert evaluation.decision_plane.proof_routes == frozenset()


def test_git_read_overlap_reaches_the_frozen_cdx_064_pair_baseline() -> None:
    evaluation = evaluate_command("git diff --check", cwd=Path("workspace"), home_dir=Path("home"))

    assert verified_read_candidate_operation(evaluation.command) == "workspace-read"
    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.proof_routes == frozenset()


def test_owned_direct_local_execution_returns_silent_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_local_executor_rejects_untrusted_workspace_and_context_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, _repository, cwd = _workspace(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert try_execute_verified_local_read(("pwd",)) is None
    monkeypatch.chdir(cwd)
    initial = local_reads._current_workspace_context()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(local_reads, "_current_workspace_context", lambda: initial)
    assert try_execute_verified_local_read(("missing-read-tool",)) is None
    changed = local_reads._WorkspaceContext(  # pyright: ignore[reportPrivateUsage]
        initial.repository,
        workspace,
        "0" * 64,
        initial.repository_file_identity,
    )
    contexts = iter((initial, changed))
    monkeypatch.setattr(local_reads, "_current_workspace_context", lambda: next(contexts))
    assert try_execute_verified_local_read(("pwd",)) is None


def test_local_executor_fails_closed_on_output_and_time_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(local_reads, "_MAX_OUTPUT_BYTES", 1)
    assert try_execute_verified_local_read(("pwd",)) is None
    assert "timeout_seconds" not in inspect.signature(try_execute_verified_local_read).parameters


def test_local_executor_rejects_target_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    _ = (cwd / "main.py").write_text("line one\nline two\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    actual = local_reads._stable_file_identity  # pyright: ignore[reportPrivateUsage]
    calls = 0

    def changed(metadata: os.stat_result) -> tuple[int, int, int, int]:
        nonlocal calls
        calls += 1
        identity = actual(metadata)
        if calls == 2:
            return identity[0], identity[1], identity[2] + 1, identity[3]
        return identity

    monkeypatch.setattr(local_reads, "_stable_file_identity", changed)
    assert try_execute_verified_local_read(("head", "-1", "main.py")) is None


def test_local_executor_rejects_parent_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    safe = cwd / "safe"
    safe.mkdir()
    _ = (safe / "main.py").write_text("safe\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    _ = (outside / "main.py").write_text("private\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    resolve_target = local_reads._resolve_target  # pyright: ignore[reportPrivateUsage]

    def swap_parent(
        value: str,
        *,
        context: local_reads._WorkspaceContext,  # pyright: ignore[reportPrivateUsage]
    ) -> Path:
        target = resolve_target(value, context=context)
        _ = safe.rename(cwd / "safe-original")
        _ = safe.symlink_to(outside, target_is_directory=True)
        return target

    monkeypatch.setattr(local_reads, "_resolve_target", swap_parent)
    assert try_execute_verified_local_read(("head", "-1", "safe/main.py")) is None


def test_local_executor_rejects_file_growth_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    source = cwd / "main.py"
    _ = source.write_text("safe\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(local_reads, "_MAX_FILE_BYTES", 8)
    bounded_read = local_reads._read_bounded_text  # pyright: ignore[reportPrivateUsage]

    def grow_then_read(stream: BinaryIO) -> str:
        with source.open("a", encoding="utf-8") as output:
            _ = output.write("private-data\n")
        return bounded_read(stream)

    monkeypatch.setattr(local_reads, "_read_bounded_text", grow_then_read)
    assert try_execute_verified_local_read(("head", "-1", "main.py")) is None


def test_verified_read_cli_owns_local_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace_path, _repository, cwd = _workspace(tmp_path)
    monkeypatch.chdir(cwd)
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(("verified-read", "local", "--", "pwd"))
    output = io.StringIO()

    assert run_guard_command(args, output_stream=output) == 0
    assert output.getvalue() == f"{cwd}\n"


def test_local_executor_accepts_a_bound_git_worktree_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def _github_payloads(owner: str = "public-owner", repository: str = "public-repo") -> tuple[dict[str, object], ...]:
    full_name = f"{owner}/{repository}"
    return (
        {"private": False, "full_name": full_name},
        {
            "number": 17,
            "state": "open",
            "mergeable": True,
            "base": {"repo": {"full_name": full_name}},
        },
    )


def test_owned_public_github_get_returns_silent_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(_github_payloads())
    urls: list[str] = []

    def public_get(
        url: str,
        *,
        timeout_seconds: float,
        tls_context: object,
    ) -> dict[str, object]:
        assert timeout_seconds == 15.0
        assert tls_context is not None
        urls.append(url)
        return next(responses)

    monkeypatch.setattr(github_reads, "_public_get_json", public_get)
    result = try_read_verified_public_github_pull_request("public-owner", "public-repo", 17)

    assert result is not None
    assert result.stdout == '{"mergeable":true,"number":17,"state":"open"}\n'
    assert urls == [
        "https://api.github.com/repos/public-owner/public-repo",
        "https://api.github.com/repos/public-owner/public-repo/pulls/17",
    ]
    assert result.proof.route is ProofRoute.VERIFIED
    assert result.decision.action == "allow"
    assert result.decision.disposition is FinalDisposition.SILENT_VERIFIED


def test_github_executor_rejects_private_dynamic_and_drifted_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    private, pull = _github_payloads()
    private["private"] = True
    responses = iter((private, pull))

    def private_get(_url: str, *, timeout_seconds: float, tls_context: object) -> dict[str, object]:
        del timeout_seconds, tls_context
        return next(responses)

    monkeypatch.setattr(github_reads, "_public_get_json", private_get)
    assert try_read_verified_public_github_pull_request("public-owner", "public-repo", 17) is None
    assert try_read_verified_public_github_pull_request("owner/value", "repo", 17) is None
    assert try_read_verified_public_github_pull_request("owner", "repo", 0) is None
    assert try_read_verified_public_github_pull_request("owner", "repo", 17, fields=("body",)) is None

    responses = iter(_github_payloads())

    def drift_get(_url: str, *, timeout_seconds: float, tls_context: object) -> dict[str, object]:
        del timeout_seconds, tls_context
        return next(responses)

    monkeypatch.setattr(github_reads, "_public_get_json", drift_get)
    digests = iter(("0" * 64, "1" * 64))
    monkeypatch.setattr(github_reads, "_source_digest", lambda: next(digests))
    assert try_read_verified_public_github_pull_request("public-owner", "public-repo", 17) is None


def test_proof_apis_do_not_accept_syntax_proof_or_transport_injection(tmp_path: Path) -> None:
    local_parameters = inspect.signature(try_execute_verified_local_read).parameters
    github_parameters = inspect.signature(try_read_verified_public_github_pull_request).parameters
    assert "proof" not in local_parameters and "receipt" not in local_parameters
    assert "proof" not in github_parameters and "transport" not in github_parameters

    workspace, repository, cwd = _workspace(tmp_path)
    command = evaluate_command("pwd", cwd=cwd).command
    observation = observe_launch_identity_binding(
        command=command,
        workspace=workspace,
        repository=repository,
        working_directory=cwd,
        policy_version="verified-read-test.v1",
        rules=(RuleVersionBinding("command.verified-read.test", "1.0.0"),),
        launch_env={"PATH": os.environ.get("PATH", "")},
    )
    assert observation.can_issue_positive_proof is False
    assert observation.unresolved_requirements == observation.required_requirements
    assert evaluate_command("pwd").decision_plane.proof_routes == frozenset()
