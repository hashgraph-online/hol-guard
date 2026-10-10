"""Per-PR, model-free gate: ordinary agent work must never be reviewed.

Replays realistic PreToolUse payloads for every shipped harness through the
real native decision path (compiled ``hol-guard-runtime`` behind the daemon
``HookWorker``) against a synthetic fixture that mirrors real workspaces:
linked-worktree cwd, untracked nested repo, global ``filter.lfs.*`` gitconfig,
project skill docs, ``[slug]`` directories and credential-lookalike file names.
No workspace policy is pre-bound, so every case takes the first-contact path.

Cases live in ``tests/fixtures/benign_false_positive_gate.json``. Benign cases
must allow with zero approval rows and no ``native_*_review`` reason. Negative
controls must still not allow. ``pending_fix`` names cases that are known to
fail until a sibling fix lands; the gate fails if a listed case starts passing
so stale markers get removed rather than hiding regressions.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from ci.gauntlet.approval_rows import always_gap, approval_rows
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_fixture import BenignFixture, build_fixture

pytestmark = pytest.mark.usefixtures("native_hook_force")

_CASES_PATH = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
_DOCUMENT = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
_PENDING_FIX: dict[str, str] = _DOCUMENT["pending_fix"]

_SHELL_TOOL = {"codex": "Bash", "zcode": "Bash", "claude-code": "Bash", "omp": "bash"}
_READ_TOOL = {"zcode": "Read", "claude-code": "Read", "omp": "read"}
_GLOB_TOOL = {"claude-code": "Glob", "omp": "glob"}
_GREP_TOOL = {"claude-code": "Grep", "omp": "grep"}
_WRITE_TOOL = {"zcode": "Write", "claude-code": "Write", "omp": "write"}
_FIXED_TOOLS = {
    "eval": "eval",
    "task": "task",
    "wait": "wait",
    "mcp_js": "mcp__node_repl__js",
    # Real OMP builds ship todo_write and ls; the pinned live-lane build only has todo, so these are gate-only.
    "todo": "todo",
    "todo_write": "todo_write",
    "ls": "ls",
}
_ALLOWED_PR = {"#3958", "#3959", "#3960", "#3961", "pending-shell-github-extension", "unassigned"}
_PENDING_PR: dict[str, str] = _DOCUMENT["pending_pr"]
_PENDING_ALWAYS: dict[str, str] = _DOCUMENT["pending_always"]


@dataclass(frozen=True)
class GateCase:
    case_id: str
    base_id: str
    fix_area: str
    harness: str
    tool: str
    tool_input: dict[str, object]
    cwd: str
    expect: str


def _expand() -> list[GateCase]:
    expanded: list[GateCase] = []
    for entry in _DOCUMENT["cases"]:
        for harness in entry["harnesses"]:
            expanded.append(
                GateCase(
                    case_id=f"{entry['id']}@{harness}",
                    base_id=entry["id"],
                    fix_area=entry["fix_area"],
                    harness=harness,
                    tool=entry["tool"],
                    tool_input=entry["tool_input"],
                    cwd=entry["cwd"],
                    expect=entry["expect"],
                )
            )
    return expanded


_CASES = _expand()
# Approval rows each replayed case created, kept to judge the Always option.
_ROWS: dict[str, list[dict[str, object]]] = {}
# Read-only families for which a review row must always offer a lasting Always allow.
_ALWAYS_TOOLS = {"read", "glob", "grep", "eval", "task", "wait", "todo", "todo_write", "ls"}


def _always_expected(case: GateCase) -> bool:
    return case.tool in _ALWAYS_TOOLS or (case.fix_area == "git" and case.expect == "allow")


def _tool_name(case: GateCase) -> str:
    tables = {"shell": _SHELL_TOOL, "read": _READ_TOOL, "glob": _GLOB_TOOL, "grep": _GREP_TOOL, "write": _WRITE_TOOL}
    if case.tool in tables:
        return tables[case.tool][case.harness]
    return _FIXED_TOOLS[case.tool]


def _substitute(value: object, tokens: dict[str, str]) -> object:
    if isinstance(value, str):
        for token, replacement in tokens.items():
            value = value.replace(token, replacement)
        return value
    if isinstance(value, list):
        return [_substitute(item, tokens) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item, tokens) for key, item in value.items()}
    return value


def _tool_input(case: GateCase, fixture: BenignFixture) -> dict[str, object]:
    resolved = _substitute(case.tool_input, fixture.tokens())
    assert isinstance(resolved, dict)
    if case.harness == "zcode" and case.tool == "shell":
        resolved = {**resolved, "description": "Synthetic benign probe"}
    if case.harness in {"claude-code", "zcode"} and case.tool == "read":
        resolved = {"file_path": resolved["path"]}
    if case.harness in {"claude-code", "zcode"} and case.tool == "write":
        resolved = {"file_path": resolved["path"], "content": resolved["content"]}
    return resolved


@pytest.fixture(scope="module")
def gate_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[BenignFixture, HookWorker]]:
    fixture = build_fixture(tmp_path_factory.mktemp("benign-fp-gate"))
    patch = pytest.MonkeyPatch()
    patch.setenv("HOME", str(fixture.home))
    patch.setenv("GIT_CONFIG_GLOBAL", str(fixture.home / ".gitconfig"))
    patch.setenv("HOL_GUARD_NATIVE", "force")
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled native runtime")
    patch.setenv("HOL_GUARD_NATIVE_BINARY", binary)
    store = GuardStore(fixture.guard_home)
    # Deliberately no prepare_workspace_policy/register_workspace: first contact.
    worker = HookWorker(store=store, workspace=fixture.worktree)
    try:
        yield fixture, worker
    finally:
        worker.close()
        patch.undo()
        fixture.cleanup()


def _review(case: GateCase, fixture: BenignFixture, worker: HookWorker) -> tuple[dict[str, object], int]:
    before = worker.store.count_approval_requests(status=None)
    known = {str(row.get("request_id")) for row in worker.store.list_approval_requests(status=None, limit=500)}
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": _tool_name(case),
        "tool_input": _tool_input(case, fixture),
        "session_id": "benign-fp-gate",
        "tool_call_id": case.case_id,
        "cwd": str(fixture.cwd(case.cwd)),
        "guard_execution_environment": collect_hook_execution_environment(),
    }
    result = worker.review_http_payload(
        payload=payload,
        params={},
        default_harness=case.harness,
        home_dir=fixture.home,
        guard_home=fixture.guard_home,
        workspace=fixture.cwd(case.cwd),
    )
    _ROWS[case.case_id] = approval_rows(worker.store, known)
    return result, worker.store.count_approval_requests(status=None) - before


def _reason(result: dict[str, object]) -> str:
    reason = result.get("reason_code")
    return reason if isinstance(reason, str) else ""


def _decision(result: dict[str, object]) -> str:
    """Effective verdict across the per-harness response shapes: allow, deny or ask."""
    specific = result.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    permission = permission or result.get("permission") or result.get("decision")
    if result.get("continue") is False or result.get("policy_action") == "block":
        return "deny"
    if permission in {"deny", "block"}:
        return "deny"
    if permission == "ask":
        return "ask"
    return "allow"


def _quiet_allow(result: dict[str, object], approvals: int) -> bool:
    reason = _reason(result)
    return (
        _decision(result) == "allow"
        and approvals == 0
        and result.get("policy_action") in (None, "allow")
        and not result.get("notice")
        and not (reason.startswith("native_") and (reason.endswith("_review") or reason.endswith("_warning")))
    )


def _describe(case: GateCase, result: dict[str, object], approvals: int) -> str:
    return (
        f"{case.case_id} [{case.fix_area}] decision={_decision(result)} reason={_reason(result)} approvals={approvals}"
    )


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.case_id)
def test_benign_agent_work_is_allowed_and_negative_controls_are_not(
    case: GateCase, gate_environment: tuple[BenignFixture, HookWorker]
) -> None:
    fixture, worker = gate_environment
    result, approvals = _review(case, fixture, worker)
    description = _describe(case, result, approvals)
    if case.expect == "not_allow":
        assert case.case_id not in _PENDING_FIX, "negative controls cannot be pending_fix"
        assert not _quiet_allow(result, approvals), f"negative control was allowed: {description}"
        return
    passed = _quiet_allow(result, approvals)
    gap = always_gap(_ROWS.get(case.case_id, [])) if _always_expected(case) else []
    if case.case_id in _PENDING_FIX:
        assert not passed, (
            f"stale pending_fix: {case.case_id} now allows quietly; remove it from pending_fix "
            f"({_PENDING_FIX[case.case_id]})"
        )
    else:
        assert passed, f"benign work was reviewed: {description}"
    if gap and case.case_id in _PENDING_ALWAYS:
        pytest.xfail(f"{_PENDING_ALWAYS[case.case_id]}: review row without Always: {description}")
    assert not gap, f"review row for read-only work offers no Always allow: {description}"


def test_pending_fix_entries_name_real_benign_cases() -> None:
    benign = {case.case_id for case in _CASES if case.expect == "allow"}
    assert set(_PENDING_FIX) <= benign, sorted(set(_PENDING_FIX) - benign)


def test_every_harness_and_tool_family_is_exercised() -> None:
    assert {case.harness for case in _CASES} == {"codex", "zcode", "claude-code", "omp"}
    omp_tools = {_tool_name(case) for case in _CASES if case.harness == "omp"}
    assert {"bash", "read", "glob", "grep", "eval", "task", "wait"} <= omp_tools
    assert sum(case.expect == "not_allow" for case in _CASES) >= 6


def test_pending_entries_are_consistent_and_name_their_fix() -> None:
    assert set(_PENDING_PR) == set(_PENDING_FIX)
    assert set(_PENDING_PR.values()) <= _ALLOWED_PR, sorted(set(_PENDING_PR.values()) - _ALLOWED_PR)
    assert set(_PENDING_ALWAYS) <= set(_PENDING_FIX)
    assert set(_PENDING_ALWAYS.values()) == {"#3961"}


def test_every_confirmed_false_positive_class_has_a_gate_case() -> None:
    ids = {case.base_id for case in _CASES}
    assert {"omp-eval-read-home-skill-doc", "omp-todo-write", "omp-ls", "omp-task", "omp-wait"} <= ids
    assert {"tmp-write-new-file", "tmp-write-overwrite-existing"} <= ids
    assert {"git-tmp-worktree-status", "git-parent-inner-worktree-diff-stat", "git-worktree-status"} <= ids
    assert {
        "gh-api-graphql-review-threads-single-line",
        "gh-api-graphql-review-threads-multi-line-vars",
        "gh-api-slash-graphql-review-threads",
        "gh-pr-view-json",
        "gh-api-pull-comments",
    } <= ids
    assert {
        "grep-count-absolute-home-path",
        "ls-bare",
        "ls-la-bare",
        "rg-numbered",
        "uv-version",
        "pytest-quiet",
    } <= ids
