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
fail until a sibling fix lands; on CI the gate fails if a listed case starts
passing so stale markers get removed rather than hiding regressions.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from ci.gauntlet.approval_rows import always_gap, approval_rows
from ci.gauntlet.input_evidence import redact_value
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import collect_hook_execution_environment
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_fixture import BenignFixture, build_fixture, route_codex
from tests.gauntlet_replay import OMP_CONTAINED, cursor_hook_fields
from tests.native_gate_retry import UNAVAILABLE_REASON, review_with_unavailable_retry

pytestmark = pytest.mark.usefixtures("native_hook_force")

# Mirrors SILENT_WARNING_CODES in the native hook renderer (hook_responses.rs).
_SILENT_WARNING_CODES = frozenset({"native_policy_observed", "native_policy_warning"})
_CASES_PATH = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
_DOCUMENT = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
_PENDING_FIX: dict[str, str] = _DOCUMENT["pending_fix"]

_SHELL_TOOL = {"codex": "Bash", "zcode": "Bash", "claude-code": "Bash", "omp": "bash", "cursor": "Shell"}
_READ_TOOL = {"zcode": "Read", "claude-code": "Read", "omp": "read", "cursor": "Read"}
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
    # Claude Code's built-in question prompt reaches Guard only after the user answers.
    "ask_user_question": "AskUserQuestion",
}
# A pending marker names the open work that owns the case. "unassigned" still
# prompts and has no owner yet. A merged PR is never a marker: once its fix
# lands the case either passes or needs a new owner.
_ALLOWED_PR = {"unassigned"}
# The session-* cases replay prompts users approved by hand. Those still
# reviewed on Linux CI are recorded here until their fixes land.
_PENDING_CEILING = 3
_RENDERED_KEYS = ("reason", "notice", "message", "systemMessage", "stopReason")
_RENDERED_SPECIFIC_KEYS = ("permissionDecisionReason", "additionalContext")
# Pending entries are recorded against the Linux CI host. Git helper context and
# temp-directory proofs differ on other hosts, so only CI fails a stale entry.
# Pending markers record the Linux CI result. macOS sends some Oh My Pi and Z Code reads
# through protected read-only execution, so local macOS runs do not judge marker staleness.
_ENFORCE_STALE_PENDING = bool(os.environ.get("CI")) and sys.platform != "darwin"
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
    event: str = "PreToolUse"
    tool_response: object = None
    # Variables the agent shell inherits, such as a user's RIPGREP_CONFIG_PATH.
    environment: tuple[tuple[str, str], ...] = ()


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
                    event=entry.get("event", "PreToolUse"),
                    tool_response=entry.get("tool_response"),
                    environment=tuple(sorted(entry.get("environment", {}).items())),
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


def _tool_input(case: GateCase, fixture: BenignFixture) -> dict[str, object]:
    resolved = redact_value(case.tool_input, fixture.tokens())
    assert isinstance(resolved, dict)
    if case.harness == "zcode" and case.tool == "shell":
        resolved = {**resolved, "description": "Synthetic benign probe"}
    if case.harness in {"claude-code", "zcode"} and case.tool == "read":
        resolved = {"file_path": resolved["path"]}
    if case.harness == "cursor" and case.tool == "read":
        resolved = {"file_path": resolved["path"], "path": resolved["path"]}
    if case.harness in {"claude-code", "zcode"} and case.tool == "write":
        resolved = {"file_path": resolved["path"], "content": resolved["content"]}
    return resolved


@pytest.fixture(scope="module")
def gate_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[BenignFixture, HookWorker]]:
    # macOS pytest temp dirs sit under /private/var/folders, where no real HOME
    # lives and where Guard reviews reads it allows under a real home. Root the
    # fixture under /tmp as a Linux runner and real developer hosts do.
    root = (
        Path(tempfile.mkdtemp(prefix="benign-fp-gate-", dir="/tmp")).resolve()
        if sys.platform == "darwin"
        else tmp_path_factory.mktemp("benign-fp-gate")
    )
    fixture = build_fixture(root)
    patch = pytest.MonkeyPatch()
    patch.setenv("HOME", str(fixture.home))
    # Git finds the fixture ~/.gitconfig through HOME, as on a real host. The
    # native Git proofs fail closed on any GIT_*, LD_* or DYLD_* override in
    # the agent environment. A test-only GIT_CONFIG_GLOBAL, and later the
    # LD_LIBRARY_PATH that setup-python exports on CI runners, each hid every
    # Git read case behind a review that real agents never see.
    # A developer's RIPGREP_CONFIG_PATH likewise keeps every rg case on
    # review; a case that models one sets it through its environment.
    for name in list(os.environ):
        if name.upper().startswith(("GIT_", "LD_", "DYLD_")) or name.upper() == "RIPGREP_CONFIG_PATH":
            patch.delenv(name)
    patch.setenv("XDG_CONFIG_HOME", str(fixture.home / ".config"))
    patch.setenv("HOL_GUARD_NATIVE", "force")
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail("HOL_GUARD_NATIVE_BINARY must name the compiled native runtime")
    patch.setenv("HOL_GUARD_NATIVE_BINARY", binary)
    # Match the Gauntlet replay environment: hosted Linux runners have no Bun.
    # The native bun -e proof must find a benign local executable on PATH in
    # both replay gates; otherwise a fixed case remains pending in this gate.
    bun = fixture.home / ".bun" / "bin" / "bun"
    bun.parent.mkdir(parents=True, exist_ok=True)
    bun.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bun.chmod(0o755)
    patch.setenv("PATH", os.pathsep.join([os.environ.get("PATH", ""), str(bun.parent)]))
    store = GuardStore(fixture.guard_home)
    # Deliberately no prepare_workspace_policy/register_workspace: first contact.
    worker = HookWorker(store=store, workspace=fixture.worktree)
    try:
        yield fixture, worker
    finally:
        worker.close()
        patch.undo()
        fixture.cleanup()
        if sys.platform == "darwin":
            shutil.rmtree(root, ignore_errors=True)


def _review(case: GateCase, fixture: BenignFixture, worker: HookWorker) -> tuple[dict[str, object], int]:
    before = worker.store.count_approval_requests(status=None)
    known = {str(row.get("request_id")) for row in worker.store.list_approval_requests(status=None, limit=500)}
    payload: dict[str, object] = {
        "hook_event_name": case.event,
        "tool_name": _tool_name(case),
        "tool_input": _tool_input(case, fixture),
        "session_id": "benign-fp-gate",
        "tool_call_id": case.case_id,
        "cwd": str(fixture.cwd(case.cwd)),
        "guard_execution_environment": collect_hook_execution_environment(),
    }
    if case.tool_response is not None:
        payload["tool_response"] = case.tool_response
    if case.harness == "cursor":
        payload.update(cursor_hook_fields(case.tool, payload))
    # Approval baselines stay from before the first attempt, so a retry never hides a row.
    result = review_with_unavailable_retry(
        case.case_id,
        lambda: worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=case.harness,
            home_dir=fixture.home,
            guard_home=fixture.guard_home,
            workspace=fixture.cwd(case.cwd),
        ),
    )
    # Claude's PostToolUse output carries no reason code, so a silent policy
    # warning is visible only in the native receipt the review just wrote.
    receipt = worker._last_native_decision_receipt
    if "reason_code" not in result and isinstance(receipt, dict) and isinstance(receipt.get("reason_code"), str):
        result = {**result, "reason_code": receipt["reason_code"]}
    _ROWS[case.case_id] = approval_rows(worker.store, known)
    routed = _harness_route(case, result, payload, fixture)
    return routed, worker.store.count_approval_requests(status=None) - before


def _harness_route(
    case: GateCase, result: dict[str, object], payload: dict[str, object], fixture: BenignFixture
) -> dict[str, object]:
    """Apply the containment rewrite the harness's own hook performs.

    ``review_http_payload`` already routes Z Code and Claude Code. Codex routes
    in its hook bridge and Oh My Pi in its TypeScript extension (every profile
    on macOS, the workspace profile on Linux). Without this the gate
    counts their contained runs as reviews although the user sees nothing.
    """
    if case.harness == "codex":
        return route_codex(result, payload, fixture)
    if case.harness == "omp" and _omp_routes(result):
        return {"decision": "allow", "policy_action": "allow", "reason_code": _reason(result), "routed": "omp"}
    return result


def _omp_routes(result: dict[str, object]) -> bool:
    profile = result.get("required_execution_profile")
    return (
        result.get("decision") == "deny"
        and result.get("policy_action") == "sandbox-required"
        and result.get("observe_mode") is not True
        and (profile, _reason(result)) in OMP_CONTAINED
        and (sys.platform == "darwin" or (sys.platform == "linux" and profile == "workspace-contained-v1"))
    )


def _contained(result: dict[str, object]) -> bool:
    """Allowed only to run inside the workspace sandbox, by any harness route."""
    return result.get("routed") == "omp" or _reason(result) == "native_contained_execution_routed"


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


def _rendered_text(result: dict[str, object]) -> bool:
    """True when the harness response carries text the agent or user would see."""
    specific = result.get("hookSpecificOutput")
    specific = specific if isinstance(specific, dict) else {}
    return any(result.get(key) for key in _RENDERED_KEYS) or any(specific.get(key) for key in _RENDERED_SPECIFIC_KEYS)


def _quiet_allow(result: dict[str, object], approvals: int) -> bool:
    """Allowed with no approval row and nothing rendered.

    A warn whose reason is a silent code (the policy floor on a proven action)
    is quiet: the receipt records it, but the harness shows nothing.
    """
    reason = _reason(result)
    if _decision(result) != "allow" or approvals != 0 or _rendered_text(result):
        return False
    if result.get("policy_action") == "warn" and reason in _SILENT_WARNING_CODES:
        return True
    return result.get("policy_action") in (None, "allow") and not (
        reason.startswith("native_") and (reason.endswith("_review") or reason.endswith("_warning"))
    )


def _hard_denied(result: dict[str, object], approvals: int) -> bool:
    """A deny with no approval row and no review reason is a hard block or fail-safe denial."""
    reason = _reason(result)
    return (
        _decision(result) == "deny"
        and approvals == 0
        and "_review" not in reason
        and "reapproval" not in reason
        and not reason.endswith("_containment_required")
    )


def _assert_pending(case_id: str, recorded: str, result: dict[str, object], approvals: int, description: str) -> None:
    """Fail a stale marker on CI, and fail a pending case that turned into a hard denial anywhere.

    A pending case may still warn or ask for review; it must not quietly allow or hard-block.
    """
    if _quiet_allow(result, approvals):
        if not _ENFORCE_STALE_PENDING:
            pytest.skip(f"pending {case_id} allows on this host; CI decides staleness")
        pytest.fail(f"stale pending marker: {case_id} now allows quietly; remove it ({recorded})")
    assert not _hard_denied(result, approvals), f"pending case became a hard denial: {description}"
    if _ENFORCE_STALE_PENDING:
        assert _reason(result) == recorded, f"pending case changed reason (recorded {recorded}): {description}"


def _describe(case: GateCase, result: dict[str, object], approvals: int) -> str:
    return (
        f"{case.case_id} [{case.fix_area}] decision={_decision(result)} reason={_reason(result)} approvals={approvals}"
    )


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.case_id)
def test_benign_agent_work_is_allowed_and_negative_controls_are_not(
    case: GateCase, gate_environment: tuple[BenignFixture, HookWorker]
) -> None:
    fixture, worker = gate_environment
    with pytest.MonkeyPatch.context() as patch:
        for name, value in case.environment:
            patch.setenv(name, value)
        result, approvals = _review(case, fixture, worker)
    description = _describe(case, result, approvals)
    if case.expect == "not_allow":
        assert case.case_id not in _PENDING_FIX, "negative controls cannot be pending_fix"
        # A warning or notice on an allowed call is still an allow, so check the effective decision.
        # Contained execution also protects: the sandbox runs without network, home or
        # credential access, so a contained `rg KEY ~/.ssh` finds nothing to leak.
        assert _decision(result) != "allow" or approvals > 0 or _contained(result), (
            f"negative control was allowed: {description}"
        )
        assert _reason(result) != UNAVAILABLE_REASON, f"native review unavailable: {description}"
        return
    gap = always_gap(_ROWS.get(case.case_id, [])) if _always_expected(case) else []
    if case.case_id in _PENDING_FIX:
        _assert_pending(case.case_id, _PENDING_FIX[case.case_id], result, approvals, description)
    else:
        assert _quiet_allow(result, approvals), f"benign work was reviewed: {description}"
    if case.case_id in _PENDING_ALWAYS:
        if gap:
            pytest.xfail(f"{_PENDING_ALWAYS[case.case_id]}: review row without Always: {description}")
        if not _ENFORCE_STALE_PENDING:
            pytest.skip(f"pending_always {case.case_id} offers Always on this host; CI decides staleness")
        pytest.fail(f"stale pending_always: {case.case_id} now offers Always; remove it ({description})")
    assert not gap, f"review row for read-only work offers no Always allow: {description}"


def test_pending_fix_entries_name_real_benign_cases() -> None:
    benign = {case.case_id for case in _CASES if case.expect == "allow"}
    assert set(_PENDING_FIX) <= benign, sorted(set(_PENDING_FIX) - benign)


def test_every_harness_and_tool_family_is_exercised() -> None:
    assert {case.harness for case in _CASES} == {"codex", "zcode", "claude-code", "omp", "cursor"}
    omp_tools = {_tool_name(case) for case in _CASES if case.harness == "omp"}
    assert {"bash", "read", "glob", "grep", "eval", "task", "wait"} <= omp_tools
    assert sum(case.expect == "not_allow" for case in _CASES) >= 6


def test_pending_entries_are_consistent_and_name_their_fix() -> None:
    assert set(_PENDING_PR) == set(_PENDING_FIX)
    assert set(_PENDING_PR.values()) <= _ALLOWED_PR, sorted(set(_PENDING_PR.values()) - _ALLOWED_PR)
    assert set(_PENDING_ALWAYS) <= set(_PENDING_FIX)
    assert set(_PENDING_ALWAYS.values()) <= _ALLOWED_PR, sorted(set(_PENDING_ALWAYS.values()) - _ALLOWED_PR)
    # The policy floor's warning on a proven action renders nothing, so the gate
    # counts it as quiet. A pending entry can only name a real interruption.
    silent = sorted(case_id for case_id, reason in _PENDING_FIX.items() if reason in _SILENT_WARNING_CODES)
    assert not silent, silent
    assert "advisory-warn" not in _PENDING_PR.values()


def test_pending_backlog_only_shrinks() -> None:
    """Every pending entry is a benign task that still interrupts the user.

    Lower the ceiling when a fix lands. Raising it means shipping a known false
    positive, which needs the reason in the PR description.
    """
    assert len(_PENDING_FIX) <= _PENDING_CEILING, (
        f"{len(_PENDING_FIX)} pending benign cases exceeds the ceiling of {_PENDING_CEILING}"
    )


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
    # Shapes the live Gauntlet missed: a gitignored node_modules link out of the
    # worktree, piped local builds and doctl reads, and placeholder docs reads.
    assert {
        "omp-glob-recursive-sh",
        "omp-glob-recursive-sh-pattern",
        "gauntlet-linked-modules-relative-vite-build",
        "doctl-apps-list-format-head",
        "neg-doctl-auth-token-head",
        "gauntlet-cat-credential-placeholder-docs",
    } <= ids
