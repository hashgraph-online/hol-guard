"""Model-free replay lane of the Gauntlet: recorded hook payload shapes through the native hook path.

Judging is the Gauntlet's own interruption rule, not a looser one: an ordinary-work case passes only
when Guard answers with no decision other than allow, renders no warning or reason text, and creates
no approval row. A review-by-design action instead passes when its approval row offers an
exact-action Always allow. Cases come from ``tests/fixtures/gauntlet_replay_cases.json`` plus every
benign case of the existing false-positive gate (read only), replayed for each harness and for Pi.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ci.gauntlet.approval_rows import offers_always
from ci.gauntlet.fixtures import LFS_GITCONFIG
from ci.gauntlet.host_process import realistic_environment
from ci.gauntlet.interruptions import observation_interruptions
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_contained_tests_source import (
    CONTAINED_TEST_HELPERS_SOURCE,
)
from tests.benign_fp_gate_connectors import connector_setup_failure
from tests.benign_fp_gate_git import signed_checkout_include
from tests.native_gate_retry import BUDGET_MISS_REASONS

FIXTURES = Path(__file__).parent / "fixtures"
REPLAY_DOCUMENT = json.loads((FIXTURES / "gauntlet_replay_cases.json").read_text(encoding="utf-8"))
GATE_DOCUMENT = json.loads((FIXTURES / "benign_false_positive_gate.json").read_text(encoding="utf-8"))

# Tool names each harness really sends, by the case's abstract tool family. Pi names its built-ins
# like omp, but ships only bash, read, edit, write, grep, find and ls.
SHELL = {"codex": "Bash", "zcode": "Bash", "claude-code": "Bash", "omp": "bash", "pi": "bash", "cursor": "Shell"}
READ = {"zcode": "Read", "claude-code": "Read", "omp": "read", "pi": "read", "cursor": "Read"}
GLOB = {"claude-code": "Glob", "omp": "glob"}
GREP = {"claude-code": "Grep", "omp": "grep", "pi": "grep"}
WRITE = {"zcode": "Write", "claude-code": "Write", "omp": "write", "pi": "write"}
FIXED = {
    "eval": "eval",
    "task": "task",
    "wait": "wait",
    "mcp_js": "mcp__node_repl__js",
    "todo": "todo",
    "todo_write": "todo_write",
    "ls": "ls",
    "ask_user_question": "AskUserQuestion",
}
# Abstract tools upstream Pi also ships; omp-only tools (eval, task, todo, glob, ...) are not mirrored.
PI_TOOLS = frozenset({"shell", "read", "write", "grep", "ls"})
FAMILIES = {"shell": SHELL, "read": READ, "glob": GLOB, "grep": GREP, "write": WRITE}
ENVIRONMENTS = ("clean", "realistic")
# Profile and reason pairs the shipped OMP extension runs in Guard's sandbox instead of showing the
# denial, read from its source. Every profile is contained on macOS and the workspace profile on Linux.
# Z Code and Claude Code route inside the hook path, and Codex in its hook bridge (see
# test_guard_gauntlet_replay_gate.py), so their replay result already shows the contained run.
OMP_CONTAINED = frozenset(
    re.findall(r'profile === "([^"]+)" &&\s*response\.reason_code === "([^"]+)"', CONTAINED_TEST_HELPERS_SOURCE)
)
# An empty set would silently stop modelling OMP routing if the extension's source changes shape.
assert ("workspace-contained-v1", "native_workspace_containment_required") in OMP_CONTAINED


@dataclass(frozen=True)
class ReplayCase:
    case_id: str
    base_id: str
    harness: str
    tool: str
    tool_input: dict[str, object]
    cwd: str
    expect: str  # quiet | always | quiet_or_always | setup | block
    event: str = "PreToolUse"
    tool_response: object = None
    # Set by a case whose whole harm is reach the workspace sandbox removes: the network, the home
    # directory, the host toolchain. The sandbox still writes inside the workspace, so a case that
    # damages the worktree itself never carries this and keeps the strict check.
    contained_ok: bool = False
    # Set by a PostToolUse case whose harness attaches the source-file proof the
    # output review reads. Without it the review has no output to look at, so an
    # ordinary read would be judged as an interruption the product never made.
    source_ref: bool = False

    @property
    def tool_name(self) -> str:
        table = FAMILIES.get(self.tool)
        return table[self.harness] if table else FIXED[self.tool]


def _entry(entry: dict[str, Any], harness: str, expect: str) -> ReplayCase:
    return ReplayCase(
        f"{entry['id']}@{harness}",
        entry["id"],
        harness,
        entry["tool"],
        entry["tool_input"],
        entry["cwd"],
        expect,
        entry.get("event", "PreToolUse"),
        entry.get("tool_response"),
        bool(entry.get("contained_ok", False)),
        bool(entry.get("source_ref", False)),
    )


def expand() -> list[ReplayCase]:
    cases = [_entry(e, h, e["expect"]) for e in REPLAY_DOCUMENT["cases"] for h in e["harnesses"]]
    for entry in GATE_DOCUMENT["cases"]:
        # The replay runs every case in one environment, so it cannot model
        # a case that depends on an inherited variable.
        if entry.get("environment"):
            continue
        # Pi's read tool takes files; an entry that reads a folder says so and is not mirrored.
        mirror_pi = "omp" in entry["harnesses"] and entry["tool"] in PI_TOOLS and entry.get("mirror_pi", True)
        harnesses = list(entry["harnesses"]) + (["pi"] if mirror_pi else [])
        # A setup case keeps its expectation: a generic review there is a regression, not a block.
        expect = {"allow": "quiet", "setup": "setup", "allow_or_review": "quiet_or_always"}.get(
            entry["expect"], "block"
        )
        cases.extend(_entry(entry, h, expect) for h in harnesses)
    return cases


def source_ref_payload(spelled: str, cwd: Path) -> dict[str, object]:
    """The proof Oh My Pi's extension attaches to a PostToolUse read.

    The path keeps the spelling the tool was called with, so a host spelling
    through a linked ancestor reaches classification exactly as it does live.
    """

    text = (cwd / spelled).read_text(encoding="utf-8").rstrip("\n")
    return {
        "version": 1,
        "path": spelled,
        "output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "output_chars": len(text),
        "tool_input_path": spelled,
    }


def payload_input(case: ReplayCase, resolved: dict[str, object]) -> dict[str, object]:
    """Shape the tool input the way the harness sends it."""
    if case.harness == "zcode" and case.tool == "shell":
        resolved = {**resolved, "description": "Synthetic replay probe"}
    if case.harness in {"claude-code", "zcode"} and case.tool == "read":
        resolved = {"file_path": resolved["path"]}
    if case.harness == "cursor" and case.tool == "read":
        resolved = {"file_path": resolved["path"], "path": resolved["path"]}
    if case.harness in {"claude-code", "zcode"} and case.tool == "write":
        resolved = {"file_path": resolved["path"], "content": resolved["content"]}
    return resolved


def cursor_hook_fields(tool: str, payload: dict[str, object]) -> dict[str, object]:
    """Add the fields Cursor's installed hook script sends after it normalizes a native event.

    Cursor reports shell calls as beforeShellExecution and reads as beforeReadFile.
    The script forwards both as PreToolUse, keeping the raw command or path beside tool_input.
    """
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    if tool == "read":
        return {"file_path": tool_input["file_path"]}
    return {
        "command": tool_input["command"],
        "tool_input": {**tool_input, "working_directory": payload["cwd"]},
        "cursor_source_hook_event": "beforeShellExecution",
    }


def environment_overlay(kind: str, home: Path) -> dict[str, str]:
    """Extra env for a replay: nothing for clean, the Gauntlet's realistic overlay otherwise."""
    return realistic_environment({}, home) if kind == "realistic" else {}


_IDENTITY_GITCONFIG = "[user]\n\tname = Fixture Author\n\temail = fixture@example.invalid\n"


def write_global_gitconfig(kind: str, home: Path) -> None:
    """Identity only for clean; the Gauntlet's LFS, gpg and hooksPath settings for realistic.

    The fixture's signed checkout keeps its own signing settings only because the
    user's global config carries the same ones behind a conditional include, so
    that line survives both environments; rewriting it away would leave that
    repository standing for a shape no fixture built.
    """
    text = _IDENTITY_GITCONFIG
    if kind == "realistic":
        text = LFS_GITCONFIG + text
        (home / ".config/git/hooks").mkdir(parents=True, exist_ok=True)
    (home / ".gitconfig").write_text(text + signed_checkout_include(home), encoding="utf-8", newline="\n")


def omp_contained(case: ReplayCase, result: dict[str, object]) -> bool:
    """Whether the Pi or OMP extension would run this receipt in the sandbox, so the user sees no denial."""
    code, profile = result.get("reason_code"), result.get("required_execution_profile")
    return (
        case.harness in {"omp", "pi"}
        and case.tool == "shell"
        and result.get("decision") == "deny"
        and result.get("policy_action") == "sandbox-required"
        and result.get("observe_mode") is not True
        and (profile, code) in OMP_CONTAINED
        and (sys.platform == "darwin" or (sys.platform == "linux" and profile == "workspace-contained-v1"))
    )


def interruptions(case: ReplayCase, result: dict[str, object], approvals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    row = {"response": result, "payload": {"tool_name": case.tool_name, "hook_event_name": case.event}}
    found = [] if omp_contained(case, result) else observation_interruptions(row, case.harness)
    found.extend(
        {"kind": "approval", "harness": case.harness, "tool": case.tool_name, "reason_code": a.get("reason_code")}
        for a in approvals
    )
    return found


def failure_reasons(case: ReplayCase, result: dict[str, object], approvals: list[dict[str, Any]]) -> set[str]:
    """Reason codes behind an interruption, for matching a failure to its recorded known gap."""
    return {str(e["reason_code"]) for e in interruptions(case, result, approvals) if e.get("reason_code")}


def judge(case: ReplayCase, result: dict[str, object], approvals: list[dict[str, Any]]) -> str | None:
    """None when the case behaves as expected, otherwise a one-line failure."""
    if result.get("reason_code") in BUDGET_MISS_REASONS:
        # A fail-closed hook says nothing about the policy, so it never satisfies a `block` case,
        # under either of the reason codes a missed budget is reported with.
        return "native review unavailable after retry"
    found = interruptions(case, result, approvals)
    allowed = not any(e["kind"] == "decision" for e in found)
    if case.expect == "quiet":
        return None if not found else f"ordinary work was interrupted: {[e['kind'] for e in found]}"
    if case.expect == "setup":
        failure = connector_setup_failure(approvals, result)
        return f"not connector setup: {failure}" if failure else None
    if case.expect == "quiet_or_always" and not found:
        return None
    if case.expect in {"always", "quiet_or_always"}:
        routed = result.get("reason_code") == "native_contained_execution_routed"
        if not found and (routed or omp_contained(case, result)):
            return None  # a contained run needs no approval, which is better than an Always offer
        # A silent allow means the action never reached review, so no Always allow was offered.
        if not approvals:
            return "review-by-design action raised no approval row to offer an Always allow"
        bad = [(a.get("tool_name"), a.get("once_only_reason")) for a in approvals if not offers_always(a)]
        return f"review row without an Always allow offer: {bad}" if bad else None
    # A contained run reaches no network, home or credential, so it protects a case whose harm is
    # exactly that reach. It is not protection in general: the workspace sandbox still writes inside
    # the workspace, so an attack on the worktree itself must say so on the case to count.
    contained = case.contained_ok and (
        result.get("reason_code") == "native_contained_execution_routed" or omp_contained(case, result)
    )
    return "attack was allowed" if allowed and not approvals and not contained else None
