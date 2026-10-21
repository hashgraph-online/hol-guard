#!/usr/bin/env python3
"""Record Claude permission-dialog verdict vectors from the Python ladder.

``run_native_claude_permission_request`` used to pick, in Python, how the CLI
hook answered Claude Code's permission dialog (``PermissionRequest``): a
pending Guard notice that expects an explicit answer denied the dialog and
sent Claude to the Guard approval question, any other notice was a review
that showed its reason and deferred to Claude's dialog, and without a notice
the runtime artifact's composed policy action decided between no decision, a
review and a deny. The resident decides that now (``claude_permission_verdict``
in ``hook_decision_claude_permission_verdict.rs``) and the CLI only renders it.

The ladder below (``_recorded_ladder``) is that Python code as it stood at
c0c49e05ca, kept here so the oracle never calls the code it checks. Effects
are left out: the artifact's reason, the copy and the envelope are rendered
by the CLI from the verdict, so a vector records which verdict, which action
the response renders, whether it offers a way to approve and which reason it
carries (``reason_from_artifact`` marks the artifact's own rendered reason,
with ``reason`` as its blank fallback):

    PYTHONPATH=src .venv/bin/python scripts/ci/record_claude_permission_verdict_vectors.py

The Rust ``hook_decision_claude_permission_verdict_tests`` replays every vector
through the resident; ``tests/test_claude_permission_verdict.py`` checks that
this oracle still reproduces the fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.action_lattice import (
    GUARD_ACTION_LATTICE,
    most_restrictive_guard_action,
    normalize_guard_action,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "rust/crates/guard-runtime/tests/fixtures/claude_permission_verdict_vectors.json"

GUARD_QUESTION_REASON = "HOL Guard is routing this approval through AskUserQuestion."
DEFAULT_REASON = "HOL Guard is reviewing this Claude approval prompt."

# Notices as the store returns them, including the shapes a hand-edited or
# older store could hold.
NOTICES: tuple[dict[str, object] | None, ...] = (
    None,
    {},
    {"artifact_type": "tool_action_request", "reason": "Guard is reviewing this shell command."},
    {"artifact_type": "package_request", "reason": "Guard is reviewing this package install."},
    {"artifact_type": " package_request ", "reason": "  Padded package reason.  "},
    {"artifact_type": "package_request", "reason": "   "},
    {"artifact_type": "package_request"},
    {"artifact_type": "package_request", "reason": 7},
    {"artifact_type": 5, "reason": "Non-string artifact type."},
    {"artifact_type": "PACKAGE_REQUEST", "reason": "Upper-case artifact type."},
)
# Package evaluation actions: none (not a package request), each canonical
# action, a legacy alias and a value the lattice does not know.
PACKAGE_ACTIONS: tuple[str | None, ...] = (None, *GUARD_ACTION_LATTICE, "ask", "bogus")


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _prefers_ask_user_question(notice: dict[str, object]) -> bool:
    return _optional_string(notice.get("artifact_type")) != "package_request"


def _verdict(
    verdict: str,
    policy_action: str | None,
    offers_approval: bool,
    reason: str | None,
    artifact_action: str | None = None,
) -> dict[str, object]:
    return {
        "verdict": verdict,
        "policy_action": policy_action,
        "offers_approval": offers_approval,
        "reason": reason,
        "reason_from_artifact": artifact_action is not None,
        "artifact_action": artifact_action,
    }


_PASSTHROUGH = _verdict("passthrough", None, False, None)


def _recorded_ladder(
    notice: dict[str, object] | None,
    runtime_artifact_present: bool,
    artifact_policy: dict[str, object] | None,
) -> dict[str, object]:
    if notice is not None and _prefers_ask_user_question(notice):
        # The deny's message is the Guard approval question itself.
        return _verdict("guard_question", "block", True, GUARD_QUESTION_REASON)
    if notice is not None:
        return _verdict("review", "require-reapproval", True, _optional_string(notice.get("reason")) or DEFAULT_REASON)
    if not runtime_artifact_present:
        return _PASSTHROUGH
    assert artifact_policy is not None
    policy_action = artifact_policy["config_action"]
    package_action = artifact_policy["package_action"]
    if package_action is not None:
        policy_action = most_restrictive_guard_action(policy_action, normalize_guard_action(package_action))
    if policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}:
        return _PASSTHROUGH
    if policy_action in {"block", "sandbox-required"}:
        return _verdict("deny", policy_action, False, DEFAULT_REASON, artifact_action=str(policy_action))
    return _verdict("review", "require-reapproval", True, DEFAULT_REASON, artifact_action=str(policy_action))


def record() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = []
    for notice in NOTICES:
        for present in (False, True):
            policies: list[dict[str, object] | None] = [None]
            if notice is None and present:
                policies = [
                    {"config_action": config, "package_action": package}
                    for config in GUARD_ACTION_LATTICE
                    for package in PACKAGE_ACTIONS
                ]
            for policy in policies:
                vectors.append(
                    {
                        "inputs": {"notice": notice, "runtime_artifact_present": present},
                        "artifact_policy": policy,
                        "verdict": _recorded_ladder(notice, present, policy),
                    }
                )
    return vectors


def render(vectors: list[dict[str, object]]) -> str:
    return json.dumps(vectors, indent=1, sort_keys=True) + "\n"


def main() -> None:
    FIXTURE.write_text(render(record()), encoding="utf-8")


if __name__ == "__main__":
    main()
