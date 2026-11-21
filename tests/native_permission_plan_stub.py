"""Answer a Claude-native approval's persist plan the way the resident does.

The resident decides what a native approval saves (see the Rust
``hook_decision_native_permission_persist_tests`` replay suite). A test
that cares what the *store* does with a plan, not how the plan is decided,
answers it here instead of starting a resident.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from codex_plugin_scanner.guard.native_hook_authority_state import hook_authority_state

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore


def saved_plan(inputs: Mapping[str, Any], *, inventory_approved: bool = True) -> dict[str, Any]:
    """The plan for an authoritative allow: one policy row under the hash the caller gave."""

    stored = inputs["artifact_hash"]
    return {
        "stored_artifact_hash": stored,
        "policy_action": "allow" if inputs["action"] == "allow" else "block",
        "events": [
            {
                "name": "claude/native_permission_saved",
                "payload": {
                    "artifact_id": inputs["artifact_id"],
                    "artifact_hash": stored,
                    "action": inputs["action"],
                    "reason": inputs["reason"],
                },
                "before_policy": False,
            }
        ],
        "inventory_approved": inventory_approved,
    }


def write_native_allow(store: GuardStore, artifact_id: str) -> bool:
    inputs = {
        "artifact_id": artifact_id,
        "artifact_hash": "hash-native",
        "action": "allow",
        "reason": "native approval",
    }
    result = hook_authority_state(
        store,
        "claude_question_save",
        now="2026-04-11T00:00:00+00:00",
        session_id="approval-gate-test",
        payload={
            "plan": saved_plan(inputs),
            "artifact_id": artifact_id,
            "reason": "native approval",
            "source": "claude-native-approval",
            "current_generation": 0,
        },
    )
    return result is not None and result.get("saved") is True
