"""Answer a Claude-native approval's persist plan the way the resident does.

The resident decides what a native approval saves (see the Rust
``hook_decision_native_permission_persist_tests`` replay suite). A test
that cares what the *store* does with a plan, not how the plan is decided,
answers it here instead of starting a resident.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


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
