"""Answer a Claude-native approval's persist plan the way the resident does.

The resident decides what a native approval saves (see the Rust
``hook_decision_native_permission_persist_tests`` replay suite). A test
that cares what the *store* does with a plan, not how the plan is decided,
answers it here instead of starting a resident.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands_support_permission_store as permission_store


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


def retained_plan(inputs: Mapping[str, Any], *, inventory_approved: bool) -> dict[str, Any]:
    """The plan for a stronger authoritative action: no policy row, the current policy retained."""

    return {
        "stored_artifact_hash": None,
        "policy_action": None,
        "events": [
            {
                "name": "claude/native_permission_current_policy_retained",
                "payload": {
                    "artifact_id": inputs["artifact_id"],
                    "artifact_hash": inputs["artifact_hash"],
                    "native_action": inputs["action"],
                    "authoritative_action": inputs["authoritative_action"],
                },
                "before_policy": False,
            }
        ],
        "inventory_approved": inventory_approved,
    }


def answer_persist_plans(monkeypatch: pytest.MonkeyPatch, *, inventory_approved: bool = True) -> list[dict[str, Any]]:
    """Answer every persist-plan query; returns the inputs the caller sent, in order."""

    asked: list[dict[str, Any]] = []

    def plan(inputs: Mapping[str, Any], **_kwargs: object) -> dict[str, Any]:
        asked.append(dict(inputs))
        if inputs["authoritative_action"] in {None, "allow"}:
            return saved_plan(inputs, inventory_approved=inventory_approved)
        return retained_plan(inputs, inventory_approved=inventory_approved)

    monkeypatch.setattr(permission_store, "native_permission_persist_plan", plan)
    return asked
