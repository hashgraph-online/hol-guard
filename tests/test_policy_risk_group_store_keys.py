"""A Guard Cloud rule that names a command risk group must reach the store
under its ``risk-group:<group>`` id. Stored without one, a harness-scoped row
reads as a rule for every action in that harness."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_store_support import replace_remote_policies

NOW = "2026-11-14T12:00:00Z"


def _group_document(effect: str = "block") -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "group-policy", "name": "Group policy", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "block-deletes",
                        "enabled": True,
                        "match": {"riskGroups": ["deletes", "secrets"]},
                        "effect": effect,
                        "lifetime": {"mode": "permanent"},
                        "provenance": {"source": "cli-import", "createdAt": NOW},
                    }
                ],
            },
        }
    )


def _stored(store: GuardStore) -> list[tuple[str | None, str, str]]:
    with store._connect() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("select artifact_id, scope, action from policy_decisions order by artifact_id")
        return [(row["artifact_id"], row["scope"], row["action"]) for row in rows]


def test_imported_group_rule_keeps_each_group_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _group_document()
    store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="merge",
        now=NOW,
        approval_gate_grant=None,
    )

    assert _stored(store) == [
        ("risk-group:deletes", "harness", "block"),
        ("risk-group:secrets", "harness", "block"),
    ]
    # The group rows hold nothing else in the harness.
    unrelated = store.resolve_policy_decision_lookup("codex", "codex:project:mcp:safe-read", now=NOW)
    assert unrelated["decision"] is None


def test_cloud_group_rule_keeps_its_group_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    replace_remote_policies(
        store,
        [
            PolicyDecision(
                harness="*",
                scope="harness",
                action="review",
                artifact_id="risk-group:deletes",
                source="policy-bundle-canonical",
            )
        ],
        NOW,
        remote_write_authorized=True,
    )

    assert _stored(store) == [("risk-group:deletes", "harness", "review")]
    unrelated = store.resolve_policy_decision_lookup("claude-code", "claude-code:project:tool:read", now=NOW)
    assert unrelated["decision"] is None


def test_unknown_group_is_refused_instead_of_stored_without_an_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    with pytest.raises(ValueError, match="unsupported_scoped_policy_risk_group"):
        replace_remote_policies(
            store,
            [
                PolicyDecision(
                    harness="*",
                    scope="harness",
                    action="block",
                    artifact_id="risk-group:money",
                    source="policy-bundle-canonical",
                )
            ],
            NOW,
            remote_write_authorized=True,
        )
    assert _stored(store) == []
