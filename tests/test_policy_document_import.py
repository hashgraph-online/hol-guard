from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, policy_document_digest
from codex_plugin_scanner.guard.policy_document_io import (
    CompiledPolicyRow,
    build_policy_document_from_rows,
    compile_policy_document,
)
from codex_plugin_scanner.guard.store import GuardStore


def _document(*, document_id: str = "policy-doc", rule_ids: tuple[str, ...] = ("rule-1",)) -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {
                "id": document_id,
                "name": "Imported policy",
                "revision": 1,
                "createdAt": "2026-07-16T12:00:00Z",
                "updatedAt": "2026-07-16T12:00:00Z",
            },
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": rule_id,
                        "enabled": True,
                        "match": {"artifacts": [f"skill:hol/{rule_id}"]},
                        "effect": "allow",
                        "reason": f"Imported {rule_id}",
                        "lifetime": {"mode": "permanent"},
                        "provenance": {
                            "source": "cli-import",
                            "createdAt": "2026-07-16T12:00:00Z",
                        },
                        "x-hol-local": {"harness": "codex", "scope": "artifact"},
                    }
                    for rule_id in rule_ids
                ],
            },
        }
    )


def _rows(store: GuardStore) -> list[sqlite3.Row]:
    with store._connect() as connection:
        return connection.execute(
            """
            select source, policy_document_schema_version, policy_document_id,
                   policy_document_digest, policy_rule_id, policy_provenance_json
            from policy_decisions order by decision_id
            """
        ).fetchall()


def test_import_persists_document_identity_and_provenance(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document()

    result = store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    assert result.inserted == 1
    assert result.replaced == 0
    assert result.digest == policy_document_digest(document)
    rows = _rows(store)
    assert len(rows) == 1
    assert dict(rows[0]) == {
        "source": "policy-yaml-import",
        "policy_document_schema_version": "guard.hashgraphonline.com/v1alpha1",
        "policy_document_id": "policy-doc",
        "policy_document_digest": result.digest,
        "policy_rule_id": "rule-1",
        "policy_provenance_json": '{"createdAt":"2026-07-16T12:00:00Z","source":"cli-import"}',
    }
    listed = store.list_policy_decisions()
    assert int(listed[0]["integrity_version"]) > 0
    assert isinstance(listed[0]["integrity_key_id"], str)
    assert isinstance(listed[0]["signed_at"], str)


def test_imported_tool_family_matches_only_the_selected_harness(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "tool-policy", "name": "Tool policy", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "allow-mcp",
                        "enabled": True,
                        "match": {"tools": ["mcp"], "harnesses": ["codex"]},
                        "effect": "allow",
                        "lifetime": {"mode": "permanent"},
                        "provenance": {
                            "source": "cli-import",
                            "createdAt": "2026-07-16T12:00:00Z",
                        },
                    }
                ],
            },
        }
    )
    store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    matching = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:mcp:safe-read",
        now="2026-07-16T12:01:00Z",
    )
    nonmatching = store.resolve_policy_decision_lookup(
        "cursor",
        "cursor:project:mcp:safe-read",
        now="2026-07-16T12:01:00Z",
    )

    assert matching["decision"] is not None
    assert matching["decision"]["action"] == "allow"
    assert nonmatching["decision"] is None


def test_imported_tool_family_respects_workspace_selector(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "workspace-tool-policy", "name": "Workspace tool policy", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "allow-workspace-mcp",
                        "enabled": True,
                        "match": {"tools": ["mcp"], "workspaces": ["project"]},
                        "effect": "allow",
                        "lifetime": {"mode": "permanent"},
                        "provenance": {
                            "source": "cli-import",
                            "createdAt": "2026-07-16T12:00:00Z",
                        },
                    }
                ],
            },
        }
    )
    store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    matching = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:mcp:safe-read",
        workspace="project",
        now="2026-07-16T12:01:00Z",
    )
    nonmatching = store.resolve_policy_decision_lookup(
        "codex",
        "codex:other:mcp:safe-read",
        workspace="other",
        now="2026-07-16T12:01:00Z",
    )

    assert matching["decision"] is not None
    assert matching["decision"]["action"] == "allow"
    assert nonmatching["decision"] is None


def test_replace_removes_only_prior_yaml_imports(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    first = _document(document_id="first", rule_ids=("rule-1",))
    second = _document(document_id="second", rule_ids=("rule-2",))
    store.import_policy_document(
        first,
        compile_policy_document(first),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    plan = store.plan_policy_document_import(
        compile_policy_document(second),
        mode="replace",
    )
    assert plan.additions == ("rule-2",)
    assert plan.replacements == ()
    assert plan.removals == ("rule-1",)

    result = store.import_policy_document(
        second,
        compile_policy_document(second),
        mode="replace",
        now="2026-07-16T12:01:00Z",
        approval_gate_grant=None,
    )

    assert result.inserted == 1
    assert result.replaced == 1
    assert [row["policy_document_id"] for row in _rows(store)] == ["second"]


def test_merge_preserves_cloud_policy_with_the_same_selector(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                artifact_id="skill:hol/rule-1",
                artifact_hash="sha256:rule-1",
                workspace=None,
                publisher=None,
                action="block",
                reason="cloud policy",
                owner=None,
                source="cloud-sync",
            )
        ],
        now="2026-07-16T11:59:00Z",
        remote_write_authorized=True,
    )
    document = _document(rule_ids=("rule-1",))

    plan = store.plan_policy_document_import(compile_policy_document(document), mode="merge")
    result = store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    with store._connect() as connection:
        sources = [
            str(row["source"])
            for row in connection.execute("select source from policy_decisions order by source").fetchall()
        ]
    assert plan.additions == ("rule-1",)
    assert plan.replacements == ()
    assert result.replaced == 0
    assert sources == ["cloud-sync", "policy-yaml-import"]


def test_empty_replace_clears_prior_yaml_imports(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    first = _document(rule_ids=("rule-1",))
    empty = _document(document_id="empty", rule_ids=())
    store.import_policy_document(
        first,
        compile_policy_document(first),
        mode="merge",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )

    result = store.import_policy_document(
        empty,
        compile_policy_document(empty),
        mode="replace",
        now="2026-07-16T12:01:00Z",
        approval_gate_grant=None,
    )

    assert result.inserted == 0
    assert result.replaced == 1
    assert _rows(store) == []


def test_import_rolls_back_every_row_on_insert_failure(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document(rule_ids=("rule-1", "rule-2"))
    with store._connect() as connection:
        connection.execute(
            """
            create trigger reject_rule_two before insert on policy_decisions
            when new.policy_rule_id = 'rule-2'
            begin
              select raise(abort, 'forced import failure');
            end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="forced import failure"):
        store.import_policy_document(
            document,
            compile_policy_document(document),
            mode="merge",
            now="2026-07-16T12:00:00Z",
            approval_gate_grant=None,
        )

    assert _rows(store) == []


def test_duplicate_compiled_selector_is_rejected_before_writes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document(rule_ids=("rule-1", "rule-1"))

    with pytest.raises(ValueError, match="duplicate_policy_selector"):
        store.import_policy_document(
            document,
            compile_policy_document(document),
            mode="merge",
            now="2026-07-16T12:00:00Z",
            approval_gate_grant=None,
        )

    assert _rows(store) == []


def test_privileged_export_preserves_imported_rule_identity_and_semantics(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document(rule_ids=("rule-a", "rule-b"))
    original_rows = compile_policy_document(document)

    store.import_policy_document(
        document,
        original_rows,
        mode="replace",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )
    exported = build_policy_document_from_rows(
        store.list_policy_decisions(),
        include_provenance=True,
    )
    round_trip_rows = compile_policy_document(exported)

    def semantic_row(row: CompiledPolicyRow) -> tuple[object, ...]:
        decision = row.decision
        return (
            row.rule_id,
            decision.harness,
            decision.scope,
            decision.action,
            decision.artifact_id,
            decision.artifact_hash,
            decision.workspace,
            decision.publisher,
            decision.expires_at,
        )

    assert [semantic_row(row) for row in round_trip_rows] == [semantic_row(row) for row in original_rows]
