"""HGP-159: portable export/import roundtrips retain policy meaning."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_document_compile import (
    build_policy_document_from_rows,
    compile_policy_document,
)
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.store import GuardStore


def test_allow_block_review_roundtrip_preserves_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    now = "2026-07-16T12:00:00Z"
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="codex:project:blocked",
            reason="block it",
            source="local",
            expires_at="2026-08-01T00:00:00Z",
        ),
        now,
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="review",
            artifact_id="codex:project:reviewed",
            reason="review it",
            source="local",
        ),
        now,
    )
    document = build_policy_document_from_rows(store.list_policy_decisions(), include_provenance=True)
    compiled = compile_policy_document(document)
    actions = {row.rule_id: row.decision.action for row in compiled}
    assert "block" in actions.values()
    assert "review" in actions.values()
    assert all(row.rule_id for row in compiled)


def test_redacted_export_cannot_silently_broaden() -> None:
    rows = [
        {
            "decision_id": 1,
            "harness": "codex",
            "scope": "workspace",
            "action": "allow",
            "artifact_id": "codex:project:ws",
            "workspace": "secret-workspace",
            "updated_at": "2026-07-16T12:00:00Z",
            "source": "local",
        }
    ]
    with pytest.raises(PolicyCompilationError, match="sensitive_local_policy_requires_provenance"):
        build_policy_document_from_rows(rows, include_provenance=False)


def test_ignore_has_no_local_row() -> None:
    with pytest.raises(PolicyCompilationError, match="inert_ignore_has_no_local_row"):
        build_policy_document_from_rows(
            [
                {
                    "decision_id": 2,
                    "harness": "codex",
                    "scope": "artifact",
                    "action": "ignore",
                    "artifact_id": "codex:project:ignored",
                    "updated_at": "2026-07-16T12:00:00Z",
                    "source": "local",
                }
            ],
            include_provenance=True,
        )
