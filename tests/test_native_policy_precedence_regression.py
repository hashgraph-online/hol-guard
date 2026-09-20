"""Regression for the documented generic specificity and recency contract."""

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from tests.test_canonical_policy_row_authority import _ARTIFACT, _activated_store


@pytest.mark.parametrize("cloud_action,local_action", [("block", "allow"), ("allow", "block")])
@pytest.mark.parametrize("local_is_newer", [True, False])
def test_current_generic_preview_preserves_authenticated_recency(
    tmp_path: Path, cloud_action: str, local_action: str, local_is_newer: bool
) -> None:
    store = _activated_store(tmp_path, action=cloud_action)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action=local_action,
            artifact_id=_ARTIFACT,
            artifact_hash="synthetic-hash",
            source="local",
        ),
        "2026-09-17T00:00:01Z" if local_is_newer else "2026-09-16T23:59:59Z",
    )
    direct = store.resolve_policy("codex", _ARTIFACT, "synthetic-hash", now="2026-09-17T00:00:02Z")
    preview = store.resolve_policy_decision_lookup(
        "codex",
        _ARTIFACT,
        "synthetic-hash",
        now="2026-09-17T00:00:02Z",
        consume_one_shot=False,
    )
    assert direct == (local_action if local_is_newer else cloud_action)
    assert preview["decision"]["action"] == direct
    if direct == "allow":
        assert store.claim_approval_reuse_decision(preview["decision"], now="2026-09-17T00:00:02Z")


@pytest.mark.parametrize(
    "first_scope,second_scope",
    [
        ("artifact", "workspace"),
        ("workspace", "publisher"),
        ("publisher", "harness"),
        ("harness", "global"),
    ],
)
def test_scope_precedence_is_shared_even_when_broader_block_is_newer(
    tmp_path: Path, first_scope: str, second_scope: str
) -> None:
    store = _activated_store(tmp_path, action="allow")
    store.clear_policy_bundle_authority("2026-09-17T00:00:00Z", policy_bundle_last_error={"reason": "fixture-reset"})
    artifact_id = "codex:project:prompt-env-read:synthetic-precedence"
    for scope, action, now in (
        (first_scope, "allow", "2026-09-17T00:00:01Z"),
        (second_scope, "block", "2026-09-17T00:00:02Z"),
    ):
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope=scope,
                action=action,
                artifact_id=artifact_id,
                workspace="synthetic-workspace" if scope == "workspace" else None,
                publisher="synthetic-publisher" if scope == "publisher" else None,
                source="local",
            ),
            now,
        )
    for consume in (False, True):
        selected = store.resolve_policy_decision(
            "codex",
            artifact_id,
            workspace="synthetic-workspace",
            publisher="synthetic-publisher",
            now="2026-09-17T00:00:03Z",
            consume_one_shot=consume,
        )
        assert selected is not None
        assert selected["action"] == "allow"
        assert selected["scope"] == first_scope


def test_tied_signed_row_ids_cannot_change_the_semantic_winner(tmp_path: Path) -> None:
    store = _activated_store(tmp_path, action="allow")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=_ARTIFACT,
            artifact_hash="synthetic-hash",
            source="local",
        ),
        "2026-09-17T00:00:00Z",
    )
    for mutate in (False, True):
        if mutate:
            with sqlite3.connect(store.path) as connection:
                connection.execute(
                    "update policy_decisions set decision_id = 50000 where source = 'policy-bundle-canonical'"
                )
        for consume in (False, True):
            selected = store.resolve_policy_decision(
                "codex",
                _ARTIFACT,
                "synthetic-hash",
                now="2026-09-17T00:00:02Z",
                consume_one_shot=consume,
            )
            assert selected is not None and selected["action"] == "block"


@pytest.mark.parametrize("mutation", ["expired", "tampered"])
def test_ineligible_newer_local_allow_cannot_hide_signed_block(tmp_path: Path, mutation: str) -> None:
    store = _activated_store(tmp_path, action="block")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=_ARTIFACT,
            artifact_hash="synthetic-hash",
            source="local",
            expires_at="2026-09-17T00:00:02Z" if mutation == "expired" else None,
        ),
        "2026-09-17T00:00:01Z",
    )
    if mutation == "tampered":
        with sqlite3.connect(store.path) as connection:
            connection.execute("update policy_decisions set payload_mac = 'invalid' where source = 'local'")
    for consume in (False, True):
        selected = store.resolve_policy_decision(
            "codex",
            _ARTIFACT,
            "synthetic-hash",
            now="2026-09-17T00:00:03Z",
            consume_one_shot=consume,
        )
        assert selected is not None and selected["action"] == "block"
