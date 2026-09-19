"""Exact command selectors remain an authenticated additional policy predicate."""

from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime.now(timezone.utc).isoformat()
_DIGEST = exact_command_sha256("printf 'Synthetic  Value'")


def _store(tmp_path, *, scope="artifact"):
    store = GuardStore(tmp_path / "guard")
    decision = PolicyDecision(
        harness="codex",
        scope=scope,
        action="allow",
        artifact_id="synthetic:tool",
        workspace="synthetic-workspace" if scope == "workspace" else None,
        exact_command_sha256=_DIGEST,
    )
    store.upsert_policy(decision, _NOW)
    return store


@pytest.mark.parametrize("scope", ["artifact", "workspace"])
@pytest.mark.parametrize("consume", [False, True])
def test_exact_selector_is_required_in_addition_to_original_scope(tmp_path, scope, consume):
    store = _store(tmp_path, scope=scope)
    for command_digest in (None, exact_command_sha256("printf 'Synthetic Value'"), "a" * 64):
        assert (
            store.resolve_policy_decision(
                "codex",
                "synthetic:tool",
                workspace="synthetic-workspace",
                exact_command_sha256=command_digest,
                consume_one_shot=consume,
            )
            is None
        )
    selected = store.resolve_policy_decision(
        "codex",
        "synthetic:tool",
        workspace="synthetic-workspace",
        exact_command_sha256=_DIGEST,
        consume_one_shot=consume,
    )
    assert selected is not None and selected["exact_command_sha256"] == _DIGEST
    if not consume:
        assert store.claim_approval_reuse_decision(selected)
    assert (
        store.resolve_policy_decision(
            "codex",
            "different:tool",
            workspace="synthetic-workspace",
            exact_command_sha256=_DIGEST,
            consume_one_shot=consume,
        )
        is None
    )
    if scope == "workspace":
        assert (
            store.resolve_policy_decision(
                "codex",
                "synthetic:tool",
                workspace="different-workspace",
                exact_command_sha256=_DIGEST,
                consume_one_shot=consume,
            )
            is None
        )


@pytest.mark.parametrize("tamper", [None, "a" * 64])
def test_local_integrity_authenticates_exact_selector_and_claim_identity(tmp_path, tamper):
    store = _store(tmp_path)
    selected = store.resolve_policy_decision(
        "codex", "synthetic:tool", exact_command_sha256=_DIGEST, consume_one_shot=False
    )
    assert selected is not None
    assert not store.claim_approval_reuse_decision({**selected, "exact_command_sha256": tamper})
    with store._connect() as connection:
        connection.execute("update policy_decisions set exact_command_sha256 = ?", (tamper,))
    assert store.resolve_policy_decision("codex", "synthetic:tool", exact_command_sha256=tamper) is None
    assert not store.claim_approval_reuse_decision(selected)


def test_distinct_exact_selectors_do_not_replace_each_other(tmp_path):
    store = _store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="synthetic:tool",
            exact_command_sha256="b" * 64,
        ),
        _NOW,
    )
    assert len(store.list_policy_decisions()) == 2
    assert store.resolve_policy("codex", "synthetic:tool", exact_command_sha256=_DIGEST) == "allow"
    assert store.resolve_policy("codex", "synthetic:tool", exact_command_sha256="b" * 64) == "block"


@pytest.mark.parametrize(
    "scope,artifact,digest",
    [
        ("global", "synthetic:tool", "a" * 64),
        ("workspace", None, "a" * 64),
        ("artifact", "synthetic:tool", "A" * 64),
        ("artifact", "synthetic:tool", "invalid"),
    ],
)
def test_invalid_exact_selector_cannot_be_persisted(scope, artifact, digest):
    with pytest.raises(ValueError):
        PolicyDecision(harness="codex", scope=scope, action="allow", artifact_id=artifact, exact_command_sha256=digest)
