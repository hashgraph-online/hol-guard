"""Native-review reuse holds closed whenever the native resident gives no answer.

The consume, the exact peek and the claim are all resident-owned. With the
resident unavailable, none may allow, and the single-use grant stays unspent.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_guard_store, native_store_policy, store_policy
from codex_plugin_scanner.guard.daemon.hook_native_review_binding import (
    native_review_claimed_allow,
    native_review_settle,
)
from codex_plugin_scanner.guard.store import GuardStore

_IDENTITY = f"native-review-v4:{'a' * 64}:deny:review:review:native_sensitive_access_review"
_ARTIFACT = "claude-code:native-pretool:Bash"


def _resolved_allow(store: GuardStore, workspace: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with store._connect() as connection:
        connection.execute(
            """insert into approval_requests
               (request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash,
                policy_action, recommended_scope, changed_fields_json, source_scope, config_path,
                workspace, launch_target, review_command, approval_url, status, resolution_action,
                resolution_scope, created_at, resolved_at)
               values ('r1', 'claude-code', ?, 'Bash', 'native_review', ?, 'require-reapproval', 'once',
                       '[]', 'workspace', '/cfg', ?, 'cat .env', 'cmd', 'http://127.0.0.1/a', 'resolved',
                       'allow', 'once', ?, ?)""",
            (_ARTIFACT, _IDENTITY, workspace, now, now),
        )


def _effects(store: GuardStore) -> int:
    with store._connect() as connection:
        return int(connection.execute("select count(*) from guard_continuation_effects").fetchone()[0])


def test_consume_refuses_and_spends_nothing_without_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    _resolved_allow(store, str(tmp_path))
    monkeypatch.setattr(native_guard_store, "ensure_resident_prerequisite", lambda _home, **_kwargs: False)
    kwargs = {
        "harness": "claude-code",
        "artifact_id": _ARTIFACT,
        "tool_name": "Bash",
        "launch_target": "cat .env",
        "workspace": tmp_path,
        "identity": _IDENTITY,
    }

    with pytest.raises(sqlite3.OperationalError):
        store.consume_native_review_approval(
            harness="claude-code",
            artifact_id=_ARTIFACT,
            artifact_name="Bash",
            artifact_hash=_IDENTITY,
            launch_target="cat .env",
            workspace=str(tmp_path),
            now=datetime.now(timezone.utc).isoformat(),
        )
    assert native_review_settle(store, **kwargs, spend=True) is None
    assert _effects(store) == 0


def test_settle_spends_an_approve_once_only_when_asked(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    _resolved_allow(store, str(tmp_path))
    kwargs = {
        "harness": "claude-code",
        "artifact_id": _ARTIFACT,
        "tool_name": "Bash",
        "launch_target": "cat .env",
        "workspace": tmp_path,
        "identity": _IDENTITY,
    }

    assert native_review_settle(store, **kwargs, spend=False) is None
    assert _effects(store) == 0
    assert native_review_settle(store, **kwargs, spend=True) == "allowed"
    assert native_review_settle(store, **kwargs, spend=True) is None
    assert _effects(store) == 1


def _claimed(store: GuardStore, tmp_path: Path, *, claim: bool) -> bool:
    return native_review_claimed_allow(
        store,
        harness="claude-code",
        artifact_id=_ARTIFACT,
        workspace=tmp_path,
        identity=_IDENTITY,
        claimed_saved_allow_hash=_IDENTITY,
        claimed_approval_request_id=None,
        claim_saved_approval=claim,
    )


def test_peek_denies_when_the_resident_gives_no_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    # Reach the resident round trip: key material exists and the verifier is provisioned.
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda create=False: (b"k" * 32, "key-id"))
    monkeypatch.setattr(store_policy, "provision_native_policy_verifier_key", lambda *_args: None)
    monkeypatch.setattr(store_policy, "_resident_request", lambda **_kwargs: None)

    with pytest.raises(ValueError, match="native_policy_decision_lookup_unavailable"):
        store.peek_local_once_approval(
            harness="claude-code",
            artifact_id=_ARTIFACT,
            artifact_hash=_IDENTITY,
            workspace=str(tmp_path),
            publisher=None,
            now=datetime.now(timezone.utc).isoformat(),
        )


def test_claimed_allow_denies_when_the_resident_gives_no_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    _record_once(store, tmp_path)

    calls: list[str] = []

    def unavailable(method: str, _args: object) -> object:
        calls.append(method)
        raise native_guard_store.NativeGuardStoreUnavailable("native_guard_store_unavailable")

    monkeypatch.setattr(store, "_native_store_call", unavailable)

    # Neither a claim nor a live completion repeats a call that may have landed.
    for claim in (False, True):
        calls.clear()
        assert _claimed(store, tmp_path, claim=claim) is False
        assert calls == ["settle_claimed_native_allow"]


def test_claimed_allow_provisions_the_resident_verifier_before_settling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _record_once(store, tmp_path)
    key, _key_id = store._policy_integrity_secret_material(create=False)
    assert key is not None

    steps: list[object] = []
    monkeypatch.setattr(store, "_provision_resident_verifier", lambda given=None: steps.append(given))

    def settle(method: str, _args: object) -> object:
        steps.append(method)
        return True

    monkeypatch.setattr(store, "_native_store_call", settle)

    # A resident that restarted without its verifier is served again from the
    # keyring key the settle already read, as the policy lookup does.
    assert _claimed(store, tmp_path, claim=False) is True
    assert steps == [key, "settle_claimed_native_allow"]


def _record_once(store: GuardStore, tmp_path: Path, *, request_id: str = "r1") -> None:
    now = datetime.now(timezone.utc)
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness="claude-code",
        artifact_id=_ARTIFACT,
        artifact_hash=_IDENTITY,
        workspace=str(tmp_path),
        publisher=None,
        action="allow",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    assert approval_id is not None


def test_claimed_allow_settles_the_exact_once_approval_in_the_resident(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _record_once(store, tmp_path)

    # A live completion reads the allow without spending it; a retry spends it once.
    assert _claimed(store, tmp_path, claim=False) is True
    assert _claimed(store, tmp_path, claim=True) is True
    assert _claimed(store, tmp_path, claim=True) is False
    assert _claimed(store, tmp_path, claim=False) is False


def test_claimed_allow_refuses_another_identity_or_request(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _record_once(store, tmp_path)
    other = _IDENTITY.replace("a" * 64, "b" * 64)

    assert (
        native_review_claimed_allow(
            store,
            harness="claude-code",
            artifact_id=_ARTIFACT,
            workspace=tmp_path,
            identity=_IDENTITY,
            claimed_saved_allow_hash=other,
            claimed_approval_request_id=None,
            claim_saved_approval=True,
        )
        is False
    )
    assert (
        native_review_claimed_allow(
            store,
            harness="claude-code",
            artifact_id=_ARTIFACT,
            workspace=tmp_path,
            identity=_IDENTITY,
            claimed_saved_allow_hash=_IDENTITY,
            claimed_approval_request_id="another-request",
            claim_saved_approval=True,
        )
        is False
    )
    # Neither refusal spent the approval.
    assert _claimed(store, tmp_path, claim=True) is True


def test_claim_denies_when_the_resident_gives_no_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    decision = {
        "action": "allow",
        "approval_id": "approval-1",
        "request_id": "r1",
        "scope": "artifact",
        "source": "local-once",
    }
    # The claim is the spend, and it is resident-owned.
    monkeypatch.setattr(native_store_policy, "_resident_request", lambda **_kwargs: None)

    assert store.claim_approval_reuse_decision(decision, consume_local_once=True) is False
