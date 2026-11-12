from __future__ import annotations

import json
import sqlite3
import time
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline
from codex_plugin_scanner.guard.codex_hook_integrity import (
    HOOK_MANIFEST_MAC_ALGORITHM,
    HookSecretMaterial,
    authenticate_hook_manifest_text,
)
from codex_plugin_scanner.guard.local_authority_integrity import (
    LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE,
    sign_local_authority_payload,
    verify_local_authority_payload,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import PolicyDecisionLookupResult

_HARNESS = "codex"
_ARTIFACT_ID = "codex:project:tool-action:local-integrity"
_ARTIFACT_HASH = "sha256:local-integrity"
_CREATED_AT = "2026-07-17T12:00:00+00:00"
_EXPIRES_AT = "2026-07-17T14:00:00+00:00"


def _record_local_once(store: GuardStore) -> str:
    approval_id = store.record_local_once_approval(
        request_id="request-local-integrity",
        harness=_HARNESS,
        artifact_id=_ARTIFACT_ID,
        artifact_hash=_ARTIFACT_HASH,
        workspace="/workspace/a",
        publisher="publisher-a",
        action="allow",
        created_at=_CREATED_AT,
        expires_at=_EXPIRES_AT,
    )
    assert approval_id is not None
    return approval_id


def _workspace_policy_key(workspace: str) -> str:
    normalized = str(Path(workspace).expanduser().resolve())
    return f"workspace:{sha256(normalized.encode('utf-8')).hexdigest()}"


def _lookup(
    store: GuardStore,
    *,
    now: str = "2026-07-17T12:30:00+00:00",
) -> PolicyDecisionLookupResult:
    return store.resolve_policy_decision_lookup(
        _HARNESS,
        _ARTIFACT_ID,
        _ARTIFACT_HASH,
        workspace="/workspace/a",
        publisher="publisher-a",
        now=now,
        consume_one_shot=False,
    )


def test_local_authority_hmac_is_domain_and_purpose_separated() -> None:
    key = b"k" * 32
    payload = {"action": "allow", "artifact_id": _ARTIFACT_ID}
    first = sign_local_authority_payload(
        payload,
        key=key,
        key_id="key-1",
        purpose="guard-local-once-approval",
        signed_at=_CREATED_AT,
    )
    second = sign_local_authority_payload(
        payload,
        key=key,
        key_id="key-1",
        purpose="cursor-native-shell-allow",
        signed_at=_CREATED_AT,
    )

    assert first["payload_mac"] != second["payload_mac"]
    assert (
        verify_local_authority_payload(
            payload,
            first,
            key=key,
            key_id="key-1",
            purpose="guard-local-once-approval",
        ).status
        == "valid"
    )
    wrong_purpose = verify_local_authority_payload(
        payload,
        first,
        key=key,
        key_id="key-1",
        purpose="cursor-native-shell-allow",
    )
    assert wrong_purpose.status == "tampered"
    assert wrong_purpose.message == "local_authority_integrity_payload_hash_mismatch"


def test_malformed_local_authority_payload_fails_closed_without_raising() -> None:
    key = b"k" * 32
    integrity = sign_local_authority_payload(
        {"action": "allow"},
        key=key,
        key_id="key-1",
        purpose="guard-local-once-approval",
        signed_at=_CREATED_AT,
    )

    result = verify_local_authority_payload(
        {"action": object()},
        integrity,
        key=key,
        key_id="key-1",
        purpose="guard-local-once-approval",
    )

    assert result.status == "tampered"
    assert result.message == "local_authority_integrity_payload_invalid"


def test_non_ascii_forged_integrity_metadata_fails_closed_without_raising() -> None:
    key = b"k" * 32
    payload = {"action": "allow"}
    integrity = sign_local_authority_payload(
        payload,
        key=key,
        key_id="key-1",
        purpose="guard-local-once-approval",
        signed_at=_CREATED_AT,
    )

    result = verify_local_authority_payload(
        payload,
        {**integrity, "payload_hash": "\N{BOMB}"},
        key=key,
        key_id="key-1",
        purpose="guard-local-once-approval",
    )

    assert result.status == "tampered"
    assert result.message == "local_authority_integrity_payload_hash_mismatch"


def test_no_runtime_signs_nothing_and_verifies_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    with pytest.raises(RuntimeError, match="requires the native runtime"):
        _ = sign_local_authority_payload(
            {"action": "allow"},
            key=b"k" * 32,
            key_id="key-1",
            purpose="guard-local-once-approval",
            signed_at=_CREATED_AT,
        )
    result = verify_local_authority_payload(
        {"action": "allow"},
        {"integrity_version": 1},
        key=b"k" * 32,
        key_id="key-1",
        purpose="guard-local-once-approval",
    )
    assert result.status != "valid"
    assert result.message == LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE


def test_runtime_calls_share_the_active_and_explicit_deadlines(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    deadlines: list[object] = []

    def answer(*_args: object, **kwargs: object) -> None:
        deadlines.append(kwargs.get("deadline"))

    monkeypatch.setattr(runtime_request, "runtime_answer", answer)
    hook_deadline = time.monotonic() + 1.0
    with hook_validation_deadline(hook_deadline):
        _ = verify_local_authority_payload(
            {"action": "allow"}, {"integrity_version": 1}, key=b"k" * 32, key_id="key-1", purpose="p"
        )
    signing_deadline = time.monotonic() + 0.5
    with pytest.raises(RuntimeError):
        _ = sign_local_authority_payload(
            {"action": "allow"},
            key=b"k" * 32,
            key_id="key-1",
            purpose="p",
            signed_at=_CREATED_AT,
            deadline=signing_deadline,
        )
    assert deadlines == [hook_deadline, signing_deadline]


def test_an_unverifiable_hook_manifest_is_not_reported_as_foreign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    manifest = json.dumps({"authentication": {"algorithm": HOOK_MANIFEST_MAC_ALGORITHM}})
    secret = HookSecretMaterial(installation_id="install-1", key_id="key-1", key=b"k" * 32)

    with pytest.raises(CodexHookIntegrityError) as error:
        _ = authenticate_hook_manifest_text(tmp_path, manifest, _secret=secret)

    assert error.value.reason == "codex_hook_manifest_verification_unavailable"


def test_authentic_local_once_row_resolves_and_claims(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = _record_local_once(store)

    lookup = _lookup(store)

    assert lookup["ignored_local_integrity"] is None
    decision = lookup["decision"]
    assert isinstance(decision, dict)
    assert decision["approval_id"] == approval_id
    assert decision["integrity_status"] == "valid"
    assert store.claim_approval_reuse_decision(decision, now="2026-07-17T12:31:00+00:00")


def test_local_once_lookup_reads_existing_integrity_key_without_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _ = _record_local_once(store)
    original_lookup = store._policy_integrity_secret_material  # pyright: ignore[reportPrivateUsage]
    create_flags: list[bool] = []

    def tracked_lookup(*, create: bool) -> tuple[bytes | None, str | None]:
        create_flags.append(create)
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", tracked_lookup)

    assert _lookup(store)["decision"] is not None
    assert create_flags == [False]


def test_unsigned_legacy_local_once_row_cannot_grant_and_reports_integrity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with sqlite3.connect(store.path) as connection:
        _ = connection.execute(
            """
            insert into guard_local_once_approvals (
              approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher,
              action, created_at, expires_at, claimed_at
            ) values (?, ?, ?, ?, ?, ?, ?, 'allow', ?, ?, null)
            """,
            (
                "legacy-unsigned",
                "request-legacy-unsigned",
                _HARNESS,
                _ARTIFACT_ID,
                _ARTIFACT_HASH,
                _workspace_policy_key("/workspace/a"),
                "publisher-a",
                _CREATED_AT,
                _EXPIRES_AT,
            ),
        )

    lookup = _lookup(store)

    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "missing_integrity"
    assert ignored["integrity_message"] == "local_authority_integrity_metadata_missing"
    assert (
        store.approval_reuse_validation_reason(
            _HARNESS,
            _ARTIFACT_ID,
            _ARTIFACT_HASH,
            "/workspace/a",
            "publisher-a",
            "2026-07-17T12:30:00+00:00",
        )
        == "approval_reuse_integrity_failure"
    )
    events = store.list_events(event_name="rule.ignored.local_integrity")
    assert len(events) == 1
    event_payload = events[0]["payload"]
    assert isinstance(event_payload, dict)
    assert event_payload["source"] == "approval-gate-once"
    assert event_payload["integrity_status"] == "missing_integrity"


def test_post_storage_local_once_tamper_cannot_grant(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = _record_local_once(store)
    with sqlite3.connect(store.path) as connection:
        _ = connection.execute(
            "update guard_local_once_approvals set action = 'block' where approval_id = ?",
            (approval_id,),
        )

    lookup = _lookup(store)

    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "tampered"
    assert ignored["integrity_message"] == "local_authority_integrity_payload_hash_mismatch"


def test_forged_local_once_mac_cannot_grant(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = _record_local_once(store)
    with sqlite3.connect(store.path) as connection:
        _ = connection.execute(
            "update guard_local_once_approvals set payload_mac = ? where approval_id = ?",
            ("00" * 32, approval_id),
        )

    lookup = _lookup(store)

    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "tampered"
    assert ignored["integrity_message"] == "local_authority_integrity_mac_mismatch"


def test_local_once_claim_revalidates_integrity_after_lookup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = _record_local_once(store)
    lookup = _lookup(store)
    decision = lookup["decision"]
    assert isinstance(decision, dict)
    with sqlite3.connect(store.path) as connection:
        _ = connection.execute(
            "update guard_local_once_approvals set payload_mac = ? where approval_id = ?",
            ("forged-after-lookup", approval_id),
        )

    assert not store.claim_approval_reuse_decision(decision, now="2026-07-17T12:31:00+00:00")


def test_resetting_claimed_at_cannot_replay_consumed_local_once_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = _record_local_once(store)
    decision = _lookup(store)["decision"]
    assert isinstance(decision, dict)
    assert store.claim_approval_reuse_decision(decision, now="2026-07-17T12:31:00+00:00")
    with sqlite3.connect(store.path) as connection:
        _ = connection.execute(
            "update guard_local_once_approvals set claimed_at = null where approval_id = ?",
            (approval_id,),
        )

    replay_lookup = _lookup(store, now="2026-07-17T12:32:00+00:00")

    assert replay_lookup["decision"] is None
    ignored = replay_lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "tampered"


def test_legacy_local_once_schema_is_migrated_without_trusting_existing_rows(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    with sqlite3.connect(guard_home / "guard.db") as connection:
        _ = connection.execute(
            """
            create table guard_local_once_approvals (
              approval_id text primary key,
              request_id text not null,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              workspace text,
              publisher text,
              action text not null,
              created_at text not null,
              expires_at text not null,
              claimed_at text
            )
            """
        )
        _ = connection.execute(
            """
            insert into guard_local_once_approvals values (?, ?, ?, ?, ?, ?, ?, 'allow', ?, ?, null)
            """,
            (
                "legacy-before-migration",
                "request-before-migration",
                _HARNESS,
                _ARTIFACT_ID,
                _ARTIFACT_HASH,
                _workspace_policy_key("/workspace/a"),
                "publisher-a",
                _CREATED_AT,
                _EXPIRES_AT,
            ),
        )

    store = GuardStore(guard_home)
    with sqlite3.connect(store.path) as connection:
        column_rows = cast(
            list[tuple[object, ...]],
            connection.execute("pragma table_info(guard_local_once_approvals)").fetchall(),
        )
        columns = {str(row[1]) for row in column_rows}

    assert {"integrity_version", "payload_hash", "payload_mac", "integrity_key_id", "signed_at"} <= columns
    lookup = _lookup(store)
    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "missing_integrity"
