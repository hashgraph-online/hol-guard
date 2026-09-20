from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_slo_revocation import revoke_acknowledged_authority


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, error: str | None) -> SimpleNamespace:
    from codex_plugin_scanner.guard import native_hook_edge, native_resident_client, native_runtime
    from codex_plugin_scanner.guard import native_policy_snapshot_acked as acked
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        _RUST_SNAPSHOT_STATE_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    home = tmp_path / "guard"
    authority = home / NATIVE_RUNTIME_STATE_DIRECTORY / _RUST_SNAPSHOT_STATE_NAME
    authority.parent.mkdir(parents=True)
    authority.write_bytes(b"opaque-accepted-authority")
    publisher = SimpleNamespace(closed=False, _thread=None, is_ready=lambda: True)

    def close() -> None:
        publisher.closed = True

    publisher.close = close
    binding = {"generation": 19, "policy_digest": "a" * 64, "runtime_identity": "b" * 64, "mode": "enforce"}
    monkeypatch.setattr(
        acked, "acked_snapshot_binding_for_store", lambda _store: binding if authority.exists() else None
    )
    monkeypatch.setattr(
        native_runtime,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(path=tmp_path / "runtime")),
    )
    monkeypatch.setattr(native_runtime, "_isolated_environment", lambda: {})
    requests: list[dict[str, object]] = []

    def encode(**kwargs: object) -> bytes:
        assert kwargs["snapshot"] is binding
        assert authority.read_bytes() == b"opaque-accepted-authority"
        return b"exact-old-generation-request"

    def native_request(**kwargs: object) -> bytes:
        assert publisher.closed and not authority.exists()
        assert authority.with_name(authority.name + ".revoked-fixture").read_bytes() == b"opaque-accepted-authority"
        assert kwargs["payload"] == b"exact-old-generation-request"
        assert kwargs["raw_hook_envelope"] is True
        requests.append(kwargs)
        return json.dumps({"error": error} if error else {"decision": "allow"}).encode()

    monkeypatch.setattr(native_hook_edge, "_encode_hook_envelope", encode)
    monkeypatch.setattr(native_resident_client, "native_resident_client_request", native_request)
    worker = SimpleNamespace(
        policy_snapshot_publisher=publisher, prepare_workspace_policy=lambda *_args, **_kwargs: None
    )
    session = SimpleNamespace(
        root=tmp_path,
        guard_home=home,
        workspace=tmp_path / "workspace",
        store=object(),
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
    )
    return SimpleNamespace(session=session, requests=requests, authority=authority, worker=worker)


def test_withdrawal_requires_old_native_generation_rejection_and_retains_private_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, monkeypatch, error="native_policy_snapshot_context_mismatch")
    assert revoke_acknowledged_authority(fixture.session) == {
        "revoked_generation": True,
        "policy_prepare_rejected": True,
        "refresh_suspended": True,
    }
    assert len(fixture.requests) == 1


@pytest.mark.parametrize("error", [None, "snapshot_expired", "native_policy_snapshot_missing"])
def test_allow_expiry_or_fresh_empty_resident_cannot_prove_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str | None
) -> None:
    fixture = _fixture(tmp_path, monkeypatch, error=error)
    with pytest.raises(RuntimeError, match="did not reject the withdrawn generation"):
        revoke_acknowledged_authority(fixture.session)


def test_hook_barrier_cannot_keep_a_withdrawn_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch, error="native_policy_snapshot_context_mismatch")
    fixture.worker.prepare_workspace_policy = lambda *_args, **_kwargs: {"generation": 19}
    with pytest.raises(RuntimeError, match="readiness barrier"):
        revoke_acknowledged_authority(fixture.session)


def test_revocation_rejects_non_private_scope_without_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch, error="native_policy_snapshot_context_mismatch")
    fixture.session.root = fixture.session.guard_home
    with pytest.raises(RuntimeError, match="private child home"):
        revoke_acknowledged_authority(fixture.session)
    assert fixture.authority.read_bytes() == b"opaque-accepted-authority"
    assert not fixture.requests
