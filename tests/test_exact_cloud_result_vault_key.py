"""The signed exact Cloud result names the vault key instead of shipping it."""

from __future__ import annotations

import time
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_guard_store
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from codex_plugin_scanner.guard.store_exact_cloud_review import StoreExactCloudReviewMixin


class _Owner:
    def __init__(self, secret_store: object) -> None:
        self._policy_integrity_secret_store = secret_store
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.minted: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes, str]:
        self.minted.append(create)
        return b"\x09" * 32, "key-1"

    def hold_oauth_credential_lock(self) -> nullcontext[None]:
        return nullcontext()

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, args))
        return {"applied": True} if method == "apply_signed_remote_exact_result" else None


def _apply(owner: _Owner, action: str) -> dict[str, Any]:
    resolve = vars(StoreExactCloudReviewMixin)["resolve_one_request_with_signed_remote_exact_result"]
    _ = resolve(
        owner,
        "req-1",
        receipt_id="rcpt-1",
        resolution_action=action,
        resolution_scope="exact",
        reason="cloud",
        expected_capability=None,
        expected_oauth_binding={},
        expected_request={},
        expected_raw_request={},
        receipt_expires_at="2030-01-01T00:00:00Z",
    )
    method, args = owner.calls[-1]
    assert method == "apply_signed_remote_exact_result"
    return args


def test_a_plain_vault_allow_sends_only_the_flag(tmp_path: Path) -> None:
    owner = _Owner(EncryptedFileSecretStore(tmp_path))
    args = _apply(owner, "allow")
    assert args["vault_key"] is True
    assert "integrity_key_b64" not in args
    assert "integrity_key_id" not in args
    # The key is still minted first, so the vault the resident reads holds it.
    assert owner.minted == [True]


def test_another_store_still_sends_its_key(tmp_path: Path) -> None:
    owner = _Owner(object())
    args = _apply(owner, "allow")
    assert "vault_key" not in args
    assert args["integrity_key_id"] == "key-1"
    assert isinstance(args["integrity_key_b64"], str)


def test_a_block_sends_no_key(tmp_path: Path) -> None:
    owner = _Owner(EncryptedFileSecretStore(tmp_path))
    args = _apply(owner, "block")
    assert "vault_key" not in args
    assert args["integrity_key_b64"] is None
    assert args["integrity_key_id"] is None
    assert owner.minted == []


@pytest.mark.parametrize(
    ("args", "feature"),
    [
        ({"vault_key": True}, native_guard_store.GUARD_STORE_VAULT_KEY_FEATURE),
        ({"integrity_key_b64": None}, native_guard_store.GUARD_STORE_FEATURE),
    ],
)
def test_a_vault_key_call_requires_the_vault_feature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: dict[str, object], feature: str
) -> None:
    seen: dict[str, object] = {}

    def fake_request(**kwargs: object) -> None:
        seen.update(kwargs)
        return None

    monkeypatch.setattr(native_guard_store, "ensure_resident_prerequisite", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(native_guard_store, "_resident_request", fake_request)
    monkeypatch.setattr(native_guard_store, "native_runtime_status", lambda: SimpleNamespace(identity=None))
    with pytest.raises(native_guard_store.NativeGuardStoreUnavailable):
        _ = native_guard_store.native_guard_store_call(
            store_path=tmp_path / "guard.db",
            guard_home=tmp_path,
            source="local",
            method="apply_signed_remote_exact_result",
            args=args,
            deadline_monotonic=time.monotonic() + 30,
        )
    assert seen["required_feature"] == feature
