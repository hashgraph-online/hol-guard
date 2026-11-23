"""Store calls that sign with the install key name the plain vault instead of shipping it."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_store_policy import integrity_key_fields
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from codex_plugin_scanner.guard.store_event_receipts import StoreEventReceiptsMixin
from codex_plugin_scanner.guard.store_policy_document import StorePolicyDocumentMixin

_KEY = b"\x07" * 32


class _Owner:
    def __init__(self, secret_store: object, *, key: bytes | None = _KEY) -> None:
        self._policy_integrity_secret_store = secret_store
        self._key = key
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        assert create is True
        return (self._key, "key-1") if self._key is not None else (None, None)

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, args))
        return "approval-1"

    def _connect(self) -> nullcontext[None]:
        return nullcontext()

    def _refresh_policy_integrity_state(self, connection: object, **_: object) -> dict[str, str]:
        return {"mode": "protected"}

    def _load_policy_integrity_control_state(self, *, create: bool) -> dict[str, int]:
        return {"generation": 3}

    def _begin_policy_integrity_generation(self, state: dict[str, int]) -> int:
        return state["generation"] + 1


def test_the_helper_names_the_vault_only_for_a_plain_vault(tmp_path: Path) -> None:
    assert integrity_key_fields(EncryptedFileSecretStore(tmp_path), _KEY, "key-1") == {"vault_key": True}
    fields = integrity_key_fields(object(), _KEY, "key-1")
    assert fields["integrity_key_id"] == "key-1"
    assert isinstance(fields["integrity_key_b64"], str)
    assert "vault_key" not in fields


class _PlainVaultSubclass(EncryptedFileSecretStore):
    pass


def test_a_vault_subclass_still_sends_its_key(tmp_path: Path) -> None:
    # Only the exact plain vault is one the resident reads from its own home.
    assert "vault_key" not in integrity_key_fields(_PlainVaultSubclass(tmp_path), _KEY, "key-1")


def _record(owner: _Owner) -> str | None:
    record = vars(StoreEventReceiptsMixin)["record_local_once_approval"]
    return record(
        owner,
        request_id="req-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_hash="hash-1",
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T00:05:00Z",
    )


@pytest.mark.parametrize("plain", [True, False])
def test_a_local_once_approval_names_the_vault_key(tmp_path: Path, plain: bool) -> None:
    owner = _Owner(EncryptedFileSecretStore(tmp_path) if plain else object())
    assert _record(owner) == "approval-1"
    method, args = owner.calls[-1]
    assert method == "record_local_once_approval"
    if plain:
        assert args["vault_key"] is True
        assert "integrity_key_b64" not in args
        assert "integrity_key_id" not in args
    else:
        assert "vault_key" not in args
        assert args["integrity_key_id"] == "key-1"


def test_a_local_once_approval_without_a_key_mints_nothing(tmp_path: Path) -> None:
    owner = _Owner(EncryptedFileSecretStore(tmp_path), key=None)
    assert _record(owner) is None
    assert owner.calls == []


def _import_args(owner: _Owner, *, vault_key: bool) -> dict[str, object]:
    build = vars(StorePolicyDocumentMixin)["policy_import_args"]
    document = SimpleNamespace(api_version="guard.policy/v1", metadata=SimpleNamespace(id="doc-1"))
    return build(owner, document, [], mode="replace", now="2026-01-01T00:00:00Z", digest="d", vault_key=vault_key)


def test_a_direct_policy_import_names_the_vault_key(tmp_path: Path) -> None:
    args = _import_args(_Owner(EncryptedFileSecretStore(tmp_path)), vault_key=True)
    assert args["vault_key"] is True
    assert args["current_generation"] == 4
    assert "integrity_key_b64" not in args


def test_a_nested_policy_import_still_carries_the_key(tmp_path: Path) -> None:
    # Arguments embedded in another store call are not resolved by the resident.
    args = _import_args(_Owner(EncryptedFileSecretStore(tmp_path)), vault_key=False)
    assert "vault_key" not in args
    assert args["integrity_key_id"] == "key-1"


def test_a_keyring_policy_import_sends_its_key(tmp_path: Path) -> None:
    args = _import_args(_Owner(object()), vault_key=True)
    assert "vault_key" not in args
    assert args["integrity_key_id"] == "key-1"
