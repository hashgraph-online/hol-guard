"""Exact Cloud Review lets the runtime read the plain vault's key instead of sending it."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.runtime import exact_cloud_review
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


class _Store:
    def __init__(self, guard_home: Path, secret_store: object) -> None:
        self.guard_home = guard_home
        self._policy_integrity_secret_store = secret_store
        self.material_calls: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        self.material_calls.append(create)
        return b"k" * 32, "guard-policy-integrity-key:abc"


def _sign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret_store: object, *, create: bool) -> dict[str, Any]:
    sent: dict[str, Any] = {}

    def _answer(request: dict[str, object], store: object = None) -> dict[str, object]:
        del store
        sent.update(request)
        return {"envelope": {"keyId": "k", "signature": "s"}}

    monkeypatch.setattr(exact_cloud_review, "_answer", _answer)
    store = _Store(tmp_path, secret_store)
    exact_cloud_review._sign(cast(Any, store), {"issuer": "local-cli"}, create_key=create)
    sent["material_calls"] = store.material_calls
    return sent


def test_a_vault_store_names_its_home_and_sends_no_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sign(tmp_path, monkeypatch, EncryptedFileSecretStore(tmp_path), create=False)

    assert sent["vault_home"] == str(tmp_path.resolve())
    assert "key" not in sent
    assert "key_id" not in sent
    assert sent["material_calls"] == []


def test_a_vault_store_still_mints_the_key_when_issuing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sign(tmp_path, monkeypatch, EncryptedFileSecretStore(tmp_path), create=True)

    assert sent["vault_home"] == str(tmp_path.resolve())
    assert "key" not in sent
    assert sent["material_calls"] == [True]


def test_a_keyring_store_still_sends_its_own_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sign(tmp_path, monkeypatch, object(), create=False)

    assert "vault_home" not in sent
    assert sent["key_id"] == "guard-policy-integrity-key:abc"
    assert isinstance(sent["key"], str)


def test_an_unsigned_row_sends_no_key_at_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(tmp_path, EncryptedFileSecretStore(tmp_path))
    assert exact_cloud_review._signing_key(cast(Any, store), None) == {"key": None, "key_id": None}
    assert store.material_calls == []
