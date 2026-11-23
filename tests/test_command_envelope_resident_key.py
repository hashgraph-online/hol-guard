"""The command envelope asks the resident for its own key when the store is the plain vault."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.runtime import command_capability_keys as command_capability
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


class _Store:
    def __init__(self, guard_home: Path, secret_store: object) -> None:
        self.guard_home = guard_home
        self._policy_integrity_secret_store = secret_store
        self.material_calls: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        self.material_calls.append(create)
        return b"k" * 32, "guard-policy-integrity-key:abc"


def _sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def _envelope(**kwargs: object) -> dict[str, object]:
        sent.append(kwargs)
        return {"accepted": True, "result": {"payload": {}, "keyId": "k", "signature": "s"}}

    monkeypatch.setattr(command_capability, "native_command_envelope", _envelope)
    return sent


def test_a_vault_store_sends_no_key_and_asks_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(monkeypatch)
    store = _Store(tmp_path, EncryptedFileSecretStore(tmp_path))

    command_capability._envelope(cast(Any, store), "sign", {"version": 1})

    assert sent[0]["resident_key"] is True
    assert sent[0]["integrity_key_b64"] is None
    assert sent[0]["integrity_key_id"] is None
    assert store.material_calls == []


def test_issuing_on_a_vault_store_mints_the_key_without_sending_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _sent(monkeypatch)
    store = _Store(tmp_path, EncryptedFileSecretStore(tmp_path))

    command_capability._envelope(cast(Any, store), "sign", {"version": 1}, create_key=True)

    assert store.material_calls == [True]
    assert sent[0]["resident_key"] is True
    assert sent[0]["integrity_key_b64"] is None


def test_a_keyring_store_still_sends_its_own_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(monkeypatch)
    store = _Store(tmp_path, object())

    command_capability._envelope(cast(Any, store), "verify", {"payload": {}})

    assert sent[0]["resident_key"] is False
    assert isinstance(sent[0]["integrity_key_b64"], str)
    assert sent[0]["integrity_key_id"] == "guard-policy-integrity-key:abc"


def test_a_digest_never_reads_or_sends_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(monkeypatch)
    store = _Store(tmp_path, EncryptedFileSecretStore(tmp_path))
    monkeypatch.setattr(
        command_capability,
        "native_command_envelope",
        lambda **kwargs: sent.append(kwargs) or {"accepted": True, "result": "digest"},
    )

    assert command_capability._envelope(cast(Any, store), "digest", {"id": "job-1"}) == "digest"
    assert sent[0]["resident_key"] is False
    assert sent[0]["integrity_key_b64"] is None
    assert store.material_calls == []
