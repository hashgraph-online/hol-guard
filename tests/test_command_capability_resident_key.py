"""The capability verdict asks the resident for its own key when the store is the plain vault."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_command_capability as transport
from codex_plugin_scanner.guard.runtime import command_capability
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from tests.test_native_command_capability import _call, _capture, _declared

_CONTRACT = Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/command_capability.rs"


class _Store:
    def __init__(self, guard_home: Path, secret_store: object) -> None:
        self.guard_home = guard_home
        self._policy_integrity_secret_store = secret_store
        self.material_calls: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        self.material_calls.append(create)
        return b"k" * 32, "guard-policy-integrity-key:abc"

    def get_sync_payload(self, _key: str) -> object:
        return {"signature": "abc"}


def _verdict_kwargs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret_store: object) -> dict[str, Any]:
    sent: dict[str, Any] = {}

    def _capability(**kwargs: object) -> dict[str, object]:
        sent.update(kwargs)
        return {"capability_valid": True}

    monkeypatch.setattr(command_capability, "native_command_capability", _capability)
    monkeypatch.setattr(command_capability, "_binding_for_resident", lambda _store: ("device-1", "workspace-1", None))
    store = _Store(tmp_path, secret_store)
    command_capability._capability_verdict(cast(Any, store))
    sent["material_calls"] = store.material_calls
    return sent


def test_the_resident_key_feature_mirrors_the_contract() -> None:
    source = _CONTRACT.read_text(encoding="utf-8")
    declared = _declared(source, "COMMAND_CAPABILITY_RESIDENT_KEY_FEATURE")
    assert declared == transport.COMMAND_CAPABILITY_RESIDENT_KEY_FEATURE


def test_a_vault_store_sends_no_key_and_asks_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _verdict_kwargs(tmp_path, monkeypatch, EncryptedFileSecretStore(tmp_path))

    assert sent["resident_key"] is True
    assert sent["integrity_key_b64"] is None
    assert sent["integrity_key_id"] is None
    assert sent["material_calls"] == []


def test_a_keyring_store_still_sends_its_own_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _verdict_kwargs(tmp_path, monkeypatch, object())

    assert sent["resident_key"] is False
    assert isinstance(sent["integrity_key_b64"], str)
    assert sent["integrity_key_id"] == "guard-policy-integrity-key:abc"


def test_the_resident_key_request_carries_no_key_and_names_its_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"capability_valid": True})

    _ = _call(resident_key=True)

    assert seen["feature"] == transport.COMMAND_CAPABILITY_RESIDENT_KEY_FEATURE
    assert seen["wire"]["resident_key"] is True
    assert seen["wire"]["integrity_key_b64"] is None
    assert seen["wire"]["integrity_key_id"] is None
    assert seen["bound"]["resident_key"] is True


def test_a_plain_request_omits_the_resident_key_field(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch, {"capability_valid": True})

    _ = _call()

    assert "resident_key" not in seen["wire"]
    assert seen["feature"] == transport.COMMAND_CAPABILITY_FEATURE
