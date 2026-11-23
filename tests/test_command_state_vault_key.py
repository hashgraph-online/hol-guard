"""The command ledger reads the plain vault's key itself instead of taking it on the wire."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_command_state
from codex_plugin_scanner.guard.runtime import command_capability
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_RUST = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/command_state.rs"


class _Store:
    def __init__(self, guard_home: Path, secret_store: object) -> None:
        self.guard_home = guard_home
        self._policy_integrity_secret_store = secret_store
        self.material_calls: list[bool] = []

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        self.material_calls.append(create)
        return b"k" * 32, "guard-policy-integrity-key:abc"


def _sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret_store: object, *, signing: bool) -> dict[str, Any]:
    sent: dict[str, Any] = {}

    def _state(guard_home: Path, op: str, **kwargs: object) -> object:
        sent.update(kwargs, guard_home=guard_home, op=op)
        return {"approved": True}

    monkeypatch.setattr(command_capability, "native_command_state", _state)
    store = _Store(tmp_path, secret_store)
    now = "2026-09-27T12:00:00+00:00"
    command_capability._ledger(cast(Any, store), "approve", now=now, signing=signing, job_id="j")
    sent["material_calls"] = store.material_calls
    return sent


def test_the_python_feature_matches_the_runtime() -> None:
    declared = re.search(r'pub\(crate\) const FEATURE: &str = "([^"]+)";', _RUST.read_text(encoding="utf-8"))
    assert declared is not None
    assert declared.group(1) == native_command_state.COMMAND_STATE_FEATURE


def test_a_vault_store_asks_the_ledger_to_read_its_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(tmp_path, monkeypatch, EncryptedFileSecretStore(tmp_path), signing=True)

    assert sent["vault_key"] is True
    assert "integrity_key_b64" not in sent
    assert "integrity_key_id" not in sent
    assert sent["material_calls"] == []


def test_a_keyring_store_still_sends_its_own_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(tmp_path, monkeypatch, object(), signing=True)

    assert "vault_key" not in sent
    assert isinstance(sent["integrity_key_b64"], str)
    assert sent["integrity_key_id"] == "guard-policy-integrity-key:abc"
    assert sent["material_calls"] == [False]


def test_an_unsigned_op_names_no_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _sent(tmp_path, monkeypatch, EncryptedFileSecretStore(tmp_path), signing=False)

    assert not {"vault_key", "integrity_key_b64", "integrity_key_id"} & set(sent)
