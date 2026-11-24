"""`repair_policy_integrity --clear-invalid` deletes through the resident's clear."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_policy_integrity_runtime as runtime_module
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from codex_plugin_scanner.guard.store_policy_integrity_runtime import StorePolicyIntegrityAdminMixin


class _Store(StorePolicyIntegrityAdminMixin):
    def __init__(self, secret_store: object, *, mode: str = "protected", local_match: bool = True) -> None:
        self.guard_home = Path("/nonexistent-guard-home")
        self._policy_integrity_secret_store = secret_store
        self.mode = mode
        self._local_match = local_match
        self.calls: list[dict[str, Any]] = []
        self.finalized: list[object] = []

    def hold_policy_integrity_generation_lock(self) -> nullcontext[None]:
        return nullcontext()

    def _connect(self) -> nullcontext[object]:
        return nullcontext(object())

    def _refresh_policy_integrity_state(self, connection: object, **_: object) -> dict[str, object]:
        return {"mode": self.mode, "generation": 2}

    def _load_policy_integrity_state(self) -> dict[str, object]:
        return {"mode": self.mode, "generation": 2}

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes, str]:
        return b"\x05" * 32, "key-1"

    def _policy_integrity_results_for_rows(self, rows: list[dict[str, int]], **_: object) -> list[SimpleNamespace]:
        return [SimpleNamespace(status="tampered" if row["decision_id"] != 7 else "valid") for row in rows]

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        assert method == "clear_policy_decisions"
        self.calls.append(args)
        if args.get("unsigned_only") and self._local_match:
            return {"needs_signing": True}
        signed = "current_generation" in args
        return {"cleared": 2, "next_control_state": {"generation": 3} if signed else None}

    def _load_policy_integrity_control_state(self, *, create: bool) -> dict[str, int]:
        return {"generation": 2}

    def _begin_policy_integrity_generation(self, state: dict[str, int]) -> int:
        return state["generation"]

    def _finalize_policy_integrity_control_state(self, state: object) -> bool:
        self.finalized.append(state)
        return True


def _rows(connection: object, *, harness: str | None = None) -> list[dict[str, int]]:
    return [{"decision_id": 9}, {"decision_id": 4}, {"decision_id": 7}]


def _scan(store: _Store, connection: object, **_: object) -> tuple[dict[str, object], dict[str, int], list[object]]:
    return {"mode": store.mode}, {"valid": 1}, []


def _summary(**_: object) -> dict[str, object]:
    return {}


def _no_gate(*_: object, **__: object) -> None:
    return None


@pytest.fixture(autouse=True)
def _patched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_module, "require_policy_clear", _no_gate)
    monkeypatch.setattr(_Store, "_load_local_policy_rows", staticmethod(_rows))
    monkeypatch.setattr(_Store, "_policy_integrity_scan", _scan)
    monkeypatch.setattr(_Store, "_policy_integrity_summary_payload", staticmethod(_summary))


def test_a_protected_repair_clears_through_the_resident_with_the_vault_key(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path))
    payload = store.repair_policy_integrity(clear_invalid=True, now="2026-01-01T00:00:00Z", include_items=False)
    assert payload["cleared"] == 2
    first, second = store.calls
    assert first["decision_ids"] == [4, 9]
    assert first["unsigned_only"] is True
    assert second["decision_ids"] == [4, 9]
    assert second["current_generation"] == 2
    assert second["vault_key"] is True
    assert "integrity_key_b64" not in second
    assert store.finalized == [{"generation": 3}]


def test_a_keyring_repair_sends_its_key() -> None:
    store = _Store(object())
    _ = store.repair_policy_integrity(clear_invalid=True, now="2026-01-01T00:00:00Z", include_items=False)
    assert store.calls[1]["integrity_key_id"] == "key-1"
    assert "vault_key" not in store.calls[1]


def test_a_degraded_repair_clears_without_signing(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path), mode="degraded")
    payload = store.repair_policy_integrity(clear_invalid=True, now="2026-01-01T00:00:00Z", include_items=False)
    assert payload["cleared"] == 2
    assert "current_generation" not in store.calls[1]
    assert "vault_key" not in store.calls[1]
    assert store.finalized == []


def test_a_repair_that_does_not_clear_calls_nothing(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path))
    payload = store.repair_policy_integrity(clear_invalid=False, now="2026-01-01T00:00:00Z", include_items=False)
    assert payload["cleared"] == 0
    assert store.calls == []
