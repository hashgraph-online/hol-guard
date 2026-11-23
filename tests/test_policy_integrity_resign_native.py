"""Integrity setup re-signs rows through the resident's ``resign_policy_rows``."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from codex_plugin_scanner.guard.store_policy_integrity_runtime import StorePolicyIntegrityAdminMixin


class _Store(StorePolicyIntegrityAdminMixin):
    def __init__(self, secret_store: object, *, mode: str = "protected", reply: object = None) -> None:
        self.guard_home = Path("/nonexistent-guard-home")
        self._policy_integrity_secret_store = secret_store
        self.mode = mode
        self.reply = reply if reply is not None else {"cleared": 0, "next_control_state": {"generation": 3}}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.finalized: list[object] = []

    def hold_policy_integrity_generation_lock(self) -> nullcontext[None]:
        return nullcontext()

    def _connect(self) -> nullcontext[SimpleNamespace]:
        return nullcontext(SimpleNamespace(rollback=lambda: None))

    def _refresh_policy_integrity_state(self, connection: object, **_: object) -> dict[str, object]:
        return {"mode": self.mode, "generation": 2}

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes, str]:
        return b"\x05" * 32, "key-1"

    def _load_policy_integrity_control_state(self, *, create: bool) -> dict[str, object]:
        return {"generation": 2}

    def _policy_integrity_results_for_rows(self, rows: list[dict[str, int]], **_: object) -> list[SimpleNamespace]:
        statuses = {9: "missing_integrity", 4: "valid", 7: "tampered"}
        return [SimpleNamespace(status=statuses[row["decision_id"]]) for row in rows]

    def _begin_policy_integrity_generation(self, state: dict[str, object]) -> int:
        return 2

    def _native_store_call(self, method: str, args: dict[str, Any]) -> object:
        self.calls.append((method, args))
        return self.reply

    def _finalize_policy_integrity_control_state(self, state: object) -> bool:
        self.finalized.append(state)
        return True

    def get_policy_integrity_status(self, harness: str | None = None) -> dict[str, object]:
        return {"status": "ok"}


def _rows(*, harness: str | None = None) -> list[dict[str, int]]:
    return [{"decision_id": 9}, {"decision_id": 4}, {"decision_id": 7}]


@pytest.fixture(autouse=True)
def _patched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_Store, "_load_local_policy_rows", staticmethod(_rows))


def test_setup_resigns_the_legacy_rows_in_the_resident_with_the_vault_key(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path))
    assert store.setup_policy_integrity(now="2026-01-01T00:00:00Z", include_items=False) == {"status": "ok"}
    [(method, args)] = store.calls
    assert method == "resign_policy_rows"
    assert args["force_sign_decision_ids"] == [9]
    assert args["clear_decision_ids"] == []
    assert args["current_generation"] == 2
    assert args["vault_key"] is True
    assert "integrity_key_b64" not in args
    assert store.finalized == [{"generation": 3}]


def test_setup_in_degraded_mode_writes_nothing(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path), mode="degraded")
    _ = store.setup_policy_integrity(now="2026-01-01T00:00:00Z", include_items=False)
    assert store.calls == []


def test_a_reply_without_a_control_state_is_refused(tmp_path: Path) -> None:
    store = _Store(EncryptedFileSecretStore(tmp_path), reply={"cleared": 0, "next_control_state": None})
    with pytest.raises(RuntimeError, match="control state is invalid"):
        _ = store.setup_policy_integrity(now="2026-01-01T00:00:00Z", include_items=False)
    assert store.finalized == []
