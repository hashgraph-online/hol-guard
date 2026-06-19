"""Regression tests for local Guard policy integrity enforcement."""

from __future__ import annotations

import base64
import json
import pickle
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.cli import _resolve_legacy_args, main
from codex_plugin_scanner.guard import local_trust_contract as local_trust_contract_module
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.local_trust_contract import (
    LOCAL_TRUST_DEGRADED_REASON_LABELS,
    LOCAL_TRUST_MODES,
    POLICY_INTEGRITY_DEGRADED_REASONS,
    POLICY_INTEGRITY_ENFORCEMENT_ENFORCE,
    POLICY_INTEGRITY_ENFORCEMENT_WARN,
    POLICY_INTEGRITY_MODE_DEGRADED,
    POLICY_INTEGRITY_MODE_PROTECTED,
    POLICY_INTEGRITY_REASON_BACKEND_CORRUPT,
    POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED,
    POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,
    POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE,
    TrustBackendCorruptResultError,
    TrustBackendProcessFailedError,
    TrustBackendUnavailableError,
    TrustStatus,
    degraded_reason_for_backend_error,
    run_trust_backend_check,
    select_trust_backend,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_authority import PolicyAuthorityError
from codex_plugin_scanner.guard.store import GuardStore, SystemKeyringSecretStore


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


@pytest.fixture(autouse=True)
def _default_store_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


@dataclass
class _FakeTrustBackend:
    name: str
    priority: int
    supported: bool = True
    passive_no_ui_safe: bool = True

    def status(self) -> TrustStatus:
        return TrustStatus(
            runtime_protection="protected",
            remembered_rules="enforced",
            cloud_policies="available",
            backend=self.name,
        )

    def sign(self, payload: bytes) -> str:
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        return self.sign(payload) == signature

    def setup(self) -> TrustStatus:
        return self.status()

    def revoke(self) -> TrustStatus:
        return TrustStatus(
            runtime_protection="degraded",
            remembered_rules="disabled_degraded",
            cloud_policies="setup_unavailable",
            backend=self.name,
            setup_available=True,
        )


def _write_nested_trust_marker(marker_path: str) -> None:
    Path(marker_path).write_text("ok", encoding="utf-8")


def _write_delayed_nested_trust_marker(marker_path: str) -> None:
    time.sleep(0.4)
    Path(marker_path).write_text("late", encoding="utf-8")


def _write_corrupt_trust_result(operation, result_path: str) -> None:
    Path(result_path).write_bytes(b"not a pickle")


def _write_malformed_trust_result(operation, result_path: str) -> None:
    Path(result_path).write_bytes(pickle.dumps({"ok": True}))


def _write_list_trust_result(operation, result_path: str) -> None:
    Path(result_path).write_bytes(pickle.dumps([True, {"mode": "protected"}]))


def _skip_trust_result(operation, result_path: str) -> None:
    operation()


def test_local_trust_contract_exports_stable_status_vocabulary() -> None:
    assert LOCAL_TRUST_MODES == (
        "protected",
        "cloud_authoritative",
        "degraded_safe",
        "setup_required",
        "unsupported",
    )
    assert POLICY_INTEGRITY_MODE_PROTECTED == "protected"
    assert POLICY_INTEGRITY_MODE_DEGRADED == "degraded"
    assert POLICY_INTEGRITY_ENFORCEMENT_ENFORCE == "enforce"
    assert POLICY_INTEGRITY_ENFORCEMENT_WARN == "warn"
    assert "system_keyring_unavailable" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "policy_integrity_key_unavailable" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "policy_integrity_control_unavailable" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "guard_home_symlink" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "guard_db_symlink" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "guard_home_permissions" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert "guard_db_permissions" in POLICY_INTEGRITY_DEGRADED_REASONS
    assert set(LOCAL_TRUST_DEGRADED_REASON_LABELS) == set(POLICY_INTEGRITY_DEGRADED_REASONS)


def test_trust_backend_registry_requires_no_ui_safe_passive_backend() -> None:
    unsafe_high_priority = _FakeTrustBackend(
        name="unsafe-high",
        priority=100,
        passive_no_ui_safe=False,
    )
    safe_low_priority = _FakeTrustBackend(name="safe-low", priority=10)
    unsupported = _FakeTrustBackend(name="unsupported", priority=200, supported=False)

    passive_backend = select_trust_backend(
        (unsupported, unsafe_high_priority, safe_low_priority),
        passive=True,
    )
    explicit_backend = select_trust_backend(
        (unsupported, unsafe_high_priority, safe_low_priority),
        passive=False,
    )

    assert passive_backend is safe_low_priority
    assert explicit_backend is unsafe_high_priority


def test_trust_backend_timeout_returns_degraded_result_without_waiting() -> None:
    timeout_result = TrustStatus(
        runtime_protection="degraded",
        remembered_rules="disabled_degraded",
        cloud_policies="setup_unavailable",
        backend="timeout",
        degraded_reasons=(POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,),
        setup_available=True,
    )

    started = time.monotonic()
    result = run_trust_backend_check(
        lambda: (time.sleep(1.0), _FakeTrustBackend("slow", 1).status())[1],
        timeout_seconds=0.01,
        timeout_result=timeout_result,
        on_error=lambda error: TrustStatus(
            runtime_protection="degraded",
            remembered_rules="disabled_degraded",
            cloud_policies="setup_unavailable",
            backend="error",
            degraded_reasons=(degraded_reason_for_backend_error(error),),
        ),
    )

    assert result == timeout_result
    assert time.monotonic() - started < 0.5


def test_trust_backend_timeout_contains_late_side_effects(tmp_path: Path) -> None:
    marker_path = tmp_path / "late-side-effect"

    def slow_mutation() -> TrustStatus:
        time.sleep(0.5)
        marker_path.write_text("mutated", encoding="utf-8")
        return _FakeTrustBackend("slow", 1).status()

    timeout_result = TrustStatus(
        runtime_protection="degraded",
        remembered_rules="disabled_degraded",
        cloud_policies="setup_unavailable",
        backend="timeout",
        degraded_reasons=(POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,),
    )

    result = run_trust_backend_check(
        slow_mutation,
        timeout_seconds=0.01,
        timeout_result=timeout_result,
    )
    time.sleep(0.1)

    assert result == timeout_result
    assert not marker_path.exists()


def test_trust_backend_timeout_kills_nested_helper_process(tmp_path: Path) -> None:
    marker_path = tmp_path / "nested-late-side-effect"

    def slow_nested_mutation() -> TrustStatus:
        context = local_trust_contract_module.multiprocessing.get_context("fork")
        process = context.Process(target=_write_delayed_nested_trust_marker, args=(str(marker_path),))
        process.start()
        time.sleep(2.0)
        return _FakeTrustBackend("slow", 1).status()

    timeout_result = TrustStatus(
        runtime_protection="degraded",
        remembered_rules="disabled_degraded",
        cloud_policies="setup_unavailable",
        backend="timeout",
        degraded_reasons=(POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,),
    )

    result = run_trust_backend_check(
        slow_nested_mutation,
        timeout_seconds=0.05,
        timeout_result=timeout_result,
    )
    time.sleep(0.6)

    assert result == timeout_result
    assert not marker_path.exists()


def test_trust_backend_timeout_falls_back_when_process_group_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeProcess:
        pid = 12345

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: float | None = None) -> None:
            calls.append(f"join:{timeout}")

        def terminate(self) -> None:
            calls.append("terminate")

        def kill(self) -> None:
            calls.append("kill")

    def fake_killpg(pid: int, sig: int) -> None:
        calls.append(f"killpg:{pid}:{sig}")
        raise ProcessLookupError("process group not ready")

    monkeypatch.setattr(local_trust_contract_module.os, "killpg", fake_killpg)

    local_trust_contract_module._terminate_trust_backend_process_tree(FakeProcess())

    assert calls == ["killpg:12345:15", "terminate", "join:0.2"]


def test_trust_backend_check_handles_corrupt_result_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_trust_contract_module, "_trust_backend_check_worker", _write_corrupt_trust_result)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {
            "mode": "degraded",
            "error": error.__class__.__name__,
            "reason": degraded_reason_for_backend_error(error),
        },
    )

    assert result == {
        "mode": "degraded",
        "error": "TrustBackendCorruptResultError",
        "reason": POLICY_INTEGRITY_REASON_BACKEND_CORRUPT,
    }


def test_trust_backend_check_rejects_malformed_result_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_trust_contract_module, "_trust_backend_check_worker", _write_malformed_trust_result)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {
            "mode": "degraded",
            "error": error.__class__.__name__,
            "reason": degraded_reason_for_backend_error(error),
        },
    )

    assert result == {
        "mode": "degraded",
        "error": "TrustBackendCorruptResultError",
        "reason": POLICY_INTEGRITY_REASON_BACKEND_CORRUPT,
    }


def test_trust_backend_check_rejects_list_result_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_trust_contract_module, "_trust_backend_check_worker", _write_list_trust_result)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {
            "mode": "degraded",
            "error": error.__class__.__name__,
            "reason": degraded_reason_for_backend_error(error),
        },
    )

    assert result == {
        "mode": "degraded",
        "error": "TrustBackendCorruptResultError",
        "reason": POLICY_INTEGRITY_REASON_BACKEND_CORRUPT,
    }


def test_trust_backend_result_loader_preserves_permission_denied() -> None:
    class PermissionDeniedResultPath:
        def open(self, mode: str = "rb"):
            raise PermissionError("denied")

    with pytest.raises(PermissionError):
        local_trust_contract_module._load_trust_backend_result(cast(Path, PermissionDeniedResultPath()))


def test_trust_backend_check_handles_result_permission_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied_loader(result_file: Path):
        raise PermissionError("denied")

    monkeypatch.setattr(local_trust_contract_module, "_load_trust_backend_result", denied_loader)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {
            "mode": "degraded",
            "error": error.__class__.__name__,
            "reason": degraded_reason_for_backend_error(error),
        },
    )

    assert result == {
        "mode": "degraded",
        "error": "PermissionError",
        "reason": POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED,
    }


def test_trust_backend_check_reports_missing_result_with_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_trust_contract_module, "_trust_backend_check_worker", _skip_trust_result)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {"mode": "degraded", "error": str(error)},
    )

    assert result == {"mode": "degraded", "error": "trust_backend_process_failed:0"}


def test_trust_backend_timeout_helper_allows_minimal_fallback_contract() -> None:
    timeout_result = {"mode": "degraded"}

    result = run_trust_backend_check(
        lambda: (time.sleep(1.0), {"mode": "protected"})[1],
        timeout_seconds=0.01,
        timeout_result=timeout_result,
    )

    assert result == timeout_result


def test_trust_backend_check_drains_large_completed_result_before_timeout() -> None:
    timeout_result = {"mode": "degraded"}
    large_status = {"mode": "protected", "payload": "x" * 1_000_000}

    result = run_trust_backend_check(
        lambda: large_status,
        timeout_seconds=1.0,
        timeout_result=timeout_result,
    )

    assert result == large_status


def test_trust_backend_check_allows_native_helper_child_process(tmp_path: Path) -> None:
    marker_path = tmp_path / "nested-helper"

    def operation() -> dict[str, str]:
        context = local_trust_contract_module.multiprocessing.get_context("fork")
        process = context.Process(target=_write_nested_trust_marker, args=(str(marker_path),))
        process.start()
        process.join(timeout=1.0)
        return {"mode": "protected", "nested": str(marker_path.exists())}

    result = run_trust_backend_check(
        operation,
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded", "nested": "False"},
    )

    assert result == {"mode": "protected", "nested": "True"}


def test_trust_backend_check_degrades_without_spawn_when_fork_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str | None] = []

    def fake_get_context(method: str | None = None):
        calls.append(method)
        if method == "fork":
            raise ValueError("fork unavailable")
        raise AssertionError("spawn fallback must not be used for passive trust checks")

    monkeypatch.setattr(local_trust_contract_module.multiprocessing, "get_context", fake_get_context)

    result = run_trust_backend_check(
        lambda: {"mode": "protected"},
        timeout_seconds=1.0,
        timeout_result={"mode": "degraded"},
        on_error=lambda error: {"mode": "degraded", "reason": degraded_reason_for_backend_error(error)},
    )

    assert result == {"mode": "degraded", "reason": POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE}
    assert calls == ["fork"]


def test_trust_backend_errors_normalize_to_safe_degraded_reasons() -> None:
    assert degraded_reason_for_backend_error(TimeoutError("slow")) == POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT
    assert (
        degraded_reason_for_backend_error(TrustBackendUnavailableError("fork unavailable"))
        == POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE
    )
    assert (
        degraded_reason_for_backend_error(TrustBackendProcessFailedError("worker died"))
        == POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE
    )
    assert (
        degraded_reason_for_backend_error(TrustBackendCorruptResultError("bad result"))
        == POLICY_INTEGRITY_REASON_BACKEND_CORRUPT
    )
    assert (
        degraded_reason_for_backend_error(PermissionError("denied"))
        == POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED
    )
    assert degraded_reason_for_backend_error(ValueError("bad payload")) == POLICY_INTEGRITY_REASON_BACKEND_CORRUPT
    assert degraded_reason_for_backend_error(RuntimeError("broken")) == POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE


def test_trust_status_serializes_policy_integrity_authority_without_paths() -> None:
    status = TrustStatus.from_policy_integrity_state(
        {
            "backend": "unavailable",
            "mode": POLICY_INTEGRITY_MODE_DEGRADED,
            "degraded_reasons": ["system_keyring_unavailable", "guard_home_symlink"],
            "key_id": "/Users/example/.hol-guard/key",
        }
    ).to_dict()

    assert status["runtime_protection"] == "degraded"
    assert status["remembered_rules"] == "disabled_degraded"
    assert status["cloud_policies"] == "setup_unavailable"
    assert status["backend"] == "unavailable"
    assert status["degraded_reasons"] == ["system_keyring_unavailable", "guard_home_symlink"]
    assert status["setup_available"] is True
    assert status["last_proof"] is None


def test_trust_status_hides_policy_integrity_proof_ids_and_handles_unknown_mode() -> None:
    status = TrustStatus.from_policy_integrity_state(
        {
            "backend": "system-keyring",
            "mode": "future-mode",
            "degraded_reasons": [],
            "key_id": "abc/def==",
        }
    ).to_dict()

    assert status["runtime_protection"] == "unknown"
    assert status["remembered_rules"] == "unknown"
    assert status["cloud_policies"] == "available"
    assert status["setup_available"] is False
    assert status["last_proof"] is None

    windows_status = TrustStatus.from_policy_integrity_state(
        {
            "backend": "system-keyring",
            "mode": POLICY_INTEGRITY_MODE_PROTECTED,
            "degraded_reasons": [],
            "key_id": "\\Users\\alice\\.hol-guard\\key",
        }
    ).to_dict()
    assert windows_status["runtime_protection"] == "protected"
    assert windows_status["last_proof"] is None


def test_policy_integrity_status_includes_trust_status(tmp_path: Path) -> None:
    store = _store(tmp_path)

    status = store.get_policy_integrity_status()
    trust_status = status["trust_status"]

    assert isinstance(trust_status, dict)
    assert trust_status["runtime_protection"] == "degraded"
    assert trust_status["remembered_rules"] == "disabled_degraded"
    assert trust_status["cloud_policies"] == "setup_unavailable"
    assert trust_status["degraded_reasons"] == status["degraded_reasons"]

    verify = store.verify_policy_integrity()
    assert verify["trust_status"] == trust_status


def test_guard_store_init_does_not_create_policy_integrity_keyring_material(tmp_path: Path) -> None:
    store = _store(tmp_path)
    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, SystemKeyringSecretStore)

    assert secret_store.get_secret(store._policy_integrity_key_ref) is None
    assert secret_store.get_secret(store._policy_integrity_control_ref) is None


def _decision(
    *,
    artifact_id: str = "codex:project:workspace-skill",
    artifact_hash: str = "hash-123",
    action: str = "allow",
    source: str = "local",
) -> PolicyDecision:
    return PolicyDecision(
        harness="codex",
        scope="artifact",
        action=action,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        reason="reviewed",
        source=source,
    )


def _policy_row(home_dir: Path, *, artifact_id: str) -> sqlite3.Row:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "select * from policy_decisions where artifact_id = ?",
            (artifact_id,),
        ).fetchone()
    assert row is not None
    return row


def _policy_integrity_state_payload(home_dir: Path) -> dict[str, object]:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        row = connection.execute("select payload_json from sync_state where state_key = 'policy_integrity'").fetchone()
    assert row is not None
    return json.loads(str(row[0]))


def _policy_integrity_control_payload(store: GuardStore) -> dict[str, object]:
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    payload_json = secret_store.get_secret(store._policy_integrity_control_ref)
    assert payload_json is not None
    return json.loads(payload_json)


def _delete_policy_integrity_control_state(store: GuardStore) -> None:
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.delete_secret(store._policy_integrity_control_ref)
    store._clear_policy_integrity_cache()


def _delete_policy_integrity_key(store: GuardStore) -> None:
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.delete_secret(store._policy_integrity_key_ref)
    store._clear_policy_integrity_cache()


def _strip_policy_integrity(home_dir: Path, *, artifact_id: str) -> None:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = null,
                integrity_generation = null,
                payload_hash = null,
                payload_mac = null,
                integrity_key_id = null,
                signed_at = null
            where artifact_id = ?
            """,
            (artifact_id,),
        )


def _tamper_policy_integrity_state(
    home_dir: Path,
    *,
    backend: str,
    mode: str,
    enforcement: str,
    key_id: str | None,
    degraded_reasons: list[str] | None = None,
) -> None:
    payload = {
        "backend": backend,
        "degraded_reasons": degraded_reasons or [],
        "enforcement": enforcement,
        "key_id": key_id,
        "mode": mode,
    }
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values ('policy_integrity', ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), "2026-06-14T00:00:00Z"),
        )


def _rotate_policy_integrity_key(store: GuardStore, *, raw_key: bytes) -> None:
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.set_secret(
        store._policy_integrity_key_ref,
        base64.urlsafe_b64encode(raw_key).decode("ascii"),
    )
    store._clear_policy_integrity_cache()


def test_upsert_policy_signs_local_row_and_resolve_honors_it(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(_decision(), "2026-06-14T00:00:00Z")

    row = _policy_row(store.guard_home, artifact_id="codex:project:workspace-skill")
    control = _policy_integrity_control_payload(store)
    resolved = store.resolve_policy_decision(
        "codex",
        "codex:project:workspace-skill",
        "hash-123",
        now="2026-06-14T00:01:00Z",
    )

    assert row["integrity_version"] == 2
    assert row["integrity_generation"] == 1
    assert isinstance(row["payload_hash"], str) and row["payload_hash"]
    assert isinstance(row["payload_mac"], str) and row["payload_mac"]
    assert isinstance(row["integrity_key_id"], str) and row["integrity_key_id"]
    assert control["cutover_complete"] is True
    assert control["generation"] == 1
    assert resolved is not None
    assert resolved["action"] == "allow"
    assert resolved["integrity_status"] == "valid"


def test_direct_sqlite_insert_is_ignored_when_integrity_is_degraded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    status = store.get_policy_integrity_status()
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
              expires_at, updated_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "artifact",
                "codex:project:forged",
                "hash-forged",
                None,
                None,
                "allow",
                "forged",
                None,
                "local",
                None,
                "2026-06-14T00:00:00Z",
            ),
        )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:forged",
        "hash-forged",
        now="2026-06-14T00:02:00Z",  # must be after the baseline upsert at 00:00:00Z
    )
    verify = store.verify_policy_integrity()

    assert status["enforcement"] == "enforce"
    assert resolved is None
    assert verify["enforcement"] == "enforce"
    assert verify["counts"]["missing_integrity"] == 1


def test_sync_state_tamper_cannot_downgrade_enforcement(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    status = store.get_policy_integrity_status()
    _tamper_policy_integrity_state(
        store.guard_home,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="warn",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
              expires_at, updated_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "artifact",
                "codex:project:forged-sync-state",
                "hash-forged-sync-state",
                None,
                None,
                "allow",
                "forged",
                None,
                "local",
                None,
                "2026-06-14T00:01:00Z",
            ),
        )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:forged-sync-state",
        "hash-forged-sync-state",
        now="2026-06-14T00:02:00Z",
    )
    verify = store.verify_policy_integrity()

    assert resolved is None
    assert verify["enforcement"] == "enforce"
    assert verify["counts"]["missing_integrity"] == 1


def test_upsert_policy_uses_single_integrity_key_lookup_per_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    original_lookup = store._policy_integrity_secret_material
    lookup_calls = 0

    def _flaky_lookup(*, create: bool) -> tuple[bytes | None, str | None]:
        nonlocal lookup_calls
        lookup_calls += 1
        if lookup_calls == 1:
            return None, None
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", _flaky_lookup)

    store.upsert_policy(
        _decision(artifact_id="codex:project:transient", artifact_hash="hash-transient"),
        "2026-06-14T00:00:00Z",
    )

    row = _policy_row(store.guard_home, artifact_id="codex:project:transient")
    state = _policy_integrity_state_payload(store.guard_home)

    assert lookup_calls == 1
    assert row["integrity_version"] is None
    assert state["mode"] == "degraded"
    assert state["key_id"] is None


def test_policy_integrity_status_uses_timed_keychain_reads_once_per_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:keychain-cache", artifact_hash="hash-keychain-cache"),
        "2026-06-14T00:00:00Z",
    )
    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, SystemKeyringSecretStore)
    key_value = secret_store.get_secret(store._policy_integrity_key_ref)
    control_value = secret_store.get_secret(store._policy_integrity_control_ref)
    assert isinstance(key_value, str) and key_value
    assert isinstance(control_value, str) and control_value
    assert store.get_policy_integrity_status()["mode"] == "protected"
    timed_reads: list[str] = []

    def _count_timed_reads(secret_id: str, *, timeout_seconds: float) -> str | None:
        assert timeout_seconds > 0
        timed_reads.append(secret_id)
        if secret_id == store._policy_integrity_key_ref:
            return key_value
        if secret_id == store._policy_integrity_control_ref:
            return control_value
        raise AssertionError(f"unexpected policy-integrity secret lookup: {secret_id}")

    monkeypatch.setattr(
        store,
        "_get_secret_from_store",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("plain keyring reads should not run for policy integrity")
        ),
    )
    monkeypatch.setattr(secret_store, "get_secret_with_timeout", _count_timed_reads)
    store._clear_policy_integrity_cache()

    first_status = store.get_policy_integrity_status()
    second_status = store.get_policy_integrity_status()

    assert first_status["mode"] == "protected"
    assert second_status["mode"] == "protected"
    assert timed_reads == [
        store._policy_integrity_control_ref,
        store._policy_integrity_key_ref,
    ]


def test_policy_integrity_status_and_verify_do_not_create_keyring_material_on_fresh_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, SystemKeyringSecretStore)
    _delete_policy_integrity_key(store)
    _delete_policy_integrity_control_state(store)
    assert secret_store.get_secret(store._policy_integrity_key_ref) is None
    assert secret_store.get_secret(store._policy_integrity_control_ref) is None

    status = store.get_policy_integrity_status()
    verify = store.verify_policy_integrity()

    assert status["mode"] == "degraded"
    assert status["enforcement"] == "enforce"
    assert verify["mode"] == "degraded"
    assert verify["enforcement"] == "enforce"
    assert verify["local_rows_scanned"] == 0
    assert secret_store.get_secret(store._policy_integrity_key_ref) is None
    assert secret_store.get_secret(store._policy_integrity_control_ref) is None


def test_policy_integrity_status_skips_passive_macos_keychain_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:passive-skip", artifact_hash="hash-passive-skip"),
        "2026-06-14T00:00:00Z",
    )
    assert store._policy_integrity_secret_store is None
    store._clear_policy_integrity_cache()
    monkeypatch.setattr(sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: (_ for _ in ()).throw(AssertionError("passive macOS keychain probe should not run"))),
    )

    status = store.get_policy_integrity_status()
    verify = store.verify_policy_integrity()

    assert status["mode"] == "degraded"
    assert verify["mode"] == "degraded"
    assert status["degraded_reasons"] == ["system_keyring_unavailable", "policy_integrity_control_unavailable"]
    assert verify["local_rows_scanned"] == 1


def test_policy_integrity_status_skips_item_context_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:status-fast", artifact_hash="hash-status-fast"),
        "2026-06-14T00:00:00Z",
    )
    monkeypatch.setattr(
        store,
        "_policy_decision_dict_from_row",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("integrity-status should not build per-row item payloads")
        ),
    )

    status = store.get_policy_integrity_status()

    assert status["local_rows_scanned"] == 1


def test_tampered_signed_row_is_ignored_and_event_emitted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:tampered", artifact_hash="hash-tampered"),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:tampered"),
        )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:tampered",
        "hash-tampered",
        now="2026-06-14T00:01:00Z",
    )
    events = store.list_events(limit=100, event_name="policy_integrity_violation")
    ignored_events = store.list_events(limit=100, event_name="rule.ignored.local_integrity")

    assert resolved is None
    assert any(event.get("payload", {}).get("artifact_id") == "codex:project:tampered" for event in events)
    assert any(event.get("payload", {}).get("artifact_id") == "codex:project:tampered" for event in ignored_events)


def test_remote_policy_row_is_honored_without_local_mac(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.replace_remote_policies(
        [_decision(artifact_id="codex:project:remote", artifact_hash="hash-remote", source="cloud-sync")],
        "2026-06-14T00:00:00Z",
        remote_write_authorized=True,
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:remote",
        "hash-remote",
        now="2026-06-14T00:01:00Z",
    )
    events = store.list_events(limit=100, event_name="policy.cloud.applied")

    assert resolved == "allow"
    assert any(event.get("payload", {}).get("artifact_id") == "codex:project:remote" for event in events)


def test_remote_policy_integrity_failure_does_not_emit_local_rule_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.policy_integrity import PolicyIntegrityVerificationResult

    store = _store(tmp_path)
    store.replace_remote_policies(
        [_decision(artifact_id="codex:project:remote-tampered", artifact_hash="hash-remote", source="cloud-sync")],
        "2026-06-14T00:00:00Z",
        remote_write_authorized=True,
    )
    original_result = GuardStore._policy_integrity_result_for_row

    def _forced_invalid(
        self: GuardStore,
        row: sqlite3.Row,
        *,
        mode: str,
        key: bytes | None,
        key_id: str | None,
        trusted_generation: int | None = None,
    ) -> PolicyIntegrityVerificationResult:
        if row["artifact_id"] == "codex:project:remote-tampered":
            return PolicyIntegrityVerificationResult(status="invalid_mac", message="remote bundle row was tampered")
        return original_result(
            self,
            row,
            mode=mode,
            key=key,
            key_id=key_id,
            trusted_generation=trusted_generation,
        )

    monkeypatch.setattr(GuardStore, "_policy_integrity_result_for_row", _forced_invalid)

    resolved = store.resolve_policy(
        "codex",
        "codex:project:remote-tampered",
        "hash-remote",
        now="2026-06-14T00:01:00Z",
    )
    integrity_events = store.list_events(limit=100, event_name="policy_integrity_violation")
    ignored_events = store.list_events(limit=100, event_name="rule.ignored.local_integrity")

    assert resolved is None
    assert any(
        event.get("payload", {}).get("artifact_id") == "codex:project:remote-tampered"
        for event in integrity_events
    )
    assert not any(
        event.get("payload", {}).get("artifact_id") == "codex:project:remote-tampered"
        for event in ignored_events
    )


def test_local_policy_write_cannot_impersonate_remote_policy_source(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(PolicyAuthorityError, match="remote_policy_source_requires_validated_sync_path"):
        store.upsert_policy(
            _decision(artifact_id="codex:project:forged-remote", artifact_hash="hash-forged", source="team-policy"),
            "2026-06-14T00:00:00Z",
        )

    with pytest.raises(PolicyAuthorityError, match="remote_policy_source_requires_validated_sync_path"):
        store.replace_remote_policies(
            [_decision(artifact_id="codex:project:forged-replace", artifact_hash="hash-forged", source="team-policy")],
            "2026-06-14T00:01:00Z",
        )

    store.replace_remote_policies(
        [_decision(artifact_id="codex:project:valid-remote", artifact_hash="hash-valid", source="team-policy")],
        "2026-06-14T00:01:00Z",
        remote_write_authorized=True,
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:valid-remote",
        "hash-valid",
        now="2026-06-14T00:02:00Z",
    )

    assert resolved == "allow"


def test_legacy_unsigned_row_stays_ignored_before_and_after_trusted_write(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy")
    _delete_policy_integrity_control_state(store)

    warned_status = store.get_policy_integrity_status()
    warned = store.resolve_policy_decision(
        "codex",
        "codex:project:legacy",
        "hash-legacy",
        now="2026-06-14T00:01:00Z",
    )
    store.upsert_policy(
        _decision(artifact_id="codex:project:fresh", artifact_hash="hash-fresh"),
        "2026-06-14T00:02:00Z",
    )
    enforced_status = store.get_policy_integrity_status()
    enforced = store.resolve_policy(
        "codex",
        "codex:project:legacy",
        "hash-legacy",
        now="2026-06-14T00:03:00Z",
    )

    assert warned_status["enforcement"] == "enforce"
    assert warned is None
    assert enforced_status["enforcement"] == "enforce"
    assert enforced is None


def test_migrate_local_policy_integrity_preserves_selected_rows_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy-one", artifact_hash="hash-one"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy-two", artifact_hash="hash-two"),
        "2026-06-14T00:00:00Z",
    )
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy-one")
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy-two")
    _delete_policy_integrity_control_state(store)

    items = store.verify_policy_integrity()["items"]
    preserve_id = next(
        int(item["decision_id"]) for item in items if item.get("artifact_id") == "codex:project:legacy-one"
    )
    payload = store.migrate_local_policy_integrity(
        preserve_decision_ids={preserve_id},
        clear_unselected=False,
        now="2026-06-14T00:05:00Z",
    )

    first = store.resolve_policy("codex", "codex:project:legacy-one", "hash-one", now="2026-06-14T00:06:00Z")
    second = store.resolve_policy("codex", "codex:project:legacy-two", "hash-two", now="2026-06-14T00:06:00Z")

    assert Path(str(payload["backup_path"])).exists()
    assert payload["enforcement"] == "enforce"
    assert payload["counts"]["valid"] == 1
    assert payload["counts"]["missing_integrity"] == 1
    assert first == "allow"
    assert second is None


def test_migrate_local_policy_integrity_re_signs_unknown_key_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:rotated", artifact_hash="hash-rotated"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"2" * 32)

    verify_payload = store.verify_policy_integrity()
    preserve_id = next(
        int(item["decision_id"])
        for item in verify_payload["items"]
        if item.get("artifact_id") == "codex:project:rotated"
    )
    payload = store.migrate_local_policy_integrity(
        preserve_decision_ids={preserve_id},
        clear_unselected=False,
        now="2026-06-14T00:05:00Z",
    )

    resolved = store.resolve_policy("codex", "codex:project:rotated", "hash-rotated", now="2026-06-14T00:06:00Z")

    assert verify_payload["counts"]["unknown_key"] == 1
    assert payload["unknown_key_row_ids"] == [preserve_id]
    assert payload["counts"]["valid"] == 1
    assert resolved == "allow"


def test_pending_generation_recovers_when_post_commit_control_write_is_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)

    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
        "2026-06-14T00:01:00Z",
    )

    pending_control = _policy_integrity_control_payload(store)
    verify = store.verify_policy_integrity()
    recovered_control = _policy_integrity_control_payload(store)

    assert pending_control["generation"] == 1
    assert pending_control["pending_generation"] == 2
    assert verify["counts"]["valid"] == 2
    assert recovered_control["generation"] == 2
    assert recovered_control["pending_generation"] is None


def test_signed_rollback_snapshot_is_detected_and_repair_advances_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:rollback", artifact_hash="hash-rollback"),
        "2026-06-14T00:00:00Z",
    )
    snapshot = _policy_row(store.guard_home, artifact_id="codex:project:rollback")
    assert snapshot["integrity_generation"] == 1

    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )

    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                snapshot["integrity_version"],
                snapshot["integrity_generation"],
                snapshot["payload_hash"],
                snapshot["payload_mac"],
                snapshot["integrity_key_id"],
                snapshot["signed_at"],
                "codex:project:rollback",
            ),
        )

    verify = store.verify_policy_integrity()
    rollback_item = next(item for item in verify["items"] if item.get("artifact_id") == "codex:project:rollback")
    repair = store.repair_policy_integrity(clear_invalid=True, now="2026-06-14T00:02:00Z")
    control = _policy_integrity_control_payload(store)
    resolved = store.resolve_policy("codex", "codex:project:current", "hash-current", now="2026-06-14T00:03:00Z")

    assert verify["counts"]["rollback_detected"] == 1
    assert rollback_item["integrity_status"] == "rollback_detected"
    assert rollback_item["integrity_message"] == "policy_integrity_generation_rollback"
    assert repair["cleared"] == 1
    assert repair["counts"]["valid"] == 1
    assert repair["counts"]["rollback_detected"] == 0
    assert control["generation"] == 3
    assert resolved == "allow"


def test_migrate_local_policy_integrity_reports_rollback_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(store, "_backup_policy_database", lambda connection, *, now: "guard.db.pre-integrity-test")
    store.upsert_policy(
        _decision(artifact_id="codex:project:rollback-migrate", artifact_hash="hash-rollback-migrate"),
        "2026-06-14T00:00:00Z",
    )
    snapshot = _policy_row(store.guard_home, artifact_id="codex:project:rollback-migrate")
    rollback_id = int(snapshot["decision_id"])
    store.upsert_policy(
        _decision(artifact_id="codex:project:rollback-peer", artifact_hash="hash-rollback-peer"),
        "2026-06-14T00:01:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where decision_id = ?
            """,
            (
                snapshot["integrity_version"],
                snapshot["integrity_generation"],
                snapshot["payload_hash"],
                snapshot["payload_mac"],
                snapshot["integrity_key_id"],
                snapshot["signed_at"],
                rollback_id,
            ),
        )

    payload = store.migrate_local_policy_integrity(
        preserve_decision_ids={rollback_id},
        clear_unselected=False,
        now="2026-06-14T00:02:00Z",
    )

    assert payload["rollback_row_ids"] == [rollback_id]
    assert payload["blocked_preserve_row_ids"] == [rollback_id]
    assert payload["counts"]["rollback_detected"] == 1


def test_policies_cli_verify_status_migrate_and_repair(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(_decision(artifact_id="codex:project:cli", artifact_hash="hash-cli"), "2026-06-14T00:00:00Z")
    _strip_policy_integrity(home_dir, artifact_id="codex:project:cli")
    _delete_policy_integrity_control_state(store)
    monkeypatch.setattr(
        GuardStore,
        "_backup_policy_database",
        lambda self, connection, *, now: str(home_dir / "guard.db.pre-integrity-test"),
    )

    verify_rc = main(["guard", "policies", "verify", "--home", str(home_dir), "--json"])
    verify_payload = json.loads(capsys.readouterr().out)
    assert verify_rc == 1
    assert verify_payload["mode"] == "degraded"
    assert verify_payload["counts"]["degraded_mode"] == 1

    status_rc = main(["guard", "policies", "integrity-status", "--home", str(home_dir), "--json"])
    status_payload = json.loads(capsys.readouterr().out)
    assert status_rc == 0
    assert status_payload["enforcement"] == "enforce"

    human_status_rc = main(["guard", "policies", "integrity-status", "--home", str(home_dir)])
    human_status_output = capsys.readouterr().out
    assert human_status_rc == 0
    assert "Runtime protection" in human_status_output
    assert "Remembered rules" in human_status_output
    assert "Cloud policies" in human_status_output

    migrate_rc = main(
        [
            "guard",
            "policies",
            "migrate-local-integrity",
            "--home",
            str(home_dir),
            "--preserve-all-local",
            "--json",
        ]
    )
    migrate_payload = json.loads(capsys.readouterr().out)
    assert migrate_rc == 0
    assert migrate_payload["preserved"] == 0
    assert migrate_payload["counts"]["missing_integrity"] == 1
    assert migrate_payload["enforcement"] == "enforce"

    _strip_policy_integrity(home_dir, artifact_id="codex:project:cli")
    repair_rc = main(
        [
            "guard",
            "policies",
            "repair",
            "--home",
            str(home_dir),
            "--clear-invalid",
            "--json",
        ]
    )
    repair_payload = json.loads(capsys.readouterr().out)
    assert repair_rc == 0
    assert repair_payload["cleared"] == 1
    assert GuardStore(home_dir).list_policy_decisions() == []


def test_policies_integrity_status_human_output_hides_real_key_id(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(
        _decision(artifact_id="codex:project:key-visible", artifact_hash="hash-key"),
        "2026-06-18T00:00:00Z",
    )

    status_rc = main(["guard", "policies", "integrity-status", "--home", str(home_dir), "--json"])
    status_payload = json.loads(capsys.readouterr().out)
    key_id = status_payload.get("key_id")
    assert status_rc == 0
    assert isinstance(key_id, str)
    assert key_id

    human_rc = main(["guard", "policies", "integrity-status", "--home", str(home_dir)])
    human_output = capsys.readouterr().out
    assert human_rc == 0
    assert "Integrity key" in human_output
    assert "present" in human_output
    assert key_id not in human_output


def test_trust_cli_status_reports_no_passive_prompts(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(["guard", "trust", "status", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["command"] == "status"
    assert payload["no_ui_passive"] is True
    assert payload["passive_prompt_allowed"] is False
    assert payload["runtime_protection"] in {"protected", "degraded", "unknown"}
    assert payload["remembered_rules"] in {"enforced", "disabled_degraded", "unknown"}
    assert payload["one_time_approvals"] == "available"
    assert payload["durable_local_rules"] in {"enforced", "limited"}
    assert "key_id" not in payload
    assert "last_proof" not in payload


def test_guard_doctor_includes_safe_trust_diagnostics(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    rc = main(
        [
            "guard",
            "doctor",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    trust_payload = payload["trust"]

    assert rc == 0
    assert trust_payload["command"] == "doctor"
    assert trust_payload["no_ui_passive"] is True
    assert trust_payload["passive_prompt_allowed"] is False
    assert trust_payload["one_time_approvals"] == "available"
    assert trust_payload["durable_local_rules"] in {"enforced", "limited"}
    assert trust_payload["checks"]["passive_no_ui"] is True
    assert trust_payload["checks"]["runtime_protection"] is (
        trust_payload["runtime_protection"] == "protected"
    )
    assert trust_payload["official_install"]["package"] == "hol-guard"
    assert trust_payload["official_install"]["update_command"] == "hol-guard update"
    assert "recommended_actions" in trust_payload
    assert "key_id" not in trust_payload
    assert "last_proof" not in trust_payload


def test_guard_doctor_human_output_includes_trust_diagnostics(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    rc = main(["guard", "doctor", "--home", str(home_dir), "--workspace", str(workspace_dir)])
    output = capsys.readouterr().out

    assert rc == 0
    assert "Local trust" in output
    assert "Passive OS prompts" in output
    assert "hol-guard update" in output
    assert "Guard Cloud policies" in output
    assert "trust test --no-ui --json" in output


def test_trust_cli_doctor_human_output_uses_trust_renderer(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"

    rc = main(["guard", "trust", "doctor", "--home", str(home_dir)])
    output = capsys.readouterr().out

    assert rc == 0
    assert "Local trust" in output
    assert "Passive OS prompts" in output
    assert "hol-guard update" in output
    assert '"runtime_protection"' not in output


def test_trust_cli_bare_combined_command_routes_to_guard() -> None:
    assert _resolve_legacy_args(["trust", "status", "--json"], program_mode="combined") == [
        "guard",
        "trust",
        "status",
        "--json",
    ]


def test_trust_cli_no_ui_probe_requires_no_ui_flag(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"

    missing_flag_rc = main(["guard", "trust", "test", "--home", str(home_dir), "--json"])
    missing_flag_payload = json.loads(capsys.readouterr().out)
    assert missing_flag_rc == 2
    assert "Use --no-ui" in missing_flag_payload["error"]
    assert missing_flag_payload["passive_prompt_allowed"] is False

    no_ui_rc = main(["guard", "trust", "test", "--home", str(home_dir), "--no-ui", "--json"])
    no_ui_payload = json.loads(capsys.readouterr().out)
    assert no_ui_rc == 0
    assert no_ui_payload["probe"] == "passive_no_ui"
    assert no_ui_payload["ok"] is True
    assert no_ui_payload["passive_prompt_allowed"] is False
    assert no_ui_payload["trust_health"] in {"protected", "degraded_safe"}


def test_trust_cli_rejects_unavailable_backend_status(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "status",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert payload["backend_requested"] == "macos-native"
    assert "not available for passive status" in payload["error"]
    assert payload["passive_prompt_allowed"] is False


def test_trust_cli_degraded_safe_backend_is_explicit(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "status",
            "--backend",
            "degraded-safe",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["backend_requested"] == "degraded-safe"
    assert payload["backend"] == "degraded-safe"
    assert payload["remembered_rules"] == "disabled_degraded"
    assert payload["durable_local_rules"] == "limited"


def test_trust_cli_doctor_degraded_safe_does_not_pass_runtime_check(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "doctor",
            "--backend",
            "degraded-safe",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["runtime_protection"] == "degraded"
    assert payload["checks"]["runtime_protection"] is False
    assert payload["checks"]["local_rules_protected"] is False
    assert payload["summary"].startswith("Runtime protection is degraded.")


def test_trust_cli_macos_native_setup_is_explicitly_unavailable(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    rc = main(
        [
            "guard",
            "trust",
            "setup",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert payload["backend_requested"] == "macos-native"
    assert "not enabled yet" in payload["error"]
    assert "trust setup" in payload["error"]
    assert payload["passive_prompt_allowed"] is False

    reset_rc = main(
        [
            "guard",
            "trust",
            "reset",
            "--backend",
            "macos-native",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    reset_payload = json.loads(capsys.readouterr().out)
    assert reset_rc == 2
    assert "trust reset" in reset_payload["error"]


def test_policies_cli_verify_returns_nonzero_for_rollback_detected(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(
        _decision(artifact_id="codex:project:cli-rollback", artifact_hash="hash-cli-rollback"),
        "2026-06-14T00:00:00Z",
    )
    snapshot = _policy_row(home_dir, artifact_id="codex:project:cli-rollback")
    store.upsert_policy(
        _decision(artifact_id="codex:project:cli-current", artifact_hash="hash-cli-current"),
        "2026-06-14T00:01:00Z",
    )
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                snapshot["integrity_version"],
                snapshot["integrity_generation"],
                snapshot["payload_hash"],
                snapshot["payload_mac"],
                snapshot["integrity_key_id"],
                snapshot["signed_at"],
                "codex:project:cli-rollback",
            ),
        )

    verify_rc = main(["guard", "policies", "verify", "--home", str(home_dir), "--json"])
    verify_payload = json.loads(capsys.readouterr().out)

    assert verify_rc == 1
    assert verify_payload["counts"]["rollback_detected"] == 1


def test_policies_cli_migrate_preserve_all_local_re_signs_unknown_key_rows(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(
        _decision(artifact_id="codex:project:cli-rotated", artifact_hash="hash-cli-rotated"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"3" * 32)
    assert store.verify_policy_integrity()["counts"]["unknown_key"] == 1

    migrate_rc = main(
        [
            "guard",
            "policies",
            "migrate-local-integrity",
            "--home",
            str(home_dir),
            "--preserve-all-local",
            "--json",
        ]
    )
    migrate_payload = json.loads(capsys.readouterr().out)

    assert migrate_rc == 0
    assert migrate_payload["preserved"] == 1
    assert migrate_payload["counts"]["valid"] == 1


def test_backup_policy_database_sets_private_mode_when_backup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    calls: list[tuple[Path, int]] = []

    def _fake_set_private_mode(path: Path, mode: int) -> None:
        calls.append((Path(path), mode))

    class _BrokenBackupConnection:
        def backup(self, backup_connection: sqlite3.Connection) -> None:
            raise sqlite3.OperationalError("boom")

    monkeypatch.setattr("codex_plugin_scanner.guard.store._set_private_mode", _fake_set_private_mode)

    with pytest.raises(sqlite3.OperationalError, match="boom"):
        store._backup_policy_database(
            cast(sqlite3.Connection, _BrokenBackupConnection()),
            now="2026-06-14T00:05:00Z",
        )

    assert calls
    assert calls[-1][0].exists()
    assert calls[-1][0].name.startswith("guard.db.pre-integrity-")
    assert calls[-1][1] == 0o600


def test_degraded_mode_persistent_local_allow_is_not_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: False))
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:degraded", artifact_hash="hash-degraded"),
        "2026-06-14T00:00:00Z",
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:degraded",
        "hash-degraded",
        now="2026-06-14T00:01:00Z",
    )
    verify = store.verify_policy_integrity()

    assert resolved is None
    assert verify["mode"] == "degraded"
    assert verify["counts"]["degraded_mode"] == 1


def test_symlinked_guard_home_forces_degraded_local_policy_authority(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    link_home = tmp_path / "link-home"
    link_home.symlink_to(real_home, target_is_directory=True)

    store = GuardStore(link_home)
    store.upsert_policy(
        _decision(artifact_id="codex:project:symlinked", artifact_hash="hash-symlinked"),
        "2026-06-14T00:00:00Z",
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:symlinked",
        "hash-symlinked",
        now="2026-06-14T00:01:00Z",
    )
    verify = store.verify_policy_integrity()

    assert resolved is None
    assert verify["mode"] == "degraded"
    assert "guard_home_symlink" in verify["degraded_reasons"]
    assert verify["counts"]["degraded_mode"] == 1
