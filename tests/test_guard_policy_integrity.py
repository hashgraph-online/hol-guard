"""Regression tests for local Guard policy integrity enforcement."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import pickle
import sqlite3
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.cli import _resolve_legacy_args, main
from codex_plugin_scanner.guard import local_trust_contract as local_trust_contract_module
from codex_plugin_scanner.guard import policy_integrity as policy_integrity_module
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard import store_policy_integrity_runtime as policy_integrity_runtime_module
from codex_plugin_scanner.guard.cli import commands_dispatch_trust as trust_dispatch_module
from codex_plugin_scanner.guard.daemon.manager import ApprovalCenterLocator
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
    POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE,
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


def _enable_macos_native_policy_integrity(
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
):
    fake_keyring = install_fake_system_keyring()
    monkeypatch.setattr(guard_store_module.sys, "platform", "darwin", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_supports_native_macos_security_reads",
        classmethod(lambda cls: True),
    )
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_get_secret_without_macos_ui",
        lambda self, secret_id: fake_keyring.get_password(self.service_name, secret_id),
    )
    return fake_keyring


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


def test_policy_integrity_status_uses_native_no_ui_reads_on_macos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
) -> None:
    _enable_macos_native_policy_integrity(monkeypatch, install_fake_system_keyring)
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:passive-skip", artifact_hash="hash-passive-skip"),
        "2026-06-14T00:00:00Z",
    )
    secret_store = store._policy_integrity_secret_store
    assert isinstance(secret_store, SystemKeyringSecretStore)
    store._clear_policy_integrity_cache()
    monkeypatch.setattr(
        secret_store,
        "get_secret",
        lambda _secret_id: (_ for _ in ()).throw(AssertionError("plain keyring reads should not run")),
    )

    status = store.get_policy_integrity_status()
    verify = store.verify_policy_integrity()

    assert status["mode"] == "protected"
    assert verify["mode"] == "protected"
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


def test_ensure_policy_integrity_ready_for_write_skips_item_context_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:approval-memory", artifact_hash="hash-approval-memory"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"2" * 32)
    monkeypatch.setattr(
        store,
        "_policy_decision_dict_from_row",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("approval self-heal should not build per-row item payloads")
        ),
    )

    payload = store.ensure_policy_integrity_ready_for_write(now="2026-06-14T00:05:00Z")

    assert payload["mode"] == "protected"
    assert payload["counts"]["valid"] == 1
    assert payload["autorepair"]["attempted"] is True
    assert payload["autorepair"]["steps"][0]["step"] == "setup"
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:approval-memory",
            "hash-approval-memory",
            now="2026-06-14T00:06:00Z",
        )
        == "allow"
    )


def test_setup_policy_integrity_repairs_all_harnesses_when_called_with_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:codex", artifact_hash="hash-codex"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        replace(
            _decision(artifact_id="cursor:project:cursor", artifact_hash="hash-cursor"),
            harness="cursor",
        ),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"2" * 32)

    payload = store.setup_policy_integrity(harness="codex", now="2026-06-14T00:05:00Z", include_items=False)
    global_status = store.get_policy_integrity_status()

    assert payload["counts"]["valid"] == 1
    assert global_status["counts"]["valid"] == 2
    assert store.resolve_policy("codex", "codex:project:codex", "hash-codex", now="2026-06-14T00:06:00Z") == "allow"
    assert store.resolve_policy("cursor", "cursor:project:cursor", "hash-cursor", now="2026-06-14T00:06:00Z") == "allow"


def test_ensure_policy_integrity_ready_for_write_clears_tampered_rows_without_item_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:tampered-repair", artifact_hash="hash-tampered-repair"),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:tampered-repair"),
        )
    monkeypatch.setattr(policy_integrity_runtime_module, "require_policy_clear", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        store,
        "_policy_decision_dict_from_row",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("approval repair should not build per-row item payloads")
        ),
    )

    payload = store.ensure_policy_integrity_ready_for_write(now="2026-06-14T00:05:00Z")

    assert payload["counts"]["valid"] == 0
    assert payload["local_rows_scanned"] == 0
    assert payload["cleared"] == 1
    assert payload["autorepair"]["steps"][0]["step"] == "clear_invalid"
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:tampered-repair",
            "hash-tampered-repair",
            now="2026-06-14T00:06:00Z",
        )
        is None
    )


def test_ensure_policy_integrity_ready_for_write_preserves_unknown_key_rows_while_clearing_tampered_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:unknown-key", artifact_hash="hash-unknown-key"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"2" * 32)
    store.upsert_policy(
        _decision(artifact_id="codex:project:tampered-mixed", artifact_hash="hash-tampered-mixed"),
        "2026-06-14T00:01:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:tampered-mixed"),
        )
    monkeypatch.setattr(policy_integrity_runtime_module, "require_policy_clear", lambda *args, **kwargs: None)

    payload = store.ensure_policy_integrity_ready_for_write(now="2026-06-14T00:05:00Z")

    assert payload["counts"]["valid"] == 1
    assert payload["cleared"] == 1
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:unknown-key",
            "hash-unknown-key",
            now="2026-06-14T00:06:00Z",
        )
        == "allow"
    )
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:tampered-mixed",
            "hash-tampered-mixed",
            now="2026-06-14T00:06:00Z",
        )
        is None
    )


def test_ensure_policy_integrity_ready_for_write_repairs_only_requested_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:tampered-local", artifact_hash="hash-tampered-local"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        replace(
            _decision(artifact_id="cursor:project:tampered-foreign", artifact_hash="hash-tampered-foreign"),
            harness="cursor",
        ),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id in (?, ?)",
            ("deadbeef", "codex:project:tampered-local", "cursor:project:tampered-foreign"),
        )
    monkeypatch.setattr(policy_integrity_runtime_module, "require_policy_clear", lambda *args, **kwargs: None)

    payload = store.ensure_policy_integrity_ready_for_write(harness="codex", now="2026-06-14T00:05:00Z")

    assert payload["cleared"] == 1
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:tampered-local",
            "hash-tampered-local",
            now="2026-06-14T00:06:00Z",
        )
        is None
    )
    foreign_rows = [
        item
        for item in store.list_policy_decisions(harness="cursor")
        if item.get("artifact_id") == "cursor:project:tampered-foreign"
    ]
    assert len(foreign_rows) == 1
    assert foreign_rows[0]["integrity_status"] == "tampered"


def test_repair_policy_integrity_uses_reconciled_generation_before_fast_scan(
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
    monkeypatch.setattr(policy_integrity_runtime_module, "require_policy_clear", lambda *args, **kwargs: None)

    payload = store.repair_policy_integrity(clear_invalid=True, now="2026-06-14T00:02:00Z", include_items=False)

    assert payload["counts"]["valid"] == 2
    assert payload["cleared"] == 0
    assert (
        store.resolve_policy("codex", "codex:project:baseline", "hash-baseline", now="2026-06-14T00:03:00Z") == "allow"
    )
    assert store.resolve_policy("codex", "codex:project:pending", "hash-pending", now="2026-06-14T00:03:00Z") == "allow"


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
        event.get("payload", {}).get("artifact_id") == "codex:project:remote-tampered" for event in integrity_events
    )
    assert not any(
        event.get("payload", {}).get("artifact_id") == "codex:project:remote-tampered" for event in ignored_events
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


def test_startup_refresh_does_not_overwrite_newer_policy_integrity_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))

    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    store._prepare_startup_prefetched_policy_integrity_state()
    original_control_lookup = store._load_policy_integrity_control_state
    original_secret_lookup = store._policy_integrity_secret_material
    monkeypatch.setattr(
        store,
        "_load_policy_integrity_control_state",
        lambda *, create: (_ for _ in ()).throw(AssertionError("startup refresh should not re-read control state")),
    )
    monkeypatch.setattr(
        store,
        "_policy_integrity_secret_material",
        lambda *, create: (_ for _ in ()).throw(AssertionError("startup refresh should not re-read secret material")),
    )
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._load_policy_integrity_control_state = original_control_lookup
        store._policy_integrity_secret_material = original_secret_lookup

    state_payload = _policy_integrity_state_payload(store.guard_home)
    current_policy = next(
        item for item in store.list_policy_decisions() if item["artifact_id"] == "codex:project:current"
    )

    assert state_payload["generation"] == 2
    assert current_policy["integrity_status"] == "valid"


def test_startup_refresh_does_not_promote_unverified_policy_integrity_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_generation = ?
            where artifact_id = ?
            """,
            (999, "codex:project:baseline"),
        )

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    store._prepare_startup_prefetched_policy_integrity_state()
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:01:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert state_payload["generation"] == 1


def test_startup_refresh_does_not_promote_legacy_row_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    raw_key, key_id = prefetched_secret
    assert raw_key is not None
    assert key_id is not None

    legacy_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:baseline"))
    legacy_row["integrity_version"] = 1
    legacy_row["integrity_generation"] = 999
    legacy_payload = policy_integrity_module.canonical_policy_payload(legacy_row, integrity_version=1)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?
            where artifact_id = ?
            """,
            (
                1,
                999,
                hashlib.sha256(legacy_payload).hexdigest(),
                hmac.new(raw_key, legacy_payload, hashlib.sha256).hexdigest(),
                key_id,
                "codex:project:baseline",
            ),
        )

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    store._prepare_startup_prefetched_policy_integrity_state()
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:01:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert state_payload["generation"] == 1


def test_startup_refresh_repairs_stale_sync_state_generation_from_control_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    tampered_state = dict(_policy_integrity_state_payload(store.guard_home))
    tampered_state["generation"] = 999
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update sync_state
            set payload_json = ?,
                updated_at = ?
            where state_key = 'policy_integrity'
            """,
            (
                json.dumps(tampered_state, sort_keys=True, separators=(",", ":")),
                "2026-06-14T00:00:30Z",
            ),
        )

    with store._connect() as connection:
        store._refresh_policy_integrity_state(connection, now="2026-06-14T00:01:00Z", create_key=False)

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert state_payload["generation"] == 1


def test_startup_refresh_persists_pending_generation_repair(
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

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    assert prefetched_control["pending_generation"] == 2

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    store._prepare_startup_prefetched_policy_integrity_state()
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 2
    assert recovered_control["pending_generation"] is None
    assert state_payload["generation"] == 2


def test_startup_refresh_keeps_pending_generation_when_legacy_rows_remain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)
    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
        "2026-06-14T00:01:00Z",
    )
    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None
    legacy_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:legacy"))
    legacy_row["integrity_version"] = 1
    legacy_payload = policy_integrity_module.canonical_policy_payload(legacy_row, integrity_version=1)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(legacy_payload).hexdigest(),
                hmac.new(raw_key, legacy_payload, hashlib.sha256).hexdigest(),
                key_id,
                legacy_row["signed_at"],
                "codex:project:legacy",
            ),
        )
    stale_control = dict(_policy_integrity_control_payload(store))
    stale_control["generation"] = 1
    stale_control["pending_generation"] = 2
    stale_control["cutover_complete"] = False
    assert store._store_policy_integrity_control_state(stale_control)
    assert _policy_integrity_control_payload(store)["generation"] == 1

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    store._prepare_startup_prefetched_policy_integrity_state()
    assert store._startup_prefetched_policy_integrity_trusted_state["generation"] == 1

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] == 2
    assert recovered_control["cutover_complete"] is False
    assert state_payload["generation"] == 1


def test_startup_refresh_clears_stale_pending_generation_when_legacy_rows_remain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)
    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
        "2026-06-14T00:01:00Z",
    )
    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None

    legacy_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:legacy"))
    legacy_row["integrity_version"] = 1
    legacy_payload = policy_integrity_module.canonical_policy_payload(legacy_row, integrity_version=1)
    pending_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:pending"))
    pending_row["integrity_generation"] = 1
    pending_payload = policy_integrity_module.canonical_policy_payload(
        pending_row,
        integrity_version=pending_row["integrity_version"],
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(legacy_payload).hexdigest(),
                hmac.new(raw_key, legacy_payload, hashlib.sha256).hexdigest(),
                key_id,
                legacy_row["signed_at"],
                "codex:project:legacy",
            ),
        )
        connection.execute(
            """
            update policy_decisions
            set integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(pending_payload).hexdigest(),
                hmac.new(raw_key, pending_payload, hashlib.sha256).hexdigest(),
                key_id,
                "codex:project:pending",
            ),
        )
    stale_control = dict(_policy_integrity_control_payload(store))
    stale_control["generation"] = 1
    stale_control["pending_generation"] = 2
    stale_control["cutover_complete"] = False
    assert store._store_policy_integrity_control_state(stale_control)

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    store._prepare_startup_prefetched_policy_integrity_state()

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] is None
    assert recovered_control["cutover_complete"] is False
    assert state_payload["generation"] == 1


def test_refresh_clears_stale_pending_generation_when_legacy_rows_remain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)
    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
        "2026-06-14T00:01:00Z",
    )
    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None

    legacy_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:legacy"))
    legacy_row["integrity_version"] = 1
    legacy_payload = policy_integrity_module.canonical_policy_payload(legacy_row, integrity_version=1)
    pending_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:pending"))
    pending_row["integrity_generation"] = 1
    pending_payload = policy_integrity_module.canonical_policy_payload(
        pending_row,
        integrity_version=pending_row["integrity_version"],
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(legacy_payload).hexdigest(),
                hmac.new(raw_key, legacy_payload, hashlib.sha256).hexdigest(),
                key_id,
                legacy_row["signed_at"],
                "codex:project:legacy",
            ),
        )
        connection.execute(
            """
            update policy_decisions
            set integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(pending_payload).hexdigest(),
                hmac.new(raw_key, pending_payload, hashlib.sha256).hexdigest(),
                key_id,
                "codex:project:pending",
            ),
        )
    stale_control = dict(_policy_integrity_control_payload(store))
    stale_control["generation"] = 1
    stale_control["pending_generation"] = 2
    stale_control["cutover_complete"] = False
    assert store._store_policy_integrity_control_state(stale_control)

    with store._connect() as connection:
        store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] is None
    assert recovered_control["cutover_complete"] is False
    assert state_payload["generation"] == 1


def test_refresh_keeps_pending_generation_when_only_signed_v1_rows_remain(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None

    legacy_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:legacy"))
    legacy_row["integrity_version"] = 1
    legacy_payload = policy_integrity_module.canonical_policy_payload(legacy_row, integrity_version=1)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?,
                signed_at = ?
            where artifact_id = ?
            """,
            (
                1,
                hashlib.sha256(legacy_payload).hexdigest(),
                hmac.new(raw_key, legacy_payload, hashlib.sha256).hexdigest(),
                key_id,
                legacy_row["signed_at"],
                "codex:project:legacy",
            ),
        )
    stale_control = dict(_policy_integrity_control_payload(store))
    stale_control["generation"] = 1
    stale_control["pending_generation"] = 2
    stale_control["cutover_complete"] = False
    assert store._store_policy_integrity_control_state(stale_control)

    with store._connect() as connection:
        store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] == 2
    assert recovered_control["cutover_complete"] is False
    assert state_payload["generation"] == 1


def test_refresh_leaves_mixed_pending_generations_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    baseline_snapshot = _policy_row(store.guard_home, artifact_id="codex:project:baseline")
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)
    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
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
                baseline_snapshot["integrity_version"],
                baseline_snapshot["integrity_generation"],
                baseline_snapshot["payload_hash"],
                baseline_snapshot["payload_mac"],
                baseline_snapshot["integrity_key_id"],
                baseline_snapshot["signed_at"],
                "codex:project:baseline",
            ),
        )

    with store._connect() as connection:
        store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] == 2
    assert state_payload["generation"] == 1


def test_startup_refresh_leaves_mixed_pending_generations_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    baseline_snapshot = _policy_row(store.guard_home, artifact_id="codex:project:baseline")
    monkeypatch.setattr(store, "_finalize_policy_integrity_control_state", lambda payload: None)
    store.upsert_policy(
        _decision(artifact_id="codex:project:pending", artifact_hash="hash-pending"),
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
                baseline_snapshot["integrity_version"],
                baseline_snapshot["integrity_generation"],
                baseline_snapshot["payload_hash"],
                baseline_snapshot["payload_mac"],
                baseline_snapshot["integrity_key_id"],
                baseline_snapshot["signed_at"],
                "codex:project:baseline",
            ),
        )

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    store._prepare_startup_prefetched_policy_integrity_state()

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] == 2
    assert state_payload["generation"] == 1


def test_startup_refresh_leaves_invalid_pending_generations_unresolved(
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
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:baseline"),
        )

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    store._prepare_startup_prefetched_policy_integrity_state()

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert recovered_control["pending_generation"] == 2
    assert state_payload["generation"] == 1


def test_startup_refresh_does_not_write_control_state_inside_refresh(
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

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    store._prepare_startup_prefetched_policy_integrity_state()

    monkeypatch.setattr(
        store,
        "_store_policy_integrity_control_state",
        lambda payload: (_ for _ in ()).throw(AssertionError("startup refresh should not write control state")),
    )
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET


def test_startup_refresh_degrades_when_prefetched_repair_cannot_persist(
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

    store._startup_prefetched_policy_integrity_secret_material = store._policy_integrity_secret_material(create=False)
    store._startup_prefetched_policy_integrity_trusted_state = dict(_policy_integrity_control_payload(store))
    original_store = store._store_policy_integrity_control_state
    monkeypatch.setattr(store, "_store_policy_integrity_control_state", lambda payload: False)
    store._prepare_startup_prefetched_policy_integrity_state()
    monkeypatch.setattr(store, "_store_policy_integrity_control_state", original_store)

    try:
        with store._connect() as connection:
            payload = store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_repair_failed = False

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert payload["mode"] == POLICY_INTEGRITY_MODE_DEGRADED
    assert POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE in payload["degraded_reasons"]
    assert state_payload["generation"] is None


def test_startup_refresh_uses_newer_control_state_before_persisting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))

    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )
    current_control = dict(_policy_integrity_control_payload(store))
    assert current_control["generation"] == 2

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    original_lookup = store._load_policy_integrity_control_state
    calls = {"count": 0}

    def lookup_current(*, create: bool) -> dict[str, object] | None:
        calls["count"] += 1
        if calls["count"] == 1:
            return current_control
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", lookup_current)
    try:
        store._prepare_startup_prefetched_policy_integrity_state()
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._load_policy_integrity_control_state = original_lookup

    repaired_control = _policy_integrity_control_payload(store)
    assert repaired_control["generation"] == 2
    assert repaired_control["pending_generation"] is None


def test_startup_refresh_degrades_when_freshness_control_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    prefetched_control["generation"] = 1
    assert store._store_policy_integrity_control_state(prefetched_control)

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = dict(prefetched_control)
    original_lookup = store._load_policy_integrity_control_state
    calls = {"count": 0}

    def flaky_lookup(*, create: bool) -> dict[str, object] | None:
        calls["count"] += 1
        if calls["count"] == 1:
            return None
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", flaky_lookup)
    try:
        store._prepare_startup_prefetched_policy_integrity_state()
        with store._connect() as connection:
            payload = store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_repair_failed = False
        store._load_policy_integrity_control_state = original_lookup

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert payload["mode"] == POLICY_INTEGRITY_MODE_DEGRADED
    assert POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE in payload["degraded_reasons"]
    assert state_payload["generation"] is None


def test_startup_refresh_keeps_valid_prefetch_when_freshness_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = dict(prefetched_control)
    original_lookup = store._load_policy_integrity_control_state
    calls = {"count": 0}

    def flaky_lookup(*, create: bool) -> dict[str, object] | None:
        calls["count"] += 1
        if calls["count"] == 1:
            return None
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", flaky_lookup)
    try:
        store._prepare_startup_prefetched_policy_integrity_state()
        with store._connect() as connection:
            payload = store._refresh_policy_integrity_state(connection, now="2026-06-14T00:01:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_repair_failed = False
        store._load_policy_integrity_control_state = original_lookup

    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert payload["mode"] == POLICY_INTEGRITY_MODE_PROTECTED
    assert state_payload["generation"] == 1


def test_startup_refresh_leaves_mixed_newer_generations_unresolved(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    baseline_snapshot = _policy_row(store.guard_home, artifact_id="codex:project:baseline")
    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )

    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None

    newer_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:current"))
    newer_row["integrity_generation"] = 3
    newer_payload = policy_integrity_module.canonical_policy_payload(
        newer_row, integrity_version=newer_row["integrity_version"]
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
                baseline_snapshot["integrity_version"],
                baseline_snapshot["integrity_generation"],
                baseline_snapshot["payload_hash"],
                baseline_snapshot["payload_mac"],
                baseline_snapshot["integrity_key_id"],
                baseline_snapshot["signed_at"],
                "codex:project:baseline",
            ),
        )
        connection.execute(
            """
            update policy_decisions
            set integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?
            where artifact_id = ?
            """,
            (
                3,
                hashlib.sha256(newer_payload).hexdigest(),
                hmac.new(raw_key, newer_payload, hashlib.sha256).hexdigest(),
                key_id,
                "codex:project:current",
            ),
        )

    prefetched_secret = (raw_key, key_id)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    prefetched_control["generation"] = 1
    prefetched_control["pending_generation"] = None
    assert store._store_policy_integrity_control_state(prefetched_control)

    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = dict(prefetched_control)
    store._prepare_startup_prefetched_policy_integrity_state()

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert state_payload["generation"] == 1


def test_startup_refresh_leaves_invalid_newer_generations_unresolved(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        _decision(artifact_id="codex:project:current", artifact_hash="hash-current"),
        "2026-06-14T00:01:00Z",
    )

    raw_key, key_id = store._policy_integrity_secret_material(create=False)
    assert raw_key is not None
    assert key_id is not None

    valid_row = dict(_policy_row(store.guard_home, artifact_id="codex:project:baseline"))
    valid_row["integrity_generation"] = 3
    valid_payload = policy_integrity_module.canonical_policy_payload(
        valid_row, integrity_version=valid_row["integrity_version"]
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_generation = ?,
                payload_hash = ?,
                payload_mac = ?,
                integrity_key_id = ?
            where artifact_id = ?
            """,
            (
                3,
                hashlib.sha256(valid_payload).hexdigest(),
                hmac.new(raw_key, valid_payload, hashlib.sha256).hexdigest(),
                key_id,
                "codex:project:baseline",
            ),
        )
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:current"),
        )

    prefetched_control = dict(_policy_integrity_control_payload(store))
    prefetched_control["generation"] = 1
    prefetched_control["pending_generation"] = None
    assert store._store_policy_integrity_control_state(prefetched_control)

    store._startup_prefetched_policy_integrity_secret_material = (raw_key, key_id)
    store._startup_prefetched_policy_integrity_trusted_state = dict(prefetched_control)
    store._prepare_startup_prefetched_policy_integrity_state()

    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:02:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["generation"] == 1
    assert state_payload["generation"] == 1


def test_startup_refresh_persists_cutover_completion(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:baseline", artifact_hash="hash-baseline"),
        "2026-06-14T00:00:00Z",
    )

    stale_control = dict(_policy_integrity_control_payload(store))
    stale_control["cutover_complete"] = False
    assert store._store_policy_integrity_control_state(stale_control)

    prefetched_secret = store._policy_integrity_secret_material(create=False)
    prefetched_control = dict(_policy_integrity_control_payload(store))
    store._startup_prefetched_policy_integrity_secret_material = prefetched_secret
    store._startup_prefetched_policy_integrity_trusted_state = prefetched_control
    store._prepare_startup_prefetched_policy_integrity_state()
    try:
        with store._connect() as connection:
            store._refresh_policy_integrity_state(connection, now="2026-06-14T00:01:00Z", create_key=False)
    finally:
        store._startup_prefetched_policy_integrity_secret_material = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET
        store._startup_prefetched_policy_integrity_trusted_state = guard_store_module._POLICY_INTEGRITY_LOOKUP_UNSET

    recovered_control = _policy_integrity_control_payload(store)
    state_payload = _policy_integrity_state_payload(store.guard_home)
    assert recovered_control["cutover_complete"] is True
    assert state_payload["cutover_complete"] is True


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
    assert trust_payload["checks"]["runtime_protection"] is (trust_payload["runtime_protection"] == "protected")
    assert trust_payload["official_install"]["package"] == "hol-guard"
    assert trust_payload["official_install"]["update_command"] == "hol-guard update"
    assert "active_command_status" in trust_payload["official_install"]
    assert "self_check_command" in trust_payload["official_install"]
    assert trust_payload["approval_center"]["active"] is False
    assert trust_payload["approval_url_base"] is None
    assert trust_payload["passive_read_guarantee"]
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
    assert "Install check" in output
    assert "hol-guard update" in output
    assert "Guard Cloud policies" in output
    assert "trust test --no-ui --json" in output


def test_trust_cli_doctor_human_output_uses_trust_renderer(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"

    rc = main(["guard", "trust", "doctor", "--home", str(home_dir)])
    output = capsys.readouterr().out

    assert rc == 0
    assert "Local trust" in output
    assert "Mode" in output
    assert "Passive OS prompts" in output
    assert "Install mode" in output
    assert "Install check" in output
    assert "hol-guard update" in output
    assert '"runtime_protection"' not in output


def test_build_trust_doctor_payload_reports_active_approval_center_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1:5481",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:00:00+00:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: locator.daemon_url)

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["active"] is True
    assert payload["approval_center"]["approval_url_base"] == "http://127.0.0.1:5481"
    assert payload["approval_center"]["port"] == 5481
    assert payload["checks"]["approval_center_active"] is True
    assert payload["approval_url_base"] == "http://127.0.0.1:5481"


def test_build_trust_doctor_payload_prefers_live_daemon_port_when_locator_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    stale_locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1:5481",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:00:00+00:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: stale_locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:5499")
    monkeypatch.setattr(
        trust_dispatch_module,
        "_load_state",
        lambda _home: {
            "pid": 7777,
            "port": 5499,
            "package_version": trust_dispatch_module.__version__,
            "started_at": "2026-06-19T12:01:00+00:00",
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["approval_url_base"] == "http://127.0.0.1:5499"
    assert payload["approval_center"]["port"] == 5499
    assert payload["approval_center"]["snapshot_fresh"] is False
    assert payload["checks"]["approval_center_route_current"] is False
    assert any("refresh the local browser approval route" in action for action in payload["recommended_actions"])


def test_build_trust_doctor_payload_tolerates_mixed_naive_and_aware_locator_timestamps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1:5481",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:01:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: locator.daemon_url)
    monkeypatch.setattr(
        trust_dispatch_module,
        "_load_state",
        lambda _home: {
            "pid": 1234,
            "port": 5481,
            "package_version": trust_dispatch_module.__version__,
            "started_at": "2026-06-19T12:00:00+00:00",
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["snapshot_fresh"] is True
    assert payload["approval_center"]["approval_url_base"] == "http://127.0.0.1:5481"


def test_build_trust_doctor_payload_tolerates_missing_locator_daemon_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:01:00+00:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: locator.daemon_url)
    monkeypatch.setattr(
        trust_dispatch_module,
        "_load_state",
        lambda _home: {
            "pid": 1234,
            "port": 5481,
            "package_version": trust_dispatch_module.__version__,
            "started_at": "2026-06-19T12:00:00+00:00",
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["snapshot_fresh"] is True
    assert payload["approval_center"]["approval_url_base"] == "http://127.0.0.1:5481"
    assert payload["approval_center"]["port"] == 5481


def test_build_trust_doctor_payload_detects_editable_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)

    class _FakeDistribution:
        version = "9.9.9"

        def read_text(self, filename: str) -> str | None:
            if filename == "direct_url.json":
                return json.dumps({"dir_info": {"editable": True}})
            return None

        def locate_file(self, _path: str) -> Path:
            return Path("editable/hol-guard/src")

    monkeypatch.setattr(trust_dispatch_module.importlib.metadata, "distribution", lambda _name: _FakeDistribution())
    monkeypatch.setattr(
        trust_dispatch_module,
        "build_guard_install_surface_payload",
        lambda: {
            "installer": "pipx",
            "binary_diagnostics": {
                "resolved_hol_guard": "/mock-home/.local/bin/hol-guard",
                "expected_script_dir": None,
                "path_status": "pipx_shim_detected",
            },
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["official_install"]["version"] == "9.9.9"
    assert payload["official_install"]["installation_mode"] == "editable"
    assert payload["official_install"]["editable_install"] is True
    assert payload["official_install"]["official_install"] is False
    assert payload["official_install"]["official_install_verified"] is False
    assert any("official pipx install" in action for action in payload["recommended_actions"])


def test_build_trust_doctor_payload_tolerates_distribution_path_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)

    class _FakeDistribution:
        version = "9.9.9"

        def read_text(self, _filename: str) -> str | None:
            return None

        def locate_file(self, _path: str) -> Path:
            raise RuntimeError("bad metadata")

    monkeypatch.setattr(trust_dispatch_module.importlib.metadata, "distribution", lambda _name: _FakeDistribution())
    monkeypatch.setattr(
        trust_dispatch_module,
        "build_guard_install_surface_payload",
        lambda: {
            "installer": "pipx",
            "binary_diagnostics": {
                "resolved_hol_guard": "/usr/local/bin/hol-guard",
                "expected_script_dir": None,
                "path_status": "path_mismatch",
            },
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["official_install"]["version"] == "9.9.9"
    assert payload["official_install"]["installation_mode"] == "packaged"
    assert payload["official_install"]["official_install"] is False
    assert payload["official_install"]["active_command_status"] == "path_mismatch"
    assert payload["official_install"]["active_command_verified"] is False
    assert any("command -v hol-guard" in action for action in payload["recommended_actions"])


def test_build_trust_doctor_payload_reports_missing_command_path_help(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)

    class _FakeDistribution:
        version = "9.9.9"

        def read_text(self, _filename: str) -> str | None:
            return None

        def locate_file(self, _path: str) -> Path:
            return Path("/mock-home/.local/pipx/venvs/hol-guard/lib/python3.12/site-packages")

    monkeypatch.setattr(trust_dispatch_module.importlib.metadata, "distribution", lambda _name: _FakeDistribution())
    monkeypatch.setattr(
        trust_dispatch_module,
        "build_guard_install_surface_payload",
        lambda: {
            "installer": "pipx",
            "binary_diagnostics": {
                "resolved_hol_guard": None,
                "expected_script_dir": None,
                "path_status": "not_on_path",
            },
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["official_install"]["active_command_status"] == "not_on_path"
    assert payload["official_install"]["active_command_verified"] is False
    assert any("not on PATH" in action for action in payload["recommended_actions"])
    assert not any("command -v hol-guard" in action for action in payload["recommended_actions"])


def test_build_trust_doctor_payload_verifies_official_pipx_command_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)

    class _FakeDistribution:
        version = "9.9.9"

        def read_text(self, _filename: str) -> str | None:
            return None

        def locate_file(self, _path: str) -> Path:
            return Path("/mock-home/.local/pipx/venvs/hol-guard/lib/python3.12/site-packages")

    monkeypatch.setattr(trust_dispatch_module.importlib.metadata, "distribution", lambda _name: _FakeDistribution())
    monkeypatch.setattr(
        trust_dispatch_module,
        "build_guard_install_surface_payload",
        lambda: {
            "installer": "pipx",
            "binary_diagnostics": {
                "resolved_hol_guard": "/mock-home/.local/bin/hol-guard",
                "expected_script_dir": None,
                "path_status": "pipx_shim_detected",
            },
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["official_install"]["installation_mode"] == "official-pipx"
    assert payload["official_install"]["official_install"] is True
    assert payload["official_install"]["official_install_verified"] is True
    assert payload["checks"]["official_install_verified"] is True


def test_build_trust_doctor_payload_recommends_daemon_restart_only_for_version_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1:5481",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:01:00+00:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: locator.daemon_url)
    monkeypatch.setattr(
        trust_dispatch_module,
        "_load_state",
        lambda _home: {
            "pid": 1234,
            "port": 5481,
            "package_version": "0.0.1",
            "started_at": "2026-06-19T12:00:00+00:00",
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["snapshot_fresh"] is True
    assert payload["approval_center"]["restart_required"] is True
    assert any("restart the Guard daemon" in action for action in payload["recommended_actions"])


def test_build_trust_doctor_payload_skips_daemon_restart_when_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    locator = ApprovalCenterLocator(
        guard_home=home_dir,
        daemon_url="http://127.0.0.1:5481",
        approval_url_base="http://127.0.0.1:5481",
        pid=1234,
        started_at="2026-06-19T12:01:00+00:00",
        state_path=home_dir / "guard-daemon-state.json",
    )
    monkeypatch.setattr(trust_dispatch_module, "read_approval_center_locator", lambda _home: locator)
    monkeypatch.setattr(trust_dispatch_module, "load_guard_daemon_url", lambda _home: locator.daemon_url)
    monkeypatch.setattr(
        trust_dispatch_module,
        "_load_state",
        lambda _home: {
            "pid": 1234,
            "port": 5481,
            "package_version": trust_dispatch_module.__version__,
            "started_at": "2026-06-19T12:00:00+00:00",
        },
    )

    payload = trust_dispatch_module.build_trust_doctor_payload(store)

    assert payload["approval_center"]["snapshot_fresh"] is True
    assert payload["approval_center"]["restart_required"] is False
    assert not any("restart the Guard daemon" in action for action in payload["recommended_actions"])


def test_trust_cli_doctor_reports_macos_no_prompt_copy(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    monkeypatch.setattr(trust_dispatch_module.sys, "platform", "darwin", raising=False)

    rc = main(["guard", "trust", "doctor", "--home", str(home_dir)])
    output = capsys.readouterr().out

    assert rc == 0
    assert "No passive macOS Keychain access" in output


def test_trust_cli_doctor_redacts_secret_like_assignments_in_json_output(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    original_trust_payload = trust_dispatch_module._trust_status_payload

    def fake_trust_payload(store: GuardStore, *, command: str, backend: str) -> dict[str, object]:
        payload = original_trust_payload(store, command=command, backend=backend)
        payload["summary"] = (
            "Guard saw MY_SECRET_TOKEN=super-secret-value and "
            "guard-oauth-local-credentials:8126370c0eb65a02 while checking trust."
        )
        return payload

    monkeypatch.setattr(trust_dispatch_module, "_trust_status_payload", fake_trust_payload)

    rc = main(
        [
            "guard",
            "trust",
            "doctor",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    output = capsys.readouterr().out
    payload = json.loads(output)
    summary = str(payload.get("summary") or "")

    assert rc == 0
    assert "MY_SECRET_TOKEN" not in output
    assert "super-secret-value" not in output
    assert "8126370c0eb65a02" not in output
    assert "MY_SECRET_TOKEN" not in summary
    assert "super-secret-value" not in summary
    assert "8126370c0eb65a02" not in summary
    assert summary


def test_trust_cli_explain_preserves_non_secret_colon_rule_text(capsys) -> None:
    trust_dispatch_module._emit_trust_payload(
        "trust.explain",
        {
            "rule": {
                "pattern": "api_key: forbidden_pattern",
                "description": "credential: oauth-style",
                "status": "token: active",
            }
        },
        True,
    )
    payload = json.loads(capsys.readouterr().out)
    rule = payload["rule"]

    assert rule["pattern"] == "api_key: forbidden_pattern"
    assert rule["description"] == "credential: oauth-style"
    assert rule["status"] == "token: active"


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


def test_trust_cli_explain_requires_rule_id(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"

    rc = main(["guard", "trust", "explain", "--home", str(home_dir), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert "trust explain --rule" in payload["error"]


def test_trust_cli_explain_rejects_boolean_rule_id(tmp_path: Path, capsys) -> None:
    store = GuardStore(tmp_path / "home")

    rc = trust_dispatch_module._run_guard_trust_command(
        argparse.Namespace(trust_command="explain", rule=True, json=True, backend="auto"),
        store=store,
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert "trust explain --rule" in payload["error"]


def test_trust_cli_explain_reports_protected_local_rule(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
) -> None:
    home_dir = tmp_path / "home"
    _enable_macos_native_policy_integrity(monkeypatch, install_fake_system_keyring)
    store = GuardStore(home_dir)
    setup = store.setup_policy_integrity(now="2026-06-19T12:00:00Z")
    assert setup["mode"] == "protected"
    store.upsert_policy(_decision(artifact_id="codex:project:local-rule"), "2026-06-19T12:01:00Z")
    decision_id = int(_policy_row(home_dir, artifact_id="codex:project:local-rule")["decision_id"])

    rc = main(["guard", "trust", "explain", "--home", str(home_dir), "--rule", str(decision_id), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["rule_status"] == "remembered_rule_protected"
    assert payload["rule_status_label"] == "Remembered and protected"
    assert payload["rule"]["decision_id"] == decision_id
    assert payload["rule"]["integrity_status"] == "valid"
    assert payload["trust_status"]["remembered_rules"] == "enforced"
    assert "integrity_key_id" not in payload["rule"]


def test_trust_cli_explain_human_output_uses_trust_renderer(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
) -> None:
    home_dir = tmp_path / "home"
    _enable_macos_native_policy_integrity(monkeypatch, install_fake_system_keyring)
    store = GuardStore(home_dir)
    store.setup_policy_integrity(now="2026-06-19T12:00:00Z")
    store.upsert_policy(_decision(artifact_id="codex:project:local-rule-human"), "2026-06-19T12:01:00Z")
    decision_id = int(_policy_row(home_dir, artifact_id="codex:project:local-rule-human")["decision_id"])

    rc = main(["guard", "trust", "explain", "--home", str(home_dir), "--rule", str(decision_id)])
    output = capsys.readouterr().out

    assert rc == 0
    assert "Remembered rule authority" in output
    assert "Remembered and protected" in output


def test_trust_cli_explain_reports_guard_cloud_rule(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="publisher",
                action="block",
                publisher="npm",
                reason="cloud block",
                source="cloud-sync",
            )
        ],
        "2026-06-19T12:01:00Z",
        remote_write_authorized=True,
    )
    decision_id = int(store.list_policy_decisions("codex")[0]["decision_id"])

    rc = main(["guard", "trust", "explain", "--home", str(home_dir), "--rule", str(decision_id), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["rule_status"] == "guard_cloud"
    assert payload["rule_status_label"] == "From Guard Cloud"
    assert payload["rule"]["source"] == "cloud-sync"
    assert "integrity_status" not in payload["rule"]


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


def test_trust_cli_macos_native_setup_and_reset_work(
    tmp_path: Path,
    capsys,
    monkeypatch,
    install_fake_system_keyring,
) -> None:
    _enable_macos_native_policy_integrity(monkeypatch, install_fake_system_keyring)
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(
        _decision(artifact_id="codex:project:trust-setup", artifact_hash="hash-trust-setup"),
        "2026-06-14T00:00:00Z",
    )
    store.reset_policy_integrity(now="2026-06-14T00:00:01Z")

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

    assert rc == 0
    assert payload["backend_requested"] == "macos-native"
    assert payload["backend"] == "system-keyring"
    assert payload["mode"] == "protected"
    assert payload["remembered_rules"] == "enforced"
    assert payload["ok"] is True
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
    assert reset_rc == 0
    assert reset_payload["mode"] == "degraded"
    assert reset_payload["remembered_rules"] == "disabled_degraded"
    assert reset_payload["ok"] is True


def test_setup_policy_integrity_rolls_back_degraded_refresh_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(store, "_load_policy_integrity_control_state", lambda create: None)

    baseline = _policy_integrity_state_payload(store.guard_home)
    observed: dict[str, dict[str, object]] = {}

    def _verify_policy_integrity(*, harness: str | None = None) -> dict[str, object]:
        observed["state_payload"] = _policy_integrity_state_payload(store.guard_home)
        return {"harness": harness, "mode": "degraded"}

    monkeypatch.setattr(store, "verify_policy_integrity", _verify_policy_integrity)

    result = store.setup_policy_integrity(harness="codex", now="2026-06-14T00:00:00Z")

    assert result == {"harness": "codex", "mode": "degraded"}
    assert observed["state_payload"] == baseline


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
