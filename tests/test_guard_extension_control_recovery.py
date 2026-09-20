from __future__ import annotations

import concurrent.futures
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import extension_control_api as extension_control_api_module
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.coverage_ci import UNDER_COVERAGE_TRACING


def _view(health: AuthorityHealth, revision: int) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        health,
        revision,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )


def _approve_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extension_control_api_module, "require_extension_control", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(extension_control_api_module, "consume_extension_control_grant", lambda *_args, **_kwargs: None)


def test_recovery_refreshes_stale_runtime_after_store_already_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    protected = _view(AuthorityHealth.PROTECTED, 4)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(replace(protected, health=AuthorityHealth.RECOVERY_REQUIRED)),
    )
    recovery_calls: list[object] = []
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: protected)
    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        lambda **kwargs: recovery_calls.append(kwargs) or protected,
    )

    effective = service.recover_authority({"session_nonce": "nonce"})

    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert service.effective()["health"] == AuthorityHealth.PROTECTED.value
    assert recovery_calls == []


def test_recovery_can_install_lower_recovered_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    damaged = _view(AuthorityHealth.RECOVERY_REQUIRED, 9)
    recovered = _view(AuthorityHealth.PROTECTED, 4)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(damaged),
    )
    current_view = [damaged]
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: current_view[0])

    def recover(**_kwargs: object) -> ExtensionControlAuthorityView:
        current_view[0] = recovered
        return recovered

    monkeypatch.setattr(store, "recover_extension_control_authority", recover)
    _approve_recovery(monkeypatch)

    effective = service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert effective["revision"] == 4


@pytest.mark.parametrize(
    "runtime_health",
    (
        AuthorityHealth.PROTECTED,
        AuthorityHealth.UNENROLLED,
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
    ),
)
def test_recovery_marks_runtime_fail_safe_before_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_health: AuthorityHealth,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    damaged = _view(AuthorityHealth.RECOVERY_REQUIRED, 9)
    recovered = _view(AuthorityHealth.PROTECTED, 4)
    runtime = ExtensionControlRuntime(_view(runtime_health, 9))
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=runtime,
    )
    observed_runtime_health: list[AuthorityHealth] = []
    current_view = [damaged]
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: current_view[0])

    def recover(**_kwargs: object) -> ExtensionControlAuthorityView:
        observed_runtime_health.append(runtime.current().health)
        current_view[0] = recovered
        return recovered

    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        recover,
    )
    _approve_recovery(monkeypatch)

    effective = service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert observed_runtime_health == [AuthorityHealth.RECOVERY_REQUIRED]
    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert effective["revision"] == 4


@pytest.mark.skipif(
    UNDER_COVERAGE_TRACING,
    reason="Concurrent-recovery interleavings shift under tracing; run untraced",
)
def test_concurrent_recovery_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    damaged = _view(AuthorityHealth.RECOVERY_REQUIRED, 9)
    recovered = _view(AuthorityHealth.PROTECTED, 4)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(damaged),
    )
    current_view = damaged
    entry_barrier = threading.Barrier(8)

    def read(_registry: object) -> ExtensionControlAuthorityView:
        observed = current_view
        if observed is damaged:
            entry_barrier.wait(timeout=10)
        return observed

    def recover(**_kwargs: object) -> ExtensionControlAuthorityView:
        nonlocal current_view
        current_view = recovered
        return recovered

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", read)
    monkeypatch.setattr(store, "recover_extension_control_authority", recover)
    _approve_recovery(monkeypatch)

    results: list[dict[str, object]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        # Each cohort observes the same fault before any repair, then reads the
        # repaired authority. Retain all 32 requests and eight concurrent workers.
        for start in range(0, 32, 8):
            current_view = damaged
            entry_barrier = threading.Barrier(8)
            results.extend(
                executor.map(
                    lambda index: service.recover_authority(
                        {"approval_password": "secret", "session_nonce": f"nonce-{index}"}
                    ),
                    range(start, start + 8),
                )
            )

    assert {result["health"] for result in results} == {AuthorityHealth.PROTECTED.value}
    assert {result["revision"] for result in results} == {4}


def test_authority_recovery_consumes_daemon_bound_approval_before_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    tampered = ExtensionControlAuthorityView(
        AuthorityHealth.TAMPERED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    protected = replace(tampered, health=AuthorityHealth.PROTECTED, revision=5)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(tampered),
    )
    calls: list[str] = []
    current_view = [tampered]
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: current_view[0])

    def recover(**_kwargs: object) -> ExtensionControlAuthorityView:
        calls.append("recover")
        current_view[0] = protected
        return protected

    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        recover,
    )
    monkeypatch.setattr(
        extension_control_api_module,
        "require_extension_control",
        lambda *_args, **_kwargs: calls.append("require") or object(),
    )
    monkeypatch.setattr(
        extension_control_api_module,
        "consume_extension_control_grant",
        lambda *_args, **_kwargs: calls.append("consume"),
    )

    effective = service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert effective["revision"] == 5
    assert calls == ["require", "consume", "recover"]
