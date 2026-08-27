from __future__ import annotations

import concurrent.futures
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
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: damaged)
    monkeypatch.setattr(store, "recover_extension_control_authority", lambda **_kwargs: recovered)
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
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: damaged)
    monkeypatch.setattr(
        store,
        "recover_extension_control_authority",
        lambda **_kwargs: observed_runtime_health.append(runtime.current().health) or recovered,
    )
    _approve_recovery(monkeypatch)

    effective = service.recover_authority({"approval_password": "secret", "session_nonce": "nonce"})

    assert observed_runtime_health == [AuthorityHealth.RECOVERY_REQUIRED]
    assert effective["health"] == AuthorityHealth.PROTECTED.value
    assert effective["revision"] == 4


def test_concurrent_recovery_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    damaged = _view(AuthorityHealth.RECOVERY_REQUIRED, 9)
    recovered = _view(AuthorityHealth.PROTECTED, 4)
    service = ExtensionControlApiService(
        store=store,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(damaged),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: damaged)
    monkeypatch.setattr(store, "recover_extension_control_authority", lambda **_kwargs: recovered)
    _approve_recovery(monkeypatch)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda index: service.recover_authority(
                    {"approval_password": "secret", "session_nonce": f"nonce-{index}"}
                ),
                range(32),
            )
        )

    assert {result["health"] for result in results} == {AuthorityHealth.PROTECTED.value}
    assert {result["revision"] for result in results} == {4}
