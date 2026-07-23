"""Local trust backend selection and passive status resolution."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .daemon.discovery import load_authenticated_daemon_state
from .daemon.manager import load_guard_daemon_url
from .local_trust_contract import (
    POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,
    POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE,
    POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE,
    LocalTrustMode,
    TrustBackend,
    TrustBackendUnavailableError,
    TrustStatus,
    degraded_reason_for_backend_error,
    run_trust_backend_check,
    select_trust_backend,
)
from .store import (
    EncryptedFileSecretStore,
    FallbackSecretStore,
    GuardStore,
    SystemKeyringSecretStore,
)

PASSIVE_TRUST_TIMEOUT_SECONDS = 0.25


def macos_native_backend_supported(store: GuardStore) -> bool:
    secret_store = getattr(store, "_policy_integrity_secret_store", None)
    if isinstance(secret_store, FallbackSecretStore):
        secret_store = secret_store.primary
    return (
        sys.platform == "darwin"
        and isinstance(secret_store, SystemKeyringSecretStore)
        and secret_store._supports_native_macos_security_reads()
    )


def local_vault_backend_supported(store: GuardStore | None) -> bool:
    if store is None:
        return True
    secret_store = getattr(store, "_policy_integrity_secret_store", None)
    if isinstance(secret_store, FallbackSecretStore):
        secret_store = secret_store.fallback
    return isinstance(secret_store, EncryptedFileSecretStore)


def _degraded_safe_status(*, backend: str, reason: str, setup_available: bool = False) -> TrustStatus:
    return TrustStatus(
        runtime_protection="degraded",
        remembered_rules="disabled_degraded",
        cloud_policies="setup_unavailable",
        backend=backend,
        degraded_reasons=(reason,),
        setup_available=setup_available,
    )


class _DegradedSafeTrustBackend:
    name = "degraded-safe"
    priority = 0
    supported = True
    passive_no_ui_safe = True

    def status(self) -> TrustStatus:
        return _degraded_safe_status(backend=self.name, reason="trust_backend_unavailable")

    def sign(self, payload: bytes) -> str:
        raise TrustBackendUnavailableError("degraded_safe_backend_has_no_signing_material")

    def verify(self, payload: bytes, signature: str) -> bool:
        del payload, signature
        return False

    def setup(self) -> TrustStatus:
        return self.status()

    def revoke(self) -> TrustStatus:
        return self.status()


class _MacOSNativeTrustBackend:
    name = "macos-native"
    priority = 100

    def __init__(self, store: GuardStore | None = None, *, guard_home: Path | None = None) -> None:
        self._store = store
        self._guard_home = store.guard_home if store is not None else guard_home
        self.supported = sys.platform == "darwin"
        self.passive_no_ui_safe = (
            macos_native_backend_supported(store)
            if store is not None
            else self.supported and SystemKeyringSecretStore._supports_native_macos_security_reads()
        )

    def status(self) -> TrustStatus:
        if self._guard_home is None or load_guard_daemon_url(self._guard_home) is None:
            return _degraded_safe_status(
                backend=self.name,
                reason=POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE,
                setup_available=True,
            )
        if self._store is not None:
            state: object = self._store.get_cached_policy_integrity_state()
        else:
            daemon_state = load_authenticated_daemon_state(self._guard_home)
            state = daemon_state.get("trust_status") if isinstance(daemon_state, dict) else None
        if not isinstance(state, dict):
            return _degraded_safe_status(
                backend=self.name,
                reason=POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE,
                setup_available=True,
            )
        return TrustStatus.from_policy_integrity_state(state)

    def sign(self, payload: bytes) -> str:
        raise TrustBackendUnavailableError("macos_native_backend_signing_is_managed_by_guard_store")

    def verify(self, payload: bytes, signature: str) -> bool:
        del payload, signature
        return False

    def setup(self) -> TrustStatus:
        raise TrustBackendUnavailableError("macos_native_backend_setup_is_managed_by_guard_store")

    def revoke(self) -> TrustStatus:
        raise TrustBackendUnavailableError("macos_native_backend_reset_is_managed_by_guard_store")


class _LocalVaultTrustBackend:
    name = "local-vault"
    priority = 110
    passive_no_ui_safe = True

    def __init__(self, store: GuardStore | None = None, *, guard_home: Path | None = None) -> None:
        self._store = store
        self._guard_home = store.guard_home if store is not None else guard_home
        self.supported = local_vault_backend_supported(store)

    def status(self) -> TrustStatus:
        if self._store is not None:
            state: object = self._store.get_cached_policy_integrity_state()
        elif self._guard_home is not None:
            daemon_state = load_authenticated_daemon_state(self._guard_home)
            state = daemon_state.get("trust_status") if isinstance(daemon_state, dict) else None
        else:
            state = None
        if not isinstance(state, dict):
            return _degraded_safe_status(
                backend=self.name,
                reason=POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE,
                setup_available=True,
            )
        return TrustStatus.from_policy_integrity_state(state)

    def sign(self, payload: bytes) -> str:
        raise TrustBackendUnavailableError("local_vault_signing_is_managed_by_guard_store")

    def verify(self, payload: bytes, signature: str) -> bool:
        del payload, signature
        return False

    def setup(self) -> TrustStatus:
        raise TrustBackendUnavailableError("local_vault_setup_is_managed_by_guard_store")

    def revoke(self) -> TrustStatus:
        raise TrustBackendUnavailableError("local_vault_reset_is_managed_by_guard_store")


@dataclass(frozen=True)
class ResolvedTrustState:
    mode: LocalTrustMode
    backend_requested: str
    backend_selected: str
    backend_supported: bool
    passive_no_ui_safe: bool
    trust_status: TrustStatus


def _trust_backends(store: GuardStore | None, *, guard_home: Path | None = None) -> tuple[TrustBackend, ...]:
    return (
        _LocalVaultTrustBackend(store, guard_home=guard_home),
        _MacOSNativeTrustBackend(store, guard_home=guard_home),
        _DegradedSafeTrustBackend(),
    )


def _backend_by_name(
    store: GuardStore | None,
    backend_requested: str,
    *,
    guard_home: Path | None = None,
) -> TrustBackend:
    backends = {backend.name: backend for backend in _trust_backends(store, guard_home=guard_home)}
    return backends.get(backend_requested, _DegradedSafeTrustBackend())


def _trust_mode_for_backend(
    trust_status: TrustStatus,
    *,
    backend_requested: str,
    backend_selected: str,
    backend_supported: bool,
    passive_no_ui_safe: bool,
) -> LocalTrustMode:
    if trust_status.runtime_protection == "protected" and trust_status.remembered_rules == "enforced":
        return "protected"
    if backend_requested != "auto" and not backend_supported:
        return "unsupported"
    if backend_selected == "macos-native" and passive_no_ui_safe and trust_status.setup_available:
        return "setup_required"
    return "degraded_safe"


def resolve_passive_trust_state(
    store: GuardStore | None = None,
    *,
    guard_home: Path | None = None,
    backend_requested: str,
    timeout_seconds: float = PASSIVE_TRUST_TIMEOUT_SECONDS,
) -> ResolvedTrustState:
    if backend_requested == "auto":
        selected = (
            select_trust_backend(_trust_backends(store, guard_home=guard_home), passive=True)
            or _DegradedSafeTrustBackend()
        )
    else:
        selected = _backend_by_name(store, backend_requested, guard_home=guard_home)
    timeout_result = _degraded_safe_status(
        backend=selected.name,
        reason=POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT,
        setup_available=bool(selected.name == "macos-native" and selected.supported and selected.passive_no_ui_safe),
    )
    trust_status = run_trust_backend_check(
        selected.status,
        timeout_seconds=timeout_seconds,
        timeout_result=timeout_result,
        on_error=lambda error: _degraded_safe_status(
            backend=selected.name,
            reason=degraded_reason_for_backend_error(error),
            setup_available=bool(
                selected.name == "macos-native" and selected.supported and selected.passive_no_ui_safe
            ),
        ),
    )
    return ResolvedTrustState(
        mode=_trust_mode_for_backend(
            trust_status,
            backend_requested=backend_requested,
            backend_selected=selected.name,
            backend_supported=selected.supported,
            passive_no_ui_safe=selected.passive_no_ui_safe,
        ),
        backend_requested=backend_requested,
        backend_selected=selected.name,
        backend_supported=selected.supported,
        passive_no_ui_safe=selected.passive_no_ui_safe,
        trust_status=trust_status,
    )


__all__ = [
    "PASSIVE_TRUST_TIMEOUT_SECONDS",
    "ResolvedTrustState",
    "local_vault_backend_supported",
    "macos_native_backend_supported",
    "resolve_passive_trust_state",
]
