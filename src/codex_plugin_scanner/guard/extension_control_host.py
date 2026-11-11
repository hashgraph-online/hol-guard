"""The extension-control service the native daemon answers its control routes from.

``/v1/extension-controls/*`` reads and writes run here, inside the resident
library process the native daemon keeps for calls that hold state between
requests. A preview's proof lives in this service until its apply, as it did
in the long-running daemon, so the two must reach the same process. A
short-lived call builds a fresh service; its reads answer as before and an
apply finds no proof to consume.

Startup admits the installed release, enrolls a fresh home and reads the
authority exactly as the daemon did; see ``ExtensionControlHost.start``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from .native_policy_snapshot_constants import NativePolicySnapshotError
from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .runtime.extension_control_runtime import ExtensionControlRuntime, ExtensionControlRuntimeSnapshot
from .runtime_health.background_diagnostics import failure_detail, record_background_event
from .store import GuardStore

_LOGGER = logging.getLogger(__name__)

_READS = {
    "/v1/extension-controls/catalog": "catalog",
    "/v1/extension-controls/effective": "effective",
    "/v1/extension-controls/history": "history",
}
_WRITES = {
    "/v1/extension-controls/test": "test_command",
    "/v1/extension-controls/inspect": "inspect_command",
    "/v1/extension-controls/preview": "preview",
    "/v1/extension-controls/apply": "apply",
    "/v1/extension-controls/acknowledge-degraded": "acknowledge_degraded",
    "/v1/extension-controls/recover-authority": "recover_authority",
}
REFRESH_PATH = "/v1/extension-controls/refresh"


class _InstalledAuthorityMigrationError(Exception):
    """The installed release's command-pack authority is not migrated yet."""


class ExtensionControlHost:
    """One Guard home's extension-control API, its runtime and its refresh."""

    def __init__(self, store: GuardStore) -> None:
        from .extension_controls.extension_control_api import ExtensionControlApiService

        self.store = store
        self._installed_authority_pending = False
        self._on_core_registry = False
        try:
            self._migrate_installed_authority()
            self._enroll_authority_by_default()
            from .catalog_delivery.projection import capture

            _, registry, _ = capture(store)
            view = self._startup_view(registry)
        except (_InstalledAuthorityMigrationError, NativePolicySnapshotError):
            registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
            view = store._tampered_view(registry.catalog_digest)
            self._on_core_registry = True
        self.runtime = ExtensionControlRuntime(view)
        self.api = ExtensionControlApiService(store=store, registry=registry, runtime=self.runtime)

    def _migrate_installed_authority(self) -> None:
        """Admit the installed release, or report why it cannot be admitted yet.

        A failure leaves the migration pending. The service then starts on a
        tampered authority, so every hook fails closed, and each refresh
        retries it before reading anything newer.
        """

        try:
            self.store.migrate_installed_command_pack_authority()
        except Exception as error:
            self._installed_authority_pending = True
            record_background_event("installed_authority_migration_failed", failure_detail(error))
            _LOGGER.warning("Installed command-pack authority could not be migrated: %s", error, exc_info=True)
            raise _InstalledAuthorityMigrationError from error
        self._installed_authority_pending = False

    def _enroll_authority_by_default(self) -> None:
        """Enroll a fresh install so its controls are protected without a setup step."""

        try:
            view = self.store.enroll_extension_control_authority_by_default(
                BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
            )
        except Exception as error:
            record_background_event("default_authority_enrollment_failed", failure_detail(error))
            # The redacted detail is in the background event; the log names the class only.
            _LOGGER.warning("Extension-control authority could not be enrolled by default: %s", type(error).__name__)
            return
        if view.health is not AuthorityHealth.PROTECTED:
            record_background_event("default_authority_enrollment_skipped", f"health={view.health.value}")

    def _startup_view(self, registry: CommandSafetyExtensionRegistry) -> ExtensionControlAuthorityView:
        """Read the authority without letting a busy lease stop the service.

        A lease timeout falls back to the shared lease, and only if that is
        unobtainable too does the service start on a view with no layers,
        which the next refresh replaces. Both attempts share one budget.
        """

        from .native_command_control_authority_io import (
            AUTHORITY_LOCK_TIMEOUT_SECONDS,
            NativeCommandControlAuthorityUnavailableError,
            NativeCommandControlMutationRequiredError,
        )

        deadline = time.monotonic() + AUTHORITY_LOCK_TIMEOUT_SECONDS
        with suppress(NativeCommandControlAuthorityUnavailableError):
            return self.store.read_extension_control_authority_for_registry(
                registry, lock_timeout_seconds=AUTHORITY_LOCK_TIMEOUT_SECONDS / 2
            )
        remaining = deadline - time.monotonic()
        if remaining > 0.0:
            with suppress(NativeCommandControlAuthorityUnavailableError, NativeCommandControlMutationRequiredError):
                return self.store.read_extension_control_authority_for_registry(
                    registry, read_only=True, lock_timeout_seconds=remaining
                )
        return self.store.extension_control_authority_unreadable_view(registry.catalog_digest)

    def refresh(self) -> ExtensionControlRuntimeSnapshot:
        """Recapture the active activation and rebind the API to it."""

        from .catalog_delivery.projection import capture, require_current
        from .native_command_control_authority_io import (
            NativeCommandControlAuthorityUnavailableError,
            NativeCommandControlMutationRequiredError,
            hold_command_control_authority_lock,
        )
        from .native_command_control_authority_store import _key as authority_key

        def read(*, shared: bool) -> ExtensionControlRuntimeSnapshot:
            _, registry, activation_digest = capture(self.store)
            with hold_command_control_authority_lock(self.store.guard_home, shared=shared):
                require_current(self.store, authority_key(self.store), activation_digest)
                view = self.store.read_extension_control_authority_for_registry(registry, read_only=shared)
                snapshot = self.runtime.refresh(view)
            # Serve the registry the runtime now holds a view for, so the
            # effective controls and the catalog report the same digest.
            # Rebind after the lease is released: apply() takes the API lock
            # before that lease.
            if (
                self._on_core_registry or registry.catalog_digest != self.api.catalog_digest
            ) and self.api.rebind_registry(registry, installed=snapshot):
                self._on_core_registry = False
            return snapshot

        if self._installed_authority_pending:
            try:
                self._migrate_installed_authority()
            except _InstalledAuthorityMigrationError:
                return self.runtime.current()
            self._enroll_authority_by_default()
        try:
            try:
                snapshot = read(shared=True)
            except NativeCommandControlMutationRequiredError:
                return read(shared=False)
            if snapshot.health is AuthorityHealth.RECOVERY_REQUIRED:
                # Only a writer may roll back a prepared transition a failed
                # save left behind.
                return read(shared=False)
            return snapshot
        except NativeCommandControlAuthorityUnavailableError:
            return self.runtime.current()

    def respond(self, method: str, path: str, payload: dict[str, object]) -> dict[str, object]:
        """The whole reply for one extension-control request."""

        from .extension_controls.extension_control_api import ExtensionControlApiError

        try:
            if method == "GET" and path in _READS:
                body = getattr(self.api, _READS[path])()
            elif method == "POST" and path in _WRITES:
                body = getattr(self.api, _WRITES[path])(payload)
            elif method == "POST" and path == REFRESH_PATH:
                try:
                    self.refresh()
                except Exception as error:
                    # The page that posts here has no other way forward, so
                    # record the failure and serve what the runtime holds.
                    record_background_event("extension_control_refresh_failed", failure_detail(error))
                body = self.api.effective(reread=False)
            else:
                from .library_calls import LibraryCallError

                raise LibraryCallError("invalid_arguments")
        except ExtensionControlApiError as error:
            return {"status": error.status, "body": error.to_payload(), "no_store": False}
        return {"status": 200, "body": body, "no_store": True}


_HOSTS: dict[Path, ExtensionControlHost] = {}
_HOSTS_LOCK = threading.Lock()


def host_for(store: GuardStore) -> ExtensionControlHost:
    """The host this process keeps for ``store``'s Guard home."""

    home = Path(store.guard_home)
    with _HOSTS_LOCK:
        host = _HOSTS.get(home)
        if host is None:
            host = ExtensionControlHost(store)
            _HOSTS[home] = host
        return host


def existing_host(store: GuardStore) -> ExtensionControlHost | None:
    """The host this process already keeps for ``store``'s Guard home, if any."""

    with _HOSTS_LOCK:
        return _HOSTS.get(Path(store.guard_home))


def extension_control(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """``route.extension_control``: ``{method, path, payload?}`` to a whole reply."""

    from .library_calls import LibraryCallError

    method = args.get("method")
    path = args.get("path")
    payload = args.get("payload", {})
    if method not in {"GET", "POST"} or not isinstance(path, str) or not isinstance(payload, dict):
        raise LibraryCallError("invalid_arguments")
    return host_for(store).respond(method, path, payload)


EXTENSION_CONTROL_CALLS = {"route.extension_control": extension_control}

__all__ = ["EXTENSION_CONTROL_CALLS", "ExtensionControlHost", "existing_host", "host_for"]
