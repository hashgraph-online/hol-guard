"""Map Guard Cloud pairing gaps onto a named remaining restore step."""

from __future__ import annotations

from pathlib import Path

from .runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncEndpointUntrustedError,
    GuardSyncNotConfiguredError,
)
from .store import GuardStore
from .supply_chain_repair_errors import SupplyChainRepairDeferredError


def _deferred_cloud_error(error: BaseException) -> SupplyChainRepairDeferredError:
    if isinstance(error, GuardSyncEndpointUntrustedError):
        raise error
    if isinstance(error, GuardSyncAuthorizationExpiredError):
        return SupplyChainRepairDeferredError(
            code="guard_cloud_reconnect_required",
            message="Guard Cloud sign-in expired. Reconnect to refresh safety intelligence.",
            action="connect",
        )
    if isinstance(error, GuardSyncNotConfiguredError):
        return SupplyChainRepairDeferredError(
            code="guard_cloud_connect_required",
            message=(
                "Connect Guard Cloud to refresh safety intelligence. "
                "Package protection on this device can stay on without it."
            ),
            action="connect",
        )
    raise error


def repair_sync_intelligence(
    store: GuardStore,
    *,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    del workspace_dir
    from .daemon.server import _resolve_guard_sync_auth_context
    from .local_supply_chain import sync_supply_chain_bundle

    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except GuardSyncEndpointUntrustedError:
        raise
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        raise _deferred_cloud_error(error) from error
    try:
        # Restore is a local package-protection workflow. Workspace audits can
        # take minutes across managed projects, so they must stay in explicit
        # sync/audit actions and never hold the repair response open.
        return sync_supply_chain_bundle(store, auth_context=auth_context) or {}
    except SupplyChainRepairDeferredError:
        raise
    except GuardSyncEndpointUntrustedError:
        raise
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        raise _deferred_cloud_error(error) from error


__all__ = ["repair_sync_intelligence"]
