"""Map Guard Cloud pairing gaps onto a named remaining restore step."""

from __future__ import annotations

from pathlib import Path

from .runtime.runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError
from .store import GuardStore
from .supply_chain_repair import SupplyChainRepairDeferredError


def _deferred_cloud_error(error: BaseException) -> SupplyChainRepairDeferredError:
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
    from .daemon.server import (
        _resolve_guard_sync_auth_context,
        _sync_supply_chain_cloud_state_with_optional_auth_context,
    )

    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        raise _deferred_cloud_error(error) from error
    try:
        return _sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            auth_context,
            workspace_dir=workspace_dir,
        )
    except SupplyChainRepairDeferredError:
        raise
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError) as error:
        raise _deferred_cloud_error(error) from error


__all__ = ["repair_sync_intelligence"]
