"""Best-effort first Cloud sync admission for daemon startup."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable

from ..store import GuardStore

QueueSync = Callable[..., dict[str, object]]
ManagedControlsPublish = Callable[..., object]
_LOGGER = logging.getLogger(__name__)


def queue_sync_with_optional_publish(
    *,
    store: GuardStore,
    queue_sync: QueueSync,
    managed_controls_publish: ManagedControlsPublish | None,
) -> dict[str, object]:
    try:
        queue_parameters = inspect.signature(queue_sync).parameters
    except (TypeError, ValueError):
        queue_parameters = {}
    if managed_controls_publish is not None and "managed_controls_publish" in queue_parameters:
        return queue_sync(store=store, managed_controls_publish=managed_controls_publish)
    return queue_sync(store=store)


def maybe_queue_first_cloud_sync(
    *,
    store: GuardStore,
    queue_sync: QueueSync,
    repair_connect: Callable[[GuardStore], object],
    now: Callable[[], str],
    managed_controls_publish: ManagedControlsPublish | None = None,
) -> dict[str, object] | None:
    if store.get_cloud_sync_profile() is None:
        try:
            repair_connect(store)
        except Exception as error:
            _LOGGER.warning("Guard Cloud connection repair failed: %s", type(error).__name__)
            return None
    if store.get_cloud_sync_profile() is None:
        return None
    oauth_health = store.get_oauth_local_credential_health()
    if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded":
        try:
            repair_connect(store)
        except Exception as error:
            _LOGGER.warning("Guard Cloud credential repair failed: %s", type(error).__name__)
            return None
        oauth_health = store.get_oauth_local_credential_health()
        if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded":
            return None
    latest_state = store.get_effective_guard_connect_state(now=now())
    if latest_state is None:
        return None
    if str(latest_state.get("status") or "") != "connected":
        return None
    if str(latest_state.get("milestone") or "") != "first_sync_pending":
        return None
    return queue_sync_with_optional_publish(
        store=store,
        queue_sync=queue_sync,
        managed_controls_publish=managed_controls_publish,
    )


__all__ = ["maybe_queue_first_cloud_sync", "queue_sync_with_optional_publish"]
