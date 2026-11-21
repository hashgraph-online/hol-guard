"""Wake the cloud sync loop when Guard Cloud publishes a new policy.

Guard Cloud names the workspace's live policy revision on every command lease
response. The daemon's cloud sync loop otherwise fetches policy on its periodic
interval, so a version published in the dashboard would wait out that interval
before it reached this machine. Watching the revision on the lease channel the
daemon already holds open lets the loop sync as soon as the revision moves.

The revision is an opaque hint, never policy authority: it only decides when
to sync. What the sync fetches is still verified exactly as before.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore

_LOCK = threading.Lock()
_LAST_REVISION: dict[str, str | None] = {}
_WAKE_LISTENERS: dict[str, list[Callable[[], None]]] = {}
_MAX_REVISION_LENGTH = 128


def cloud_policy_store_key(store: GuardStore) -> str:
    """One key per Guard home, shared by the lease poller and the sync loop."""

    return str(store.guard_home.expanduser().resolve())


def register_cloud_policy_wake(store_key: str, listener: Callable[[], None]) -> Callable[[], None]:
    """Call ``listener`` whenever the policy revision for ``store_key`` moves."""

    with _LOCK:
        _WAKE_LISTENERS.setdefault(store_key, []).append(listener)

    def unregister() -> None:
        with _LOCK:
            listeners = _WAKE_LISTENERS.get(store_key)
            if listeners is None:
                return
            if listener in listeners:
                listeners.remove(listener)
            if not listeners:
                _WAKE_LISTENERS.pop(store_key, None)

    return unregister


def observe_cloud_policy_revision(store_key: str, response: object) -> bool:
    """Record the revision a lease response named; wake the sync loop if it moved.

    The first revision seen in a process only sets the baseline, because the
    sync loop already syncs when the daemon starts. A response from a Guard
    Cloud that does not send the field changes nothing.
    """

    if not isinstance(response, dict) or "policyRevision" not in response:
        return False
    raw = response.get("policyRevision")
    if raw is not None and (not isinstance(raw, str) or not raw or len(raw) > _MAX_REVISION_LENGTH):
        return False
    with _LOCK:
        seen = store_key in _LAST_REVISION
        previous = _LAST_REVISION.get(store_key)
        _LAST_REVISION[store_key] = raw
        moved = seen and previous != raw
        listeners = list(_WAKE_LISTENERS.get(store_key, ())) if moved else []
    for listener in listeners:
        listener()
    return moved


def reset_cloud_policy_revisions() -> None:
    """Forget every recorded revision. Tests use this between cases."""

    with _LOCK:
        _LAST_REVISION.clear()
