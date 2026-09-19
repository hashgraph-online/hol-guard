"""Keep initial authorization completion bound to its committed local connection."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..runtime.sync_auth_handoff import hold_sync_auth_handoff, selected_sync_auth_handoff
from ..store import GuardStore

CONNECT_CONNECTION_KEY = "_guard_connect_connection"


def take_connect_connection(payload: dict[str, object]) -> OAuthConnectionSnapshot | None:
    value = payload.pop(CONNECT_CONNECTION_KEY, None)
    if isinstance(value, OAuthConnectionSnapshot):
        return value
    if payload.get("status") == "connected" and payload.get("connect_mode") in {"browser_oauth", "device_code"}:
        raise RuntimeError("The authorized connection was not captured.")
    return None


@contextmanager
def hold_connect_connection(store: GuardStore, expected: OAuthConnectionSnapshot | None) -> Iterator[None]:
    if expected is None:
        yield
        return
    with store.hold_oauth_credential_lock():
        store._require_oauth_connection_unlocked(expected)
        yield


@contextmanager
def hold_connect_sync(
    store: GuardStore, context: dict[str, object] | None, expected: OAuthConnectionSnapshot | None
) -> Iterator[None]:
    with hold_connect_connection(store, expected):
        if expected is not None and context is None:
            raise RuntimeError("The authorized sync context is unavailable.")
    if context is None:
        yield
    else:
        with hold_sync_auth_handoff(store, context, expected):
            if expected is not None and selected_sync_auth_handoff(store, context) != expected:
                raise RuntimeError("The authorized sync context is unavailable.")
            yield
