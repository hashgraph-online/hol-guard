"""Bounded reuse of a successfully resolved sync context within one call scope."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..cli.oauth_client import GuardDpopKeyMaterial
from ..oauth_connection_authority import OAuthConnectionSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore

_ContextValues = tuple[str, str, str, tuple[tuple[str, str], ...], str, str]


def _context_values(context: dict[str, object]) -> _ContextValues | None:
    if type(context) is not dict or any(type(name) is not str for name in context):
        return None
    if set(context) != {"sync_url", "access_token", "dpop_key_material"}:
        return None
    sync_url = context["sync_url"]
    access_token = context["access_token"]
    key = context["dpop_key_material"]
    if type(sync_url) is not str or type(access_token) is not str:
        return None
    if type(key) is not GuardDpopKeyMaterial:
        return None
    if type(key.private_key_pem) is not str or type(key.public_jwk_thumbprint) is not str:
        return None
    if type(key.algorithm) is not str:
        return None
    if type(key.public_jwk) is not dict:
        return None
    if not all(type(name) is str and type(value) is str for name, value in key.public_jwk.items()):
        return None
    return (
        sync_url,
        access_token,
        key.private_key_pem,
        tuple(sorted(key.public_jwk.items())),
        key.public_jwk_thumbprint,
        key.algorithm,
    )


@dataclass
class _ScopeLifetime:
    active: bool = True


@dataclass(frozen=True, repr=False)
class _SyncAuthHandoff:
    store: GuardStore
    context: dict[str, object]
    values: _ContextValues
    connection: OAuthConnectionSnapshot
    lifetime: _ScopeLifetime


_HANDOFF: ContextVar[_SyncAuthHandoff | None] = ContextVar("guard_sync_auth_handoff", default=None)


@contextmanager
def hold_sync_auth_handoff(
    store: GuardStore,
    context: dict[str, object],
    connection: OAuthConnectionSnapshot | None,
) -> Iterator[None]:
    """Scope an observed resolver result; an unbound scope shadows any outer one."""
    values = _context_values(context)
    selected = (
        None
        if connection is None or values is None
        else _SyncAuthHandoff(store, context, values, connection, _ScopeLifetime())
    )
    token = _HANDOFF.set(selected)
    try:
        yield
    finally:
        if selected is not None:
            selected.lifetime.active = False
        _HANDOFF.reset(token)


def selected_sync_auth_handoff(store: GuardStore, context: dict[str, object] | None) -> OAuthConnectionSnapshot | None:
    """Return only the exact scoped result for the caller to revalidate."""
    selected = _HANDOFF.get()
    if selected is None or not selected.lifetime.active:
        return None
    if selected.store is not store or selected.context is not context:
        return None
    if context is None or _context_values(context) != selected.values:
        return None
    return selected.connection
