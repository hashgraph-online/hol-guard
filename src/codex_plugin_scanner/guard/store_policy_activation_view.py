"""The stored state one policy activation decides from, read through the native store.

An activation compares what it will write with what is stored, then asks the
resident to write only while every value it observed is unchanged. The values
are read in one native snapshot, as the exact stored text, because the
resident's compare-and-set compares that text byte for byte.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol


class _NativeStore(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object: ...


@dataclass(frozen=True)
class PolicyActivationView:
    """``sync_state`` text for the requested keys, the authority snapshot and the remote rows."""

    stored: Mapping[str, str | None]
    authority: tuple[int, str] | None
    remote_rows: tuple[tuple[object, ...], ...]

    def text(self, state_key: str) -> str | None:
        """The stored text, or None when absent. An unrequested key is an error."""
        return self.stored[state_key]


def _malformed() -> RuntimeError:
    return RuntimeError("Guard native store returned a malformed policy activation view.")


def read_policy_activation_view(store: _NativeStore, state_keys: Iterable[str]) -> PolicyActivationView:
    keys = list(dict.fromkeys(state_keys))
    reply = store._native_store_call("policy_activation_view", {"state_keys": keys})
    if not isinstance(reply, dict):
        raise _malformed()
    sync_state = reply.get("sync_state")
    rows = reply.get("remote_rows")
    authority = reply.get("authority")
    if not isinstance(sync_state, dict) or not isinstance(rows, list):
        raise _malformed()
    stored: dict[str, str | None] = {}
    for key in keys:
        # An absent row is an explicit null; an omitted key is a broken reply.
        if key not in sync_state:
            raise _malformed()
        value = sync_state[key]
        if value is not None and not isinstance(value, str):
            raise _malformed()
        stored[key] = value
    if not all(isinstance(row, list) for row in rows):
        raise _malformed()
    snapshot: tuple[int, str] | None = None
    if authority is not None:
        if not isinstance(authority, dict):
            raise _malformed()
        revision = authority.get("revision")
        digest = authority.get("snapshot_digest")
        if isinstance(revision, bool) or not isinstance(revision, int) or not isinstance(digest, str):
            raise _malformed()
        snapshot = (revision, digest)
    return PolicyActivationView(
        stored=stored,
        authority=snapshot,
        remote_rows=tuple(tuple(row) for row in rows),
    )
