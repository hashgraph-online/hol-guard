"""Reuse of the resident's settled extension-control authority replies.

Every ``extension_control_authority`` op is a pure function of its request and,
for the store ops, of the committed database. One hook reads the same
authority from several places, so a settled reply is kept and served again
while both are unchanged, instead of asking the resident once per reader.

The authority's inputs are unchanged while the database's file identity and
its authority epoch are unchanged. Triggers move the epoch on every write to a
row the resident's read depends on, from any connection in any process, while
the hook's own receipts and evidence leave it alone; a dropped or rewritten
trigger reads as no epoch, and nothing is served. A replaced file has a new
identity, and a connection held open for the purpose keeps the old inode from
being reused. Only replies that settled (a view, a manifest, an anchor) are
kept; a fault, a writer action or plan, a request for the full manifest or
recorded migration events always go back to the resident.

Holding a connection open keeps Windows from deleting or replacing the
database, so there nothing is kept and every read asks the resident.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import sys
from collections import OrderedDict
from pathlib import Path
from threading import Lock

from .store_extension_control_authority_epoch import extension_control_authority_epoch

_STORE_OPS = frozenset(
    {"read", "read_composed", "sync_manifest", "compose_managed", "load_manifest", "validate_chain", "history"}
)
# Ops that read nothing but their request. A writer's plan is never kept: it
# answers one write, and the write it leads to changes what the next plan sees.
_PURE_OPS = frozenset({"anchor", "managed_activation", "managed_revision"})
# A reply settled with ``allow_migration`` needed no migration, so a caller
# that may not migrate gets the same reply. The converse does not hold.
_MIGRATING_OPS = frozenset({"read", "read_composed", "sync_manifest"})
_LIMIT = 32

_lock = Lock()
_sentinels: dict[str, tuple[int, tuple[int, int], sqlite3.Connection]] = {}
_entries: OrderedDict[str, tuple[bool, dict[str, object]]] = OrderedDict()


def _store_token(store_path: str) -> tuple[int, int, int] | None:
    """The database's identity and authority epoch, or None when unknown."""

    try:
        status = os.stat(store_path)
    except OSError:
        return None
    identity = (status.st_dev, status.st_ino)
    pid = os.getpid()
    held = _sentinels.get(store_path)
    try:
        if held is None or held[0] != pid or held[1] != identity:
            if held is not None and held[0] == pid:
                held[2].close()
            connection = sqlite3.connect(
                f"{Path(store_path).as_uri()}?mode=ro", uri=True, check_same_thread=False, isolation_level=None
            )
            held = (pid, identity, connection)
            _sentinels[store_path] = held
        epoch = extension_control_authority_epoch(held[2])
    except sqlite3.Error:
        _sentinels.pop(store_path, None)
        return None
    if epoch is None:
        return None
    return (*identity, epoch)


def _memo_key(wire: dict[str, object]) -> tuple[str, bool] | None:
    op = wire.get("op")
    if sys.platform == "win32" or op not in _STORE_OPS | _PURE_OPS:
        return None
    fields = {name: value for name, value in wire.items() if name != "request_id"}
    allow_migration = bool(fields.pop("allow_migration", False)) if op in _MIGRATING_OPS else False
    if op in _STORE_OPS:
        store_path = wire.get("store_path")
        token = _store_token(store_path) if isinstance(store_path, str) else None
        if token is None:
            return None
        fields["store_token"] = list(token)
    encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest(), allow_migration


def _settled(payload: dict[str, object]) -> bool:
    return (
        "fault" not in payload
        and "action" not in payload
        and "need" not in payload
        and not payload.get("events")
        and payload.get("manifest_write") is None
    )


def lookup(wire: dict[str, object]) -> tuple[tuple[str, bool] | None, dict[str, object] | None]:
    """The memo key for ``wire`` and the kept reply, if one serves it.

    The key is taken before the resident is asked, so a commit that lands
    while it answers leaves the kept reply under the older version.
    """

    with _lock:
        key = _memo_key(wire)
        if key is None:
            return None, None
        entry = _entries.get(key[0])
        if entry is None or (key[1] and not entry[0]):
            return key, None
        _entries.move_to_end(key[0])
        return key, copy.deepcopy(entry[1])


def keep(key: tuple[str, bool] | None, payload: dict[str, object]) -> None:
    if key is None or not _settled(payload):
        return
    with _lock:
        held = _entries.get(key[0])
        _entries[key[0]] = (key[1] or (held is not None and held[0]), copy.deepcopy(payload))
        _entries.move_to_end(key[0])
        while len(_entries) > _LIMIT:
            _entries.popitem(last=False)


__all__ = ["keep", "lookup"]
