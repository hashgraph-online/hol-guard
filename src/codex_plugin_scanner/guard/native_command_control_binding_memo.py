"""Reuse of the publisher's command-control binding while its inputs hold still.

The policy publisher reads the binding once a second, and again after every
database write, to notice a change another process made. Each read verifies
the runtime, opens the activation record and replays the active pack's
security through one-shot runtime calls, under the authority lock. Almost
every read finds nothing new, and together they kept a runtime process
starting several times a second and the authority lock busy for the dashboard.

A read is served again while everything it reads is unchanged: the
database's identity and authority epoch, the activation and pending pack rows,
the protected security record and both keys, the runtime files, the program
artifact and the state files beside them. Any input that cannot be read means
no reuse, so the full read reports the failure itself. A kept binding is only
served to the runtime object it refreshed, and never once it is older than
``FULL_READ_INTERVAL_SECONDS``, so anything the inputs miss (an expiry, a
cache file replaced in place) is still read within that interval.

The epoch comes from the database sentinel the authority memo holds open,
which Windows will not allow, so there every call reads in full.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime.extension_control_runtime import ExtensionControlRuntime
    from .store import GuardStore

FULL_READ_INTERVAL_SECONDS = 10.0

_lock = Lock()
_entries: dict[str, tuple[str, object, dict[str, object], float]] = {}


def _file(path: Path) -> list[int] | None:
    try:
        status = os.stat(path)
    except FileNotFoundError:
        return None
    return [status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns]


def _digest(value: object) -> str | None:
    if value is None:
        return None
    data = value if isinstance(value, bytes) else str(value).encode()
    return hashlib.sha256(data).hexdigest()


def _pack_rows(store: GuardStore) -> list[object]:
    with store._connect() as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type='table' and name in "
                "('extension_command_pack_activation', 'extension_command_pack_pending')"
            )
        }
        activation = (
            [
                list(row)
                for row in connection.execute(
                    "select revision, record_json, record_digest, record_mac from extension_command_pack_activation"
                )
            ]
            if "extension_command_pack_activation" in tables
            else None
        )
        pending = (
            [
                list(row)
                for row in connection.execute(
                    "select control_revision, record_json, record_digest, record_mac, "
                    "link_json, link_digest, link_mac "
                    "from extension_command_pack_pending order by control_revision"
                )
            ]
            if "extension_command_pack_pending" in tables
            else None
        )
    return [activation, pending]


def input_key(store: GuardStore) -> str | None:
    """A digest of everything the binding read depends on, or None."""

    if sys.platform == "win32":
        return None
    from .catalog_delivery import active_security, lifecycle
    from .catalog_delivery.activation_store import directory_for_store
    from .native_command_control_authority import AUTHORITY_FILE_NAME
    from .native_command_control_authority_store import _key
    from .native_command_control_binding import _program_path
    from .native_extension_control_authority_memo import _store_token
    from .native_policy_snapshot_windows_support import _runtime_state_directory

    try:
        token = _store_token(str(store.path))
        if token is None:
            return None
        state = _runtime_state_directory(store.guard_home)
        inputs = {
            "store": list(token),
            "packs": _pack_rows(store),
            "security": _digest(active_security.read(store)),
            "key": _digest(_key(store, create=False)),
            "authority_key": _digest(store._authority_key(required=False)),
            "runtime": lifecycle.runtime_fingerprint(),
            "files": [
                _file(path)
                for path in (
                    _program_path(),
                    state / AUTHORITY_FILE_NAME,
                    state / active_security.FILE,
                    directory_for_store(store),
                )
            ],
        }
    except Exception:  # an unreadable input means a full read, which reports it
        return None
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def lookup(
    store: GuardStore, runtime: ExtensionControlRuntime | None
) -> tuple[str | None, tuple[dict[str, object], ExtensionControlRuntime] | None]:
    """The input key for ``store`` and the kept binding, if one serves it.

    The key is taken before the full read, so a commit that lands during the
    read leaves the kept binding under the older key.
    """

    key = input_key(store)
    if key is None or runtime is None:
        return key, None
    with _lock:
        entry = _entries.get(str(store.path))
        if entry is None or entry[0] != key or entry[1] is not runtime or time.monotonic() >= entry[3]:
            return key, None
        return key, (copy.deepcopy(entry[2]), runtime)


def keep(store: GuardStore, key: str | None, binding: dict[str, object], runtime: ExtensionControlRuntime) -> None:
    if key is None:
        return
    with _lock:
        _entries[str(store.path)] = (
            key,
            runtime,
            copy.deepcopy(binding),
            time.monotonic() + FULL_READ_INTERVAL_SECONDS,
        )


def forget() -> None:
    with _lock:
        _entries.clear()


__all__ = ["FULL_READ_INTERVAL_SECONDS", "forget", "input_key", "keep", "lookup"]
