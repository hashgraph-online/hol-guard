"""The committed extension-control snapshot, read by the native store.

Recovery asks two things of the snapshot before it touches the authority:
whether a committed row is there, and which layers it holds so a reset can
report the controls it drops. The resident answers both after the schema
check; nothing here opens a connection.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

from .native_extension_control_schema import extension_control_schema_compatible

_METHOD: Final = "extension_control_snapshot_layers"


class SnapshotLayers:
    """Whether a committed snapshot row exists, and its layers when they are text."""

    __slots__ = ("layers_json", "present")

    def __init__(self, *, present: bool, layers_json: str | None) -> None:
        self.present = present
        self.layers_json = layers_json


def extension_control_snapshot_layers(store: Any) -> SnapshotLayers:
    """Check the schema, then read the committed snapshot's layers natively.

    A malformed answer raises ``sqlite3.DatabaseError`` instead of reading as
    a missing snapshot, which would send recovery down the restore path.
    """

    _ = extension_control_schema_compatible(store)
    answer = store._native_store_call(_METHOD, {})
    if not isinstance(answer, dict) or set(answer) != {"snapshot"}:
        raise sqlite3.DatabaseError(f"native {_METHOD} returned no answer")
    snapshot = answer["snapshot"]
    if snapshot is None:
        return SnapshotLayers(present=False, layers_json=None)
    if not isinstance(snapshot, dict) or set(snapshot) != {"layers_json"}:
        raise sqlite3.DatabaseError(f"native {_METHOD} returned no answer")
    layers = snapshot["layers_json"]
    if layers is not None and not isinstance(layers, str):
        raise sqlite3.DatabaseError(f"native {_METHOD} returned no answer")
    return SnapshotLayers(present=True, layers_json=layers)


__all__ = ["SnapshotLayers", "extension_control_snapshot_layers"]
