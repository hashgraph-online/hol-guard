"""Protected activation slot. Callers own approval and the SQL transaction."""

from __future__ import annotations

from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY, NativePolicySnapshotError
from ..store_extension_control_authority_schema import (
    PACK_ACTIVATION_SCHEMA_VERSION,
    extension_control_schema_marker_is_compatible,
)
from . import activation_baseline, lifecycle
from .activation_record import open_record, verify_header
from .state_paths import resolved_guard_home


def directory_for_store(store):
    # The prefix above the Guard home is resolved once so that a host which
    # reaches it through a symlink -- /home -> var/home, a relocated home
    # directory, a Windows profile behind a directory symlink -- still yields a
    # path every checked_path below here accepts. See state_paths.
    return resolved_guard_home(store.guard_home) / NATIVE_RUNTIME_STATE_DIRECTORY / "command-packs"


def prepare_directory_for_store(store):
    """Provision the private native state parent before creating pack caches."""
    from ..native_policy_snapshot_windows_support import _runtime_state_directory

    return _runtime_state_directory(resolved_guard_home(store.guard_home)) / "command-packs"


_SLOT_FIELDS = ("revision", "record_json", "record_digest", "record_mac", "recorded_at")
_SLOT_ERRORS = {
    "schema_invalid": "native_command_pack_schema_invalid",
    "missing": "native_command_pack_activation_missing",
}


def read_slot(store):
    """The stored activation slot, read by the native store, or None before the pack schema.

    The row is returned unauthenticated; callers verify it with their key.
    The native read decides the state. This only turns its four states into
    the errors the Python callers already raise and refuses any other answer
    shape, because the record it hands on gates which command packs run.
    """
    method = "read_command_pack_activation"
    answer = store._native_store_call(method, {})
    state = answer.get("state") if isinstance(answer, dict) else None
    if not isinstance(state, str):
        raise NativePolicySnapshotError(f"native {method} returned no answer")
    if state == "absent" and set(answer) == {"state"}:
        return None
    if state in _SLOT_ERRORS and set(answer) == {"state"}:
        raise NativePolicySnapshotError(_SLOT_ERRORS[state])
    row = answer.get("row") if state == "present" and set(answer) == {"state", "row"} else None
    if not isinstance(row, dict) or set(row) != set(_SLOT_FIELDS) or not _slot_types(row):
        raise NativePolicySnapshotError(f"native {method} returned no answer")
    return row


def _slot_types(row):
    revision = row["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        return False
    return all(isinstance(row[name], str) for name in _SLOT_FIELDS[1:])


def _row(connection):
    marker = connection.execute(
        "select version, checksum from extension_control_schema_migration where singleton=1"
    ).fetchone()
    if marker is None or not extension_control_schema_marker_is_compatible(marker["version"], marker["checksum"]):
        raise NativePolicySnapshotError("native_command_pack_schema_invalid")
    if marker["version"] < PACK_ACTIVATION_SCHEMA_VERSION:
        return None
    value = connection.execute("""select * from extension_command_pack_activation where singleton=1
        and length(cast(record_json as blob)) between 1 and 65536
        and length(record_digest)=64 and length(record_mac)=64""").fetchone()
    if value is None:
        raise NativePolicySnapshotError("native_command_pack_activation_missing")
    return value


@lifecycle.one_runtime
def read(store):
    """Authenticate outside mutation locks; this may read cached metadata pages."""
    row = read_slot(store)
    if row is None:
        return None
    from ..native_command_control_authority_store import _key

    if activation_baseline.is_baseline(row["record_json"]):
        activation_baseline.verify(row, _key(store))
        return None
    result = open_record(
        row["record_json"],
        row["record_digest"],
        row["record_mac"],
        key=_key(store),
        directory=directory_for_store(store),
    )
    if result.record()["revision"] != row["revision"]:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    return result


@lifecycle.one_runtime
def header_for_store(store, verifier_key):
    """Small authenticated recheck; never materialize a catalog under a lease."""
    row = read_slot(store)
    if row is None:
        return None
    if activation_baseline.is_baseline(row["record_json"]):
        return activation_baseline.verify(row, verifier_key)
    value = verify_header(row["record_json"], row["record_digest"], row["record_mac"], key=verifier_key)
    if value["revision"] != row["revision"]:
        raise NativePolicySnapshotError("native_command_pack_revision_invalid")
    return value
