"""Protected activation slot. Callers own approval and the SQL transaction."""

from __future__ import annotations

from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY, NativePolicySnapshotError
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
_SLOT_REFUSALS = frozenset({"native_command_pack_schema_invalid", "native_command_pack_activation_missing"})


def read_slot(store):
    """The stored activation slot, read by the native store, or None before the pack schema.

    The row is returned unauthenticated; callers verify it with their key.
    The native read decides the state and names the error code of a slot the
    callers must refuse. This raises that code and refuses any other answer
    shape, because the record it hands on gates which command packs run.
    """
    method = "read_command_pack_activation"
    answer = store._native_store_call(method, {})
    state = answer.get("state") if isinstance(answer, dict) else None
    if not isinstance(state, str):
        raise NativePolicySnapshotError(f"native {method} returned no answer")
    if state == "absent" and set(answer) == {"state"}:
        return None
    code = answer.get("code") if state == "refused" and set(answer) == {"state", "code"} else None
    if isinstance(code, str) and code in _SLOT_REFUSALS:
        raise NativePolicySnapshotError(code)
    row = answer.get("row") if state == "present" and set(answer) == {"state", "row"} else None
    if not isinstance(row, dict) or set(row) != set(_SLOT_FIELDS) or not _slot_types(row):
        raise NativePolicySnapshotError(f"native {method} returned no answer")
    return row


_PENDING_FIELDS = frozenset({"record_json", "record_digest", "record_mac"})


def pending_records(store):
    """The pending activation records, read by the native store, in revision order.

    Each record is returned unauthenticated for the lifecycle op to verify.
    The native store pages the read; every page is read before this returns.
    Any other answer shape, or a record field that is not text, is refused
    rather than dropped, because a dropped record would let cleanup evict a
    pack a pending activation still needs.
    """
    method = "list_command_pack_pending_records"
    records = []
    args = {}
    while True:
        items, after = _pending_page(store._native_store_call(method, args), method)
        records.extend(items)
        if after is None:
            return records
        # Every page names a later revision, so the walk always ends.
        if not items or ("after_revision" in args and after <= args["after_revision"]):
            raise NativePolicySnapshotError(f"native {method} returned no answer")
        args = {"after_revision": after}


def _pending_page(answer, method):
    """One page of pending records and the revision the next page starts after."""
    fields = set(answer) if isinstance(answer, dict) else None
    items = answer.get("items") if fields == {"items", "next"} else None
    after = answer.get("next") if fields == {"items", "next"} else None
    if not isinstance(items, list) or not (after is None or _is_revision(after)):
        raise NativePolicySnapshotError(f"native {method} returned no answer")
    for item in items:
        if (
            not isinstance(item, dict)
            or set(item) != _PENDING_FIELDS
            or not all(isinstance(item[name], str) for name in _PENDING_FIELDS)
        ):
            raise NativePolicySnapshotError(f"native {method} returned no answer")
    return items, after


def _is_revision(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _slot_types(row):
    revision = row["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        return False
    return all(isinstance(row[name], str) for name in _SLOT_FIELDS[1:])


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
