"""Select publisher metadata from the protected active pack record."""

from __future__ import annotations

from ..native_policy_snapshot_constants import NativePolicySnapshotError
from .activation_store import header_for_store


def program_authority(store, verifier_key, binding=None):
    """Read only the bounded authenticated header while a publisher holds a lease."""
    header = header_for_store(store, verifier_key)
    if header is None:
        return None
    if binding is not None and any(
        binding.get(name) != header[name] for name in ("program_digest", "catalog_digest", "trust_digest")
    ):
        raise NativePolicySnapshotError("native_command_pack_projection_mismatch")
    return header["program_digest"]


def capture(store):
    """Materialize cached metadata before acquiring the control mutation lease."""
    from ..native_command_control_binding import load_native_command_program_metadata
    from ..runtime.generated_command_catalog import GeneratedCommandCatalog
    from .activation_store import read

    committed = read(store)
    if committed is None:
        from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

        return load_native_command_program_metadata(), BUILT_IN_COMMAND_EXTENSION_REGISTRY, None
    return committed.metadata, GeneratedCommandCatalog.from_prepared_packs(committed), committed.record_digest


def require_current(store, verifier_key, expected_digest):
    """Reject a captured catalog if another process activated a different record."""
    from .activation_store import _row

    with store._connect() as connection:
        exists = connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_control_schema_migration'"
        ).fetchone()
        row = _row(connection) if exists else None
    if row is not None:
        from . import activation_baseline

        if activation_baseline.is_baseline(row["record_json"]):
            activation_baseline.verify(row, verifier_key)
            row = None
    observed = None if row is None else row["record_digest"]
    if observed != expected_digest:
        raise NativePolicySnapshotError("native_command_pack_projection_changed")
    # Reauthenticate even when an untrusted database retains the same digest.
    if row is not None:
        from .activation_record import verify_header

        header = verify_header(row["record_json"], row["record_digest"], row["record_mac"], key=verifier_key)
        if header["revision"] != row["revision"]:
            raise NativePolicySnapshotError("native_command_pack_revision_invalid")
