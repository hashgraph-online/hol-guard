"""Authenticated legacy baseline retained while the first pack commit is pending."""

from __future__ import annotations

from ..runtime.extension_control_authority import authenticated_record, verify_authenticated_record
from .authority import DIGEST
from .pack_store import decode

SCHEMA = "guard.command-pack-legacy-baseline.v1"
PURPOSE = "command-pack-legacy-baseline.v1"


def is_baseline(data):
    if not isinstance(data, str) or not 0 < len(data.encode("utf-8")) <= 64 * 1024:
        raise ValueError("activation record exceeds byte budget")
    value = decode(data.encode())
    return isinstance(value, dict) and value.get("schema") == SCHEMA


def verify(row, key):
    value = verify_authenticated_record(
        row["record_json"],
        expected_digest=row["record_digest"],
        expected_mac=row["record_mac"],
        key=key,
        purpose=PURPOSE,
    )
    if (
        set(value)
        != {
            "authority_schema_version",
            "purpose",
            "schema",
            "revision",
            "program_digest",
            "catalog_digest",
            "trust_digest",
        }
        or value["schema"] != SCHEMA
        or type(value["revision"]) is not int
        or value["revision"] != 0
        or row["revision"] != 0
    ):
        raise ValueError("legacy activation baseline invalid")
    for name in ("program_digest", "catalog_digest", "trust_digest"):
        candidate = value[name]
        if not isinstance(candidate, str) or DIGEST.fullmatch(candidate) is None:
            raise ValueError("legacy activation baseline digest invalid")
    return value


def reserve_legacy_baseline(store, connection, metadata, *, key, recorded_at):
    from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
    from ..store_extension_control_authority_schema import ensure_extension_control_authority_schema

    require_exclusive_command_control_mutation_lease(store.guard_home)
    marker = connection.execute("select version from extension_control_schema_migration where singleton=1").fetchone()
    if marker is not None and marker["version"] == 5:
        row = connection.execute("select * from extension_command_pack_activation where singleton=1").fetchone()
        if row is None:
            raise ValueError("retained pack activation is missing")
        if is_baseline(row["record_json"]):
            verify(row, key)
        return
    ensure_extension_control_authority_schema(connection, activate_packs=True)
    if connection.execute("select 1 from extension_command_pack_activation where singleton=1").fetchone():
        return
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "revision": 0,
        **{name: getattr(metadata, name) for name in ("program_digest", "catalog_digest", "trust_digest")},
    }
    data, digest, mac = authenticated_record(payload, key=key, purpose=PURPOSE)
    connection.execute(
        "insert into extension_command_pack_activation values (1,0,?,?,?,?)", (data, digest, mac, recorded_at)
    )
