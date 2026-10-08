"""Pure authenticated native control mutation-fence and recovery contracts."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import cast

from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError

AUTHORITY_SCHEMA = "guard.native-command-control-authority.v1"
RECOVERY_SCHEMA = "guard.native-command-control-recovery.v1"
AUTHORITY_FILE_NAME = "command-control-authority.v1.json"
AUTHORITY_LOCK_NAME = "extension-control-authority.lock"
AUTHORITY_MAX_BYTES = 4096
AUTHORITY_DOMAIN = b"hol-guard.native-command-control-authority.v1\0"
AUTHORITY_KEY_DOMAIN = b"hol-guard.native-command-control-authority-key.v1\0"
FLOOR_LINK_DOMAIN = b"hol-guard.native-command-control-floor-link.v1\0"
ZERO_DIGEST = "0" * 64
MAX_REVISION = (1 << 64) - 1
AUTHORITY_BINDING_FIELDS = frozenset({"epoch", "mutation_revision", "authority_key_id", "recovery"})
_RECORD_FIELDS = AUTHORITY_BINDING_FIELDS | {"schema", "phase", "effective_digest", "mac"}
_RECOVERY_FIELDS = frozenset(
    {
        "schema",
        "previous_epoch",
        "previous_mutation_revision",
        "previous_authority_key_id",
        "previous_floor_digest",
        "nonce",
    }
)


def _invalid() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_command_control_authority_invalid")


def _mapping(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _invalid()
    return value


def _revision(value: object, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= MAX_REVISION:
        raise _invalid()
    return value


def validate_authority_binding(value: object) -> None:
    binding = _mapping(value, AUTHORITY_BINDING_FIELDS)
    epoch = _revision(binding["epoch"])
    revision = _revision(binding["mutation_revision"])
    if not _valid_digest_v3(binding["authority_key_id"]):
        raise _invalid()
    if binding["recovery"] is not None:
        recovery = _mapping(binding["recovery"], _RECOVERY_FIELDS)
        if recovery["schema"] != RECOVERY_SCHEMA:
            raise _invalid()
        if _revision(recovery["previous_epoch"], minimum=0) >= epoch:
            raise _invalid()
        if _revision(recovery["previous_mutation_revision"], minimum=0) >= revision:
            raise _invalid()
        for name in ("previous_authority_key_id", "previous_floor_digest", "nonce"):
            if not _valid_digest_v3(recovery[name]):
                raise _invalid()


def authority_binding(record: Mapping[str, object]) -> dict[str, object]:
    binding = {name: record[name] for name in AUTHORITY_BINDING_FIELDS}
    validate_authority_binding(binding)
    return binding


def authority_key_id(key: bytes | None) -> str:
    if key is None:
        return ZERO_DIGEST
    if not isinstance(key, bytes) or len(key) != 32:
        raise _invalid()
    return hashlib.sha256(AUTHORITY_KEY_DOMAIN + key).hexdigest()


def floor_link_digest(floor: object) -> str:
    return hashlib.sha256(FLOOR_LINK_DOMAIN + _canonical_json_bytes_v3(floor)).hexdigest()


def _validate_record(value: object) -> Mapping[str, object]:
    record = _mapping(value, _RECORD_FIELDS)
    validate_authority_binding(authority_binding(record))
    phase = record["phase"]
    if record["schema"] != AUTHORITY_SCHEMA or phase not in ("closed", "committed"):
        raise _invalid()
    if phase == "closed":
        if record["effective_digest"] is not None:
            raise _invalid()
    elif not _valid_digest_v3(record["effective_digest"]):
        raise _invalid()
    if not _valid_digest_v3(record["mac"]):
        raise _invalid()
    return record


def _record_mac(record: Mapping[str, object], verifier_key: bytes) -> str:
    if not isinstance(verifier_key, bytes) or len(verifier_key) != 32:
        raise _invalid()
    body = {name: value for name, value in record.items() if name != "mac"}
    return hmac.new(verifier_key, AUTHORITY_DOMAIN + _canonical_json_bytes_v3(body), hashlib.sha256).hexdigest()


def encode_authority(record: Mapping[str, object], verifier_key: bytes) -> bytes:
    signed = {**record, "mac": ZERO_DIGEST}
    _validate_record(signed)
    signed["mac"] = _record_mac(signed, verifier_key)
    encoded = _canonical_json_bytes_v3(signed)
    if len(encoded) > AUTHORITY_MAX_BYTES:
        raise _invalid()
    return encoded


def decode_authority(encoded: bytes, verifier_key: bytes) -> dict[str, object]:
    if not encoded or len(encoded) > AUTHORITY_MAX_BYTES:
        raise _invalid()
    record = _validate_record(_strict_json_loads_v3(encoded))
    if _canonical_json_bytes_v3(record) != encoded or not hmac.compare_digest(
        cast(str, record["mac"]), _record_mac(record, verifier_key)
    ):
        raise NativePolicySnapshotError("native_command_control_authority_integrity_invalid")
    return dict(record)


def validate_control_floor(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _invalid()
    fields = frozenset({"revision", "managed_revision", "effective_digest"})
    if "authority" in value:
        fields |= {"authority"}
    if "previous_floor_digest" in value:
        fields |= {"previous_floor_digest"}
    floor = _mapping(value, fields)
    _revision(floor["revision"], minimum=0)
    _revision(floor["managed_revision"], minimum=0)
    if not _valid_digest_v3(floor["effective_digest"]):
        raise _invalid()
    authority = floor.get("authority")
    if "authority" in floor:
        validate_authority_binding(authority)
        assert isinstance(authority, Mapping)
        if (authority["recovery"] is not None) != ("previous_floor_digest" in floor):
            raise _invalid()
    if "previous_floor_digest" in floor:
        if not _valid_digest_v3(floor["previous_floor_digest"]) or not isinstance(authority, Mapping):
            raise _invalid()
        recovery = authority.get("recovery")
        if not isinstance(recovery, Mapping) or recovery.get("previous_floor_digest") != floor["previous_floor_digest"]:
            raise _invalid()
    return floor
