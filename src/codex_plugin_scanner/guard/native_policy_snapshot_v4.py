"""Authenticate complete scoped authority without advertising resident support."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_managed_capture import compile_configuration_origins, configuration_origin
from .native_managed_configuration import MANAGED_CONFIGURATION_INPUT_KEY
from .native_policy_authority_contract import NativePolicyAuthorityCapabilities, NativePolicyAuthorityDraft
from .native_policy_authority_decode import native_policy_authority_from_mapping
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _digest_v3,
    _valid_digest_v3,
    native_policy_verifier_key_id,
)
from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_BYTES, NativePolicySnapshotError
from .native_policy_snapshot_contract import _snapshot_policy_digest_v3, _validate_snapshot_v3, build_policy_snapshot_v3

if TYPE_CHECKING:
    from .config import GuardConfig

SNAPSHOT_SCHEMA = "hol-guard-native-policy.v4"
PUSH_SCHEMA = "guard-policy-snapshot-push.v2"
ACK_SCHEMA = "guard-policy-snapshot-ack.v2"
INTEGRITY_DOMAIN = b"hol-guard-native-policy-snapshot-v4\0"


def _base_projection(snapshot: Mapping[str, object]) -> dict[str, object]:
    base = dict(snapshot)
    base.pop("scoped_authority", None)
    base.pop("source_input_digest", None)
    base["schema"] = "hol-guard-native-policy.v3"
    base["version"] = 3
    effective = base.get("effective_policy")
    scope = base.get("scope_contract")
    if not isinstance(effective, Mapping) or not isinstance(scope, Mapping):
        raise NativePolicySnapshotError("native_policy_snapshot_policy_invalid")
    base["policy_digest"] = _snapshot_policy_digest_v3(
        config_digest=cast(str, base.get("config_digest")),
        effective_policy=effective,
        mode=cast(str, base.get("mode")),
        rule_digest=cast(str, base.get("rule_digest")),
        runtime_identity=cast(str, base.get("runtime_identity")),
        scope_digest=cast(str, scope.get("scope_digest")),
        command_extensions=cast(Mapping[str, object] | None, base.get("command_extensions")),
    )
    return base


def policy_digest_v4(snapshot: Mapping[str, object]) -> str:
    scope = snapshot["scope_contract"]
    assert isinstance(scope, Mapping)
    value: dict[str, object] = {
        "config_digest": snapshot["config_digest"],
        "effective_policy_digest": _digest_v3(snapshot["effective_policy"]),
        "mode": snapshot["mode"],
        "protocol_version": snapshot["protocol_version"],
        "rule_digest": snapshot["rule_digest"],
        "runtime_identity": snapshot["runtime_identity"],
        "scope_digest": scope["scope_digest"],
        "scoped_authority_digest": _digest_v3(snapshot["scoped_authority"]),
        "source_input_digest": snapshot["source_input_digest"],
        "version": snapshot["version"],
    }
    if "command_extensions" in snapshot:
        value["command_extensions_digest"] = _digest_v3(snapshot["command_extensions"])
    return _digest_v3(value)


def validate_snapshot_v4(snapshot: Mapping[str, object], *, allow_empty_mac: bool = False) -> None:
    if (
        snapshot.get("schema") != SNAPSHOT_SCHEMA
        or type(snapshot.get("version")) is not int
        or snapshot["version"] != 4
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_version_invalid")
    if not _valid_digest_v3(snapshot.get("source_input_digest")):
        raise NativePolicySnapshotError("native_policy_snapshot_digest_invalid")
    authority = native_policy_authority_from_mapping(snapshot.get("scoped_authority"))
    if authority.managed_config is not None and authority.managed_config.mode != snapshot.get("mode"):
        raise NativePolicySnapshotError("native_policy_managed_configuration_mode_mismatch")
    _validate_snapshot_v3(_base_projection(snapshot), allow_empty_mac=allow_empty_mac)
    if snapshot.get("policy_digest") != policy_digest_v4(snapshot):
        raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")
    if len(_canonical_json_bytes_v3(snapshot)) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")


def snapshot_signing_bytes_v4(snapshot: Mapping[str, object]) -> bytes:
    validate_snapshot_v4(snapshot, allow_empty_mac=True)
    value = dict(snapshot)
    value.pop("integrity")
    return _canonical_json_bytes_v3(value)


def snapshot_bytes_v4(snapshot: Mapping[str, object]) -> bytes:
    validate_snapshot_v4(snapshot)
    return _canonical_json_bytes_v3(snapshot)


def verify_snapshot_v4(
    snapshot: Mapping[str, object],
    *,
    verifier_key: bytes,
    expected_runtime_identity: str,
    expected_rule_digest: str,
    minimum_generation: int,
    now_ms: int,
) -> None:
    """Authenticate persisted bytes before using their generation or policy authority."""
    validate_snapshot_v4(snapshot)
    if type(minimum_generation) is not int or minimum_generation < 0 or type(now_ms) is not int or now_ms < 0:
        raise NativePolicySnapshotError("native_policy_snapshot_identity_invalid")
    if snapshot["runtime_identity"] != expected_runtime_identity or snapshot["rule_digest"] != expected_rule_digest:
        raise NativePolicySnapshotError("native_policy_snapshot_identity_invalid")
    if cast(int, snapshot["generation"]) < minimum_generation:
        raise NativePolicySnapshotError("native_policy_snapshot_generation_downgrade")
    if cast(int, snapshot["expires_at_ms"]) <= now_ms:
        raise NativePolicySnapshotError("native_policy_snapshot_expired")
    integrity = cast(Mapping[str, object], snapshot["integrity"])
    if integrity["key_id"] != native_policy_verifier_key_id(verifier_key):
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_invalid")
    expected = hmac.new(
        verifier_key, INTEGRITY_DOMAIN + snapshot_signing_bytes_v4(snapshot), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, cast(str, integrity["mac"])):
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_mismatch")


def build_policy_snapshot_v4(
    *,
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    runtime_identity: str,
    rule_digest: str,
    verifier_key: bytes,
    generation: int,
    authority: NativePolicyAuthorityDraft,
    capabilities: NativePolicyAuthorityCapabilities,
    source_input_digest: str,
    command_extensions: Mapping[str, object] | None = None,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
) -> dict[str, object]:
    if type(authority) is not NativePolicyAuthorityDraft or type(capabilities) is not NativePolicyAuthorityCapabilities:
        raise NativePolicySnapshotError("native_policy_authority_encoding_invalid")
    scoped = authority.for_snapshot(capabilities)
    origin = configuration_origin(config)
    if origin != authority.managed_config:
        raise NativePolicySnapshotError("native_policy_managed_configuration_source_mismatch")
    base_config = config
    if origin is not None:
        compiled = dict(config) if isinstance(config, Mapping) else compile_configuration_origins((config,))
        compiled.pop(MANAGED_CONFIGURATION_INPUT_KEY)
        base_config = compiled
    snapshot = build_policy_snapshot_v3(
        config=base_config,
        guard_home=guard_home,
        runtime_identity=runtime_identity,
        rule_digest=rule_digest,
        verifier_key=verifier_key,
        generation=generation,
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
        command_extensions=command_extensions,
    )
    snapshot.update(schema=SNAPSHOT_SCHEMA, version=4, scoped_authority=scoped, source_input_digest=source_input_digest)
    snapshot["policy_digest"] = policy_digest_v4(snapshot)
    integrity = cast(dict[str, object], snapshot["integrity"])
    integrity["mac"] = hmac.new(
        verifier_key, INTEGRITY_DOMAIN + snapshot_signing_bytes_v4(snapshot), hashlib.sha256
    ).hexdigest()
    validate_snapshot_v4(snapshot)
    return snapshot
