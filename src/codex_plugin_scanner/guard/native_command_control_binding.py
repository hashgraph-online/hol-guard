"""Bounded native command program metadata and verified control projection.

Program loading and authority reads are publisher work. Snapshot validation
only calls the pure binding validator; it never imports the extension registry
or invokes the build compiler. The resident independently requires the binding
to name its packaged program, catalog, and trust digests.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_command_control_authority import validate_authority_binding, validate_control_floor
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _generation_floor_mac_v3,
    _strict_json_loads_v3,
    _valid_digest_v3,
    _validate_json_limits_v3,
)
from .native_policy_snapshot_constants import NativePolicySnapshotError

if TYPE_CHECKING:
    from .runtime.extension_control_runtime import ExtensionControlRuntime, ExtensionControlRuntimeSnapshot
    from .store import GuardStore

NATIVE_COMMAND_CONTROL_BINDING_SCHEMA = "guard.native-command-control-binding.v1"
NATIVE_COMMAND_PROGRAM_CAPABILITY = "native-command-program-v1"
_PROGRAM_SCHEMA = "guard.native-command-program.v1"
_PROGRAM_SEMANTIC_PROFILE = "cpython-3.12-ucd15"
_PROGRAM_DOMAIN = b"hol-guard.native-command-program.v1\0"
_MAX_PROGRAM_BYTES = 4 * 1024 * 1024
_MAX_U64 = (1 << 64) - 1
_RUNTIME_SCHEMA = "guard.extension-control-runtime-snapshot.v1"
_BINDING_FIELDS = frozenset(
    {
        "schema",
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "health",
        "revision",
        "managed_revision",
        "effective_digest",
        "layers",
    }
)
_LAYER_FIELDS = frozenset({"schema_version", "kind", "catalog_digest", "global_lockdown", "controls"})
_CONTROL_FIELDS = frozenset({"target_kind", "target_id", "state"})
_HEALTH_VALUES = frozenset(
    {"unenrolled", "protected", "degraded-unacknowledged", "degraded-acknowledged", "tampered", "recovery-required"}
)
_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "compiler_version",
        "semantic_profile",
        "authoring_semantics_digest",
        "catalog_digest",
        "trust_digest",
        "extensions",
        "rules",
        "nodes",
        "coverage",
        "matcher_families",
        "program_digest",
    }
)


@dataclass(frozen=True, slots=True)
class NativeCommandProgramMetadata:
    program_digest: str
    catalog_digest: str
    trust_digest: str


def _program_path() -> Path:
    package = Path(__file__).parent / "contracts" / "data" / "extensions" / "native-command-program.v1.json"
    if package.exists():
        return package
    # Editable source checkouts use the same release artifact that wheel
    # force-includes install into the package above.
    source = Path(__file__).resolve().parents[3]
    if (source / "pyproject.toml").is_file():
        return source / "contracts" / "extensions" / "native-command-program.v1.json"
    return package


def load_native_command_program_metadata() -> NativeCommandProgramMetadata:
    """Capture at most 4 MiB and cache validation by these exact bytes.

    Metadata-only cache keys could miss equal-sized file replacement on a
    filesystem with weak timestamp semantics. At most two captured immutable
    programs are retained, and no matcher objects or program nodes are cached.
    """

    try:
        descriptor = os.open(_program_path(), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_PROGRAM_BYTES:
                raise NativePolicySnapshotError("native_command_program_artifact_invalid")
            content = handle.read(_MAX_PROGRAM_BYTES + 1)
        if not content or len(content) > _MAX_PROGRAM_BYTES:
            raise NativePolicySnapshotError("native_command_program_artifact_invalid")
        return _metadata_from_bytes(content)
    except (OSError, ValueError, RecursionError) as error:
        raise NativePolicySnapshotError("native_command_program_artifact_unavailable") from error


@lru_cache(maxsize=2)
def _metadata_from_bytes(content: bytes) -> NativeCommandProgramMetadata:
    try:
        raw = _strict_json_loads_v3(content)
        if not isinstance(raw, dict) or set(raw) != _PROGRAM_FIELDS:
            raise NativePolicySnapshotError("native_command_program_artifact_invalid")
        if (
            raw.get("schema") != _PROGRAM_SCHEMA
            or type(raw.get("compiler_version")) is not int
            or raw["compiler_version"] != 1
            or raw.get("semantic_profile") != _PROGRAM_SEMANTIC_PROFILE
        ):
            raise NativePolicySnapshotError("native_command_program_artifact_invalid")
        for name in ("program_digest", "catalog_digest", "trust_digest", "authoring_semantics_digest"):
            if not _valid_digest_v3(raw.get(name)):
                raise NativePolicySnapshotError("native_command_program_artifact_invalid")
        # Bound structural validation before canonical re-encoding; actual
        # matcher/IR admission remains the resident's responsibility.
        pending: list[tuple[object, int]] = [(raw, 0)]
        remaining = 1_000_000
        while pending:
            value, depth = pending.pop()
            remaining -= 1
            if remaining < 0 or depth > 64:
                raise NativePolicySnapshotError("native_command_program_artifact_invalid")
            if isinstance(value, dict):
                if len(value) > 16_384:
                    raise NativePolicySnapshotError("native_command_program_artifact_invalid")
                pending.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                if len(value) > 16_384:
                    raise NativePolicySnapshotError("native_command_program_artifact_invalid")
                pending.extend((child, depth + 1) for child in value)
        program_digest = cast(str, raw.pop("program_digest"))
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
        if hashlib.sha256(_PROGRAM_DOMAIN + canonical).hexdigest() != program_digest:
            raise NativePolicySnapshotError("native_command_program_digest_mismatch")
        return NativeCommandProgramMetadata(
            program_digest, cast(str, raw["catalog_digest"]), cast(str, raw["trust_digest"])
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise NativePolicySnapshotError("native_command_program_artifact_invalid") from error


def _require_fields(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativePolicySnapshotError("native_command_control_binding_invalid")
    return value


def _valid_target(value: object, kind: str) -> bool:
    if not isinstance(value, str) or len(value) > 256 or not value.startswith("command."):
        return False
    parts = value[len("command.") :].replace("-", ".").split(".")
    return all(
        part and all("a" <= character <= "z" or "0" <= character <= "9" for character in part) for part in parts
    ) and (".permission." in value) == (kind == "permission")


def _effective_control_digest(binding: Mapping[str, object]) -> str:
    layers = cast(list[dict[str, object]], binding["layers"])
    canonical_layers = [
        {
            **layer,
            "controls": sorted(
                cast(list[dict[str, str]], layer["controls"]),
                key=lambda control: (control["target_kind"], control["target_id"]),
            ),
        }
        for layer in sorted(layers, key=lambda layer: cast(str, layer["kind"]))
    ]
    payload = {
        "schema_version": _RUNTIME_SCHEMA,
        "catalog_digest": binding["catalog_digest"],
        "health": binding["health"],
        "revision": binding["revision"],
        "managed_revision": binding["managed_revision"],
        "layers": canonical_layers,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{_RUNTIME_SCHEMA}\0{len(canonical)}\0{canonical}".encode()).hexdigest()


def validate_native_command_control_binding(value: object) -> None:
    """Apply the exact typed Rust binding contract without authority reads."""

    _validate_json_limits_v3(value)
    fields = _BINDING_FIELDS | ({"authority"} if isinstance(value, Mapping) and "authority" in value else set())
    binding = _require_fields(value, fields)
    if "authority" in binding:
        validate_authority_binding(binding["authority"])
    health = binding.get("health")
    if (
        binding.get("schema") != NATIVE_COMMAND_CONTROL_BINDING_SCHEMA
        or not isinstance(health, str)
        or health not in _HEALTH_VALUES
    ):
        raise NativePolicySnapshotError("native_command_control_binding_invalid")
    for field in ("program_digest", "catalog_digest", "trust_digest", "effective_digest"):
        if not _valid_digest_v3(binding.get(field)):
            raise NativePolicySnapshotError("native_command_control_binding_invalid")
    for field in ("revision", "managed_revision"):
        revision = binding.get(field)
        if type(revision) is not int or not 0 <= revision <= _MAX_U64:
            raise NativePolicySnapshotError("native_command_control_binding_invalid")
    layers = binding.get("layers")
    if not isinstance(layers, list) or len(layers) > 2:
        raise NativePolicySnapshotError("native_command_control_layer_invalid")
    kinds: set[str] = set()
    for raw_layer in layers:
        layer = _require_fields(raw_layer, _LAYER_FIELDS)
        kind = layer.get("kind")
        if (
            not isinstance(kind, str)
            or kind not in {"local-admin", "signed-cloud"}
            or kind in kinds
            or layer.get("schema_version") != "1.0.0"
            or layer.get("catalog_digest") != binding["catalog_digest"]
            or type(layer.get("global_lockdown")) is not bool
        ):
            raise NativePolicySnapshotError("native_command_control_layer_invalid")
        kinds.add(kind)
        controls = layer.get("controls")
        if not isinstance(controls, list) or len(controls) > 512:
            raise NativePolicySnapshotError("native_command_control_layer_invalid")
        targets: set[tuple[str, str]] = set()
        for raw_control in controls:
            control = _require_fields(raw_control, _CONTROL_FIELDS)
            target_kind, target_id = control.get("target_kind"), control.get("target_id")
            state = control.get("state")
            if (
                not isinstance(target_kind, str)
                or target_kind not in {"extension", "permission"}
                or not isinstance(target_id, str)
                or not _valid_target(target_id, target_kind)
                or not isinstance(state, str)
                or state not in {"enabled", "disabled"}
                or (target_kind, target_id) in targets
            ):
                raise NativePolicySnapshotError("native_command_control_target_invalid")
            targets.add((target_kind, target_id))
    if binding["effective_digest"] != _effective_control_digest(binding):
        raise NativePolicySnapshotError("native_command_control_digest_mismatch")


def capture_native_command_control_binding(value: object) -> dict[str, object]:
    validate_native_command_control_binding(value)
    return cast(dict[str, object], json.loads(_canonical_json_bytes_v3(value)))


def native_command_control_floor_mac(generation: int, policy_digest: str, floor: object, verifier_key: bytes) -> str:
    """Verify Rust's optional protected-control floor without treating it as policy."""

    if floor is None:
        return _generation_floor_mac_v3(generation, policy_digest, verifier_key)
    value = validate_control_floor(floor)
    bound_value = {"policy_digest": policy_digest, "command_controls": value}
    _validate_json_limits_v3(bound_value)
    bound = "guard-native-policy-command-control-floor.v1\0" + json.dumps(
        bound_value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _generation_floor_mac_v3(generation, bound, verifier_key)


def build_native_command_control_binding(
    snapshot: ExtensionControlRuntimeSnapshot,
    metadata: NativeCommandProgramMetadata,
) -> dict[str, object]:
    from .runtime.extension_control_runtime import _layer_payload

    if snapshot.catalog_digest != metadata.catalog_digest:
        raise NativePolicySnapshotError("native_command_control_catalog_mismatch")
    binding: dict[str, object] = {
        "schema": NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
        "program_digest": metadata.program_digest,
        "catalog_digest": metadata.catalog_digest,
        "trust_digest": metadata.trust_digest,
        "health": snapshot.health.value,
        "revision": snapshot.revision,
        "managed_revision": snapshot.managed_revision,
        "effective_digest": snapshot.effective_digest,
        "layers": sorted((_layer_payload(layer) for layer in snapshot.layers), key=lambda layer: str(layer["kind"])),
    }
    validate_native_command_control_binding(binding)
    return binding


def read_native_command_control_binding(
    store: GuardStore,
    runtime: ExtensionControlRuntime | None = None,
) -> tuple[dict[str, object], ExtensionControlRuntime]:
    """Read committed local and managed authority, retaining both revision floors."""

    from .native_command_control_projection import read_control_projection

    metadata = load_native_command_program_metadata()
    return read_control_projection(store, metadata, runtime)
