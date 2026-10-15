"""Native command program metadata and the verified control projection.

Program loading and authority reads are publisher work. Binding admission is
Rust's: the snapshot builder and the resident each validate the typed binding
(health, layers, targets, authority, effective digest) against the packaged
program, so Python only captures the binding as canonical JSON and checks the
program artifact's own digest.
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

from .native_command_control_authority import validate_control_floor
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
_PROGRAM_DOMAIN = b"hol-guard.native-command-program.v1\0"
_MAX_PROGRAM_BYTES = 4 * 1024 * 1024


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
    """Verify the artifact's own digest; the Rust runtime admits the program itself."""

    try:
        raw = _strict_json_loads_v3(content)
        if not isinstance(raw, dict) or not all(
            _valid_digest_v3(raw.get(name)) for name in ("program_digest", "catalog_digest", "trust_digest")
        ):
            raise NativePolicySnapshotError("native_command_program_artifact_invalid")
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


def capture_native_command_control_binding(value: object) -> dict[str, object]:
    """Bound and canonicalize a binding; Rust validates its contents at build and install."""

    if not isinstance(value, Mapping):
        raise NativePolicySnapshotError("native_command_control_binding_invalid")
    _validate_json_limits_v3(value)
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
    return binding


def read_native_command_control_binding(
    store: GuardStore,
    runtime: ExtensionControlRuntime | None = None,
) -> tuple[dict[str, object], ExtensionControlRuntime]:
    """Read committed local and managed authority, retaining both revision floors."""

    from .native_command_control_projection import read_control_projection

    metadata = load_native_command_program_metadata()
    return read_control_projection(store, metadata, runtime)
