"""Bind hook workers to the resident-accepted native policy snapshot."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import (
    _RUST_SNAPSHOT_STATE_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_storage import _read_v3_snapshot_file

logger = logging.getLogger(__name__)


def acked_snapshot_binding_for_store(store: object) -> dict[str, object] | None:
    """Return the compact hook binding from a still-valid rust-accepted snapshot.

    Publisher cache is written before resident IPC. Bind only the nested
    snapshot inside ``policy-snapshot-v3.json`` after MAC verification.
    """

    guard_home = getattr(store, "guard_home", None)
    material_getter = getattr(store, "_policy_integrity_secret_material", None)
    if guard_home is None or not callable(material_getter):
        return None
    try:
        material = material_getter(create=False)
    except Exception:
        logger.debug("Native policy integrity material is unavailable", exc_info=True)
        return None
    if not isinstance(material, tuple) or len(material) != 2 or not isinstance(material[0], bytes):
        return None
    try:
        cached = _read_v3_snapshot_file(
            Path(guard_home) / NATIVE_RUNTIME_STATE_DIRECTORY / _RUST_SNAPSHOT_STATE_NAME,
            verifier_key=derive_native_policy_verifier_key(material[0]),
            maximum_bytes=POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
        )
    except (NativePolicySnapshotError, OverflowError):
        return None
    if cached is None:
        return None
    snapshot, _payload = cached
    generation = snapshot.get("generation")
    expires_at_ms = snapshot.get("expires_at_ms")
    digest = snapshot.get("policy_digest")
    identity = snapshot.get("runtime_identity")
    mode = snapshot.get("mode")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        return None
    if not isinstance(expires_at_ms, int) or expires_at_ms <= int(time.time() * 1_000):
        return None
    if not isinstance(digest, str) or not isinstance(identity, str) or not isinstance(mode, str):
        return None
    return {
        "generation": generation,
        "policy_digest": digest,
        "runtime_identity": identity,
        "mode": mode,
    }
