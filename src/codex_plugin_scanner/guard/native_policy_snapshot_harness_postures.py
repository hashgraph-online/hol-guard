"""Carry per-harness posture beside, not inside, the native policy snapshot.

The Rust resident validates a strict snapshot schema and never decides
recording-only delivery; Python converts verdicts after native evaluation. So
per-harness Watch cannot be (and need not be) a snapshot field. It rides the
same publish/ACK path instead:

* the publisher captures the overrides at the ACK commit and serves them in
  its in-memory binding, and
* a verifier-key MAC'd sidecar bound to the ACKed generation and policy digest
  serves workers that read the signed snapshot file.

A missing, stale, or unauthenticated sidecar yields no overrides, so hooks fall
back to the ACKed snapshot mode. A local config edit therefore cannot weaken an
enforcing ACKed snapshot until the publisher has re-ACKed with the edit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .harness_posture import runtime_harness_key
from .native_policy_snapshot_codec import _normalized_harness_selector_v3, derive_native_policy_verifier_key
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .protection_posture import VALID_PROTECTION_POSTURES

if TYPE_CHECKING:
    from .config import GuardConfig

logger = logging.getLogger(__name__)

HARNESS_POSTURES_BINDING_KEY = "harness_postures"
HARNESS_POSTURES_SIDECAR_NAME = "harness-postures-v1.json"
_SIDECAR_SCHEMA = "guard-harness-postures.v1"
_SIDECAR_DOMAIN = b"hol-guard/harness-postures/v1\0"
_MAX_SIDECAR_BYTES = 16 * 1024
_STRENGTH = {"watch": 0, "protected": 1, "extra_careful": 2}


def valid_harness_postures(value: object) -> dict[str, str]:
    """Keep only well-formed ``harness -> posture`` pairs."""

    if not isinstance(value, Mapping):
        return {}
    return {
        key: posture
        for key, posture in value.items()
        if isinstance(key, str) and key and isinstance(posture, str) and posture in VALID_PROTECTION_POSTURES
    }


def merge_harness_postures(policies: Iterable[Mapping[str, object]]) -> dict[str, str]:
    """Strictest-wins across the configs compiled into one snapshot."""

    merged: dict[str, str] = {}
    for policy in policies:
        for harness, posture in valid_harness_postures(policy.get(HARNESS_POSTURES_BINDING_KEY)).items():
            previous = merged.get(harness)
            if previous is None or _STRENGTH[posture] > _STRENGTH[previous]:
                merged[harness] = posture
    return merged


def posture_risk_overlay(base: object, config: GuardConfig) -> object:
    """Add per-harness risk floors for overrides stricter than the baseline.

    Rust joins ``harness_risk_actions`` as strengthening floors, so the overlay
    can only tighten. It is what makes Protected/Extra careful real for one
    harness while the global posture is Watch, and Extra careful real while the
    global posture is Protected. Watch overrides add nothing here: they are
    applied by Python as recording-only after native evaluation.
    """

    from .action_lattice import most_restrictive_guard_action
    from .harness_posture import global_effective_posture
    from .protection_posture import POSTURE_RISK_ACTIONS

    overrides = config.harness_postures or {}
    if not overrides:
        return base
    baseline = _STRENGTH[global_effective_posture(config)]
    merged: dict[str, dict[str, str]] = {}
    if isinstance(base, Mapping):
        for key, value in base.items():
            if isinstance(value, Mapping):
                merged[str(key)] = {str(risk): str(action) for risk, action in value.items()}
    for harness, posture in sorted(overrides.items()):
        floors = POSTURE_RISK_ACTIONS.get(posture)
        if floors is None or _STRENGTH.get(posture, 0) <= baseline:
            continue
        selector = _normalized_harness_selector_v3(harness)
        key = next((name for name in merged if _normalized_harness_selector_v3(name) == selector), harness)
        target = merged.setdefault(key, {})
        for risk_class, action in floors.items():
            current = target.get(risk_class)
            target[risk_class] = action if current is None else most_restrictive_guard_action(current, action)
    return merged


def _verifier_key_for_store(store: object) -> bytes | None:
    material_getter = getattr(store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        return None
    try:
        material = material_getter(create=False)
    except Exception:
        logger.debug("Native policy integrity material is unavailable", exc_info=True)
        return None
    if not isinstance(material, tuple) or len(material) != 2 or not isinstance(material[0], bytes):
        return None
    try:
        return derive_native_policy_verifier_key(material[0])
    except NativePolicySnapshotError:
        return None


def _sidecar_mac(verifier_key: bytes, generation: int, policy_digest: str, postures: Mapping[str, str]) -> str:
    body = json.dumps(
        {"generation": generation, "policy_digest": policy_digest, "harness_postures": dict(sorted(postures.items()))},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hmac.new(verifier_key, _SIDECAR_DOMAIN + body, hashlib.sha256).hexdigest()


def _sidecar_path(guard_home: object) -> Path:
    """Path inside the validated private runtime-state directory."""

    from .native_policy_snapshot_windows_support import _runtime_state_directory

    return _runtime_state_directory(Path(str(guard_home))) / HARNESS_POSTURES_SIDECAR_NAME


def _write_private_file(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    except OSError:
        os.close(descriptor)
        with_suppressed_unlink(temporary)
        raise
    os.close(descriptor)
    try:
        os.replace(temporary, path)
    except OSError:
        with_suppressed_unlink(temporary)
        raise


def write_harness_postures_sidecar(
    store: object,
    *,
    generation: int,
    policy_digest: str,
    postures: Mapping[str, str],
) -> dict[str, str]:
    """Persist overrides for the ACKed snapshot and return what readers will see.

    Failure only means no overrides. The publisher binds the returned value, so
    its in-memory binding and readers of the signed file always agree.
    """

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return {}
    verified = valid_harness_postures(postures)
    path: Path | None = None
    try:
        path = _sidecar_path(guard_home)
        verifier_key = _verifier_key_for_store(store) if verified else None
        if verifier_key is None:
            path.unlink(missing_ok=True)
            return {}
        document = {
            "schema": _SIDECAR_SCHEMA,
            "generation": generation,
            "policy_digest": policy_digest,
            "harness_postures": dict(sorted(verified.items())),
            "mac": _sidecar_mac(verifier_key, generation, policy_digest, verified),
        }
        _write_private_file(path, json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    except (OSError, NativePolicySnapshotError):
        logger.warning("Could not persist per-harness posture sidecar; apps follow the global posture", exc_info=True)
        if path is not None:
            with_suppressed_unlink(path)
        return {}
    return verified


def with_suppressed_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.debug("Could not remove per-harness posture sidecar", exc_info=True)


def read_harness_postures_sidecar(
    store: object,
    *,
    generation: int,
    policy_digest: str,
) -> dict[str, str]:
    """Return overrides only when authenticated and bound to this exact ACK."""

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return {}
    verifier_key = _verifier_key_for_store(store)
    if verifier_key is None:
        return {}
    try:
        path = _sidecar_path(guard_home)
        if path.stat().st_size > _MAX_SIDECAR_BYTES:
            return {}
        document = json.loads(path.read_bytes())
    except (OSError, ValueError, NativePolicySnapshotError):
        return {}
    if not isinstance(document, dict) or document.get("schema") != _SIDECAR_SCHEMA:
        return {}
    postures = valid_harness_postures(document.get("harness_postures"))
    mac = document.get("mac")
    if (
        document.get("generation") != generation
        or document.get("policy_digest") != policy_digest
        or not postures
        or len(postures) != len(document.get("harness_postures") or {})
        or not isinstance(mac, str)
        or not hmac.compare_digest(mac, _sidecar_mac(verifier_key, generation, policy_digest, postures))
    ):
        return {}
    return postures


def binding_with_harness_postures(binding: dict[str, object], postures: Mapping[str, str]) -> dict[str, object]:
    verified = valid_harness_postures(postures)
    if verified:
        binding[HARNESS_POSTURES_BINDING_KEY] = dict(verified)
    return binding


def recording_only_for_binding(binding: Mapping[str, object] | None, harness: object) -> bool:
    """Watch decision for one harness from an ACKed binding.

    ``None`` (no ACK) never grants recording-only authority. A per-harness
    override wins over the snapshot mode in both directions: Watch records
    under an enforcing snapshot, and Protected/Extra careful keeps stopping
    under a Watch snapshot.
    """

    if binding is None:
        return False
    key = runtime_harness_key(harness)
    override = valid_harness_postures(binding.get(HARNESS_POSTURES_BINDING_KEY)).get(key) if key is not None else None
    if override is not None:
        return override == "watch"
    return binding.get("mode") == "observe"
