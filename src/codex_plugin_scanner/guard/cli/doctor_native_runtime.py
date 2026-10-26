"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, TypedDict

from ..adapters.diagnostic_probes import skipped_command_probe
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from ..resident_state_prune import pid_is_alive, probe_owner_lock


class _NativeAvailabilityFields(TypedDict):
    mode: Literal["off", "shadow", "auto", "force", "unknown"]
    available: bool | None
    compatible: bool | None
    reason_code: str
    evaluation_verified: Literal[False]


class NativeAvailabilityResult(_NativeAvailabilityFields, total=False):
    message: str


_MAX_STATE_BYTES = 64 * 1024

# Two Guard installs (for example a desktop app and a package-manager CLI) share
# one home-wide resident. Only one owns it; the other is healthy, not broken.
_REASON_MESSAGES = {
    "native_resident_owner_busy": (
        "Another Guard install on this account owns the native resident runtime, so this "
        "install cannot start its own. Nothing crashed and no restarts were used. Keep one "
        "Guard install per user, or keep both on the same version so they share one runtime."
    ),
}


def _resident_owned_elsewhere(state_base: Path, runtime_sha256: str) -> bool:
    """True when a process holds the home-wide owner lock and no live resident runs this runtime.

    Reads only the lock and the resident state files; it never takes the lock
    for longer than the probe and never starts or stops a resident.
    """

    if probe_owner_lock(state_base) is not False:
        return False
    for state_path in state_base.glob("resident-v3-*/generation-*.json"):
        try:
            with state_path.open("rb") as handle:
                state = json.loads(handle.read(_MAX_STATE_BYTES))
        except (OSError, ValueError):
            continue
        if not isinstance(state, dict) or state.get("runtime_sha256") != runtime_sha256:
            continue
        process_id = state.get("process_id")
        if isinstance(process_id, int) and pid_is_alive(process_id):
            return False
    return True


def _passive_runtime_sha256() -> str | None:
    """Hash the first valid runtime binary without running it."""

    from ..native_binary_identity import validate_native_binary
    from ..native_runtime import _runtime_candidates

    for candidate in _runtime_candidates():
        identity = validate_native_binary(candidate)
        if identity is not None:
            return identity.sha256
    return None


def _owner_busy(guard_home: Path | None, runtime_sha256: str | None) -> bool:
    return (
        guard_home is not None
        and runtime_sha256 is not None
        and _resident_owned_elsewhere(guard_home / NATIVE_RUNTIME_STATE_DIRECTORY, runtime_sha256)
    )


def _with_reason(result: NativeAvailabilityResult, reason: str) -> NativeAvailabilityResult:
    result["reason_code"] = reason
    message = _REASON_MESSAGES.get(reason)
    if message is not None:
        result["message"] = message
    return result


def doctor_native_availability(guard_home: Path | None = None) -> NativeAvailabilityResult:
    """Use null availability for an unperformed probe, never a false failure."""
    # This only queries the passive scope; its command metadata is not emitted.
    if skipped_command_probe(["hol-guard-runtime", "capabilities", "--json"]) is not None:
        skipped: NativeAvailabilityResult = {
            "mode": "unknown",
            "available": None,
            "compatible": None,
            "reason_code": "native_status_probe_skipped",
            "evaluation_verified": False,
        }
        # The owner lock and the binary hash are read without running anything.
        if guard_home is not None and _owner_busy(guard_home, _passive_runtime_sha256()):
            return _with_reason(skipped, "native_resident_owner_busy")
        return skipped

    from ..native_runtime import native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return {
            "mode": "unknown",
            "available": False,
            "compatible": False,
            "reason_code": "native_status_probe_failed",
            "evaluation_verified": False,
        }
    reason = status.reason
    # Native status reasons are fixed lowercase codes, not arbitrary probe text.
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", reason):
        reason = "native_status_reason_unavailable"
    result: NativeAvailabilityResult = {
        "mode": status.mode,
        "available": status.available,
        "compatible": status.compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }
    identity = status.identity
    if _owner_busy(guard_home, identity.sha256 if identity is not None else None):
        reason = "native_resident_owner_busy"
    return _with_reason(result, reason)
