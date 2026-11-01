"""Protected per-user harness registry and aggregate integrity projection.

The native runtime reads, verifies and replaces the registry; this module
checks the administrator context, holds the machine-state lock and maps the
runtime's answer back to the MDM contract.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from .contracts import HarnessCoverage, MachinePaths, ManagedPolicyState
from .machine_state_lock import protected_machine_state_lock
from .runtime_request import runtime_answer

HARNESS_COVERAGE_FEATURE = "native-harness-coverage-v1"
HARNESS_COVERAGE_COMMAND = "harness-coverage"
HARNESS_COVERAGE_SCHEMA = "harness-coverage.v1"
_COMMAND_TIMEOUT_SECONDS = 60.0
_OUTPUT_LIMIT_BYTES = 64 * 1024
_UNAVAILABLE = "harness_coverage_native_unavailable"
_ERROR_TYPES: dict[str, type[OSError] | type[ValueError]] = {
    "value": ValueError,
    "permission": PermissionError,
    "os": OSError,
}
_UNKNOWN_COVERAGE = HarnessCoverage(required=None, protected=None, degraded=None, missing=None)


@dataclass(frozen=True, slots=True)
class HarnessCoverageVerification:
    state: str
    reason_code: str
    coverage: HarnessCoverage


class _Shell32(Protocol):
    def IsUserAnAdmin(self) -> int: ...  # noqa: N802 - Windows API name


def _administrator_context() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    import ctypes

    shell32 = cast(_Shell32, cast(object, ctypes.windll.shell32))
    return shell32.IsUserAnAdmin() != 0


def _registry_owner_uid() -> int:
    """The only owner a Unix registry is trusted from; Windows skips the check."""

    return 0


def _native_request(op: str, paths: MachinePaths, **fields: object) -> dict[str, object] | None:
    """The runtime's answer to one registry request, or ``None`` when it cannot answer."""

    request = {
        "schema": HARNESS_COVERAGE_SCHEMA,
        "op": op,
        "state_root": str(paths.state_root),
        "registry_owner_uid": _registry_owner_uid(),
        **fields,
    }
    try:
        request_text = json.dumps(request, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise ValueError("harness_coverage_registry_invalid") from error
    return runtime_answer(
        HARNESS_COVERAGE_FEATURE,
        HARNESS_COVERAGE_COMMAND,
        request_text,
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )


def _apply_change(op: str, paths: MachinePaths, **fields: object) -> None:
    response = _native_request(op, paths, **fields)
    if response is None:
        raise OSError(_UNAVAILABLE)
    if response.get("ok") is True:
        return
    reason_code = response.get("reason_code")
    error_type = _ERROR_TYPES.get(str(response.get("error_class")))
    if error_type is None or not isinstance(reason_code, str):
        raise OSError(_UNAVAILABLE)
    raise error_type(reason_code)


def register_user_harnesses(
    paths: MachinePaths,
    home: Path,
    installs: list[dict[str, object]],
) -> None:
    if not _administrator_context():
        raise PermissionError("harness_coverage_administrator_context_required")
    resolved_home = home.resolve(strict=True)
    if not resolved_home.is_dir():
        raise ValueError("harness_coverage_home_invalid")
    with protected_machine_state_lock(paths, "harness-coverage"):
        _apply_change("register", paths, home=str(resolved_home), installs=installs)


def register_requested_user_harnesses(paths: MachinePaths, home: Path) -> None:
    """Register the user at ``home`` from the coverage request activation left there."""

    if not _administrator_context():
        raise PermissionError("harness_coverage_administrator_context_required")
    resolved_home = home.resolve(strict=True)
    if not resolved_home.is_dir():
        raise ValueError("harness_coverage_home_invalid")
    with protected_machine_state_lock(paths, "harness-coverage"):
        _apply_change("register-request", paths, home=str(resolved_home))


def write_user_coverage_request(paths: MachinePaths, home: Path, installs: list[dict[str, object]]) -> None:
    """Leave the installs activation recorded for the administrator to register."""

    _apply_change("write-request", paths, home=str(home), installs=installs)


def unregister_user_harnesses(paths: MachinePaths, home: Path) -> None:
    if not _administrator_context():
        raise PermissionError("harness_coverage_administrator_context_required")
    with protected_machine_state_lock(paths, "harness-coverage"):
        _apply_change("unregister", paths, home=str(home.resolve(strict=False)))


def _coverage_count(coverage: dict[str, object], key: str) -> int | None:
    value = coverage.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def verify_harness_coverage(paths: MachinePaths, policy: ManagedPolicyState) -> HarnessCoverageVerification:
    required_harnesses = policy.policy.required_harnesses if policy.policy is not None else ()
    if not required_harnesses:
        return HarnessCoverageVerification(
            "healthy",
            "harness_coverage_not_required",
            HarnessCoverage(required=0, protected=0, degraded=0, missing=0),
        )
    response = _native_request("verify", paths, required_harnesses=list(required_harnesses)) or {}
    state = response.get("state")
    reason_code = response.get("reason_code")
    if response.get("ok") is not True or not isinstance(state, str) or not isinstance(reason_code, str):
        return HarnessCoverageVerification("unknown", "harness_coverage_probe_failed", _UNKNOWN_COVERAGE)
    raw_coverage = response.get("coverage")
    if not isinstance(raw_coverage, dict):
        return HarnessCoverageVerification(state, reason_code, _UNKNOWN_COVERAGE)
    coverage = cast(dict[str, object], raw_coverage)
    return HarnessCoverageVerification(
        state,
        reason_code,
        HarnessCoverage(
            required=_coverage_count(coverage, "required"),
            protected=_coverage_count(coverage, "protected"),
            degraded=_coverage_count(coverage, "degraded"),
            missing=_coverage_count(coverage, "missing"),
        ),
    )


__all__ = [
    "HarnessCoverageVerification",
    "register_requested_user_harnesses",
    "register_user_harnesses",
    "unregister_user_harnesses",
    "verify_harness_coverage",
    "write_user_coverage_request",
]
