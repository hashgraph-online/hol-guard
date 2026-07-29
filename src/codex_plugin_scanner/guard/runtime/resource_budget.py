"""Shared resource budget and applied-control evidence for isolated execution.

A single ``ResourceBudget`` contract shared by central OS containment and the
restricted runners (pytest/archive/temp-dir). Where a backend cannot enforce a
control, the guarantee is reported as not applied rather than implied, so the
recorded guarantee lowers instead of overstating enforcement.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from typing import Final

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuaranteeKind,
    framed_digest,
)

RESOURCE_BUDGET_SCHEMA_VERSION: Final = "guard.resource-budget.v1"

_SECONDS_MAX: Final = 24 * 60 * 60
_MEMORY_MAX_BYTES: Final = 64 * 1024 * 1024 * 1024
_PROCESSES_MAX: Final = 4096
_OPEN_FILES_MAX: Final = 65536
_OUTPUT_BYTES_MAX: Final = 64 * 1024 * 1024


class ResourceControlKind(str, Enum):
    """Atomic resource controls aligned to the guarantee taxonomy."""

    CPU = "cpu"
    MEMORY = "memory"
    PROCESSES = "processes"
    OPEN_FILES = "open_files"
    OUTPUT_BYTES = "output_bytes"
    WALL_CLOCK = "wall_clock"


# Resource controls back the RESOURCE and OUTPUT atomic guarantees.
CONTROL_TO_GUARANTEE: Final = {
    ResourceControlKind.CPU: AtomicGuaranteeKind.RESOURCE,
    ResourceControlKind.MEMORY: AtomicGuaranteeKind.RESOURCE,
    ResourceControlKind.PROCESSES: AtomicGuaranteeKind.RESOURCE,
    ResourceControlKind.OPEN_FILES: AtomicGuaranteeKind.RESOURCE,
    ResourceControlKind.WALL_CLOCK: AtomicGuaranteeKind.RESOURCE,
    ResourceControlKind.OUTPUT_BYTES: AtomicGuaranteeKind.OUTPUT,
}


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """One shared resource budget. Order-independent, immutable, bounded."""

    cpu_seconds: int = 1200
    memory_bytes: int = 4 * 1024 * 1024 * 1024
    process_count: int = 64
    open_file_count: int = 256
    output_bytes: int = 65536
    wall_clock_seconds: int = 600
    schema_version: str = RESOURCE_BUDGET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_schema_version(self.schema_version)
        _require_int_range(self.cpu_seconds, "cpu_seconds", 1, _SECONDS_MAX)
        _require_int_range(self.memory_bytes, "memory_bytes", 1, _MEMORY_MAX_BYTES)
        _require_int_range(self.process_count, "process_count", 1, _PROCESSES_MAX)
        _require_int_range(self.open_file_count, "open_file_count", 1, _OPEN_FILES_MAX)
        _require_int_range(self.output_bytes, "output_bytes", 1, _OUTPUT_BYTES_MAX)
        _require_int_range(self.wall_clock_seconds, "wall_clock_seconds", 1, _SECONDS_MAX)

    def digest(self) -> str:
        return framed_digest(
            RESOURCE_BUDGET_SCHEMA_VERSION,
            {
                "cpu_seconds": self.cpu_seconds,
                "memory_bytes": self.memory_bytes,
                "process_count": self.process_count,
                "open_file_count": self.open_file_count,
                "output_bytes": self.output_bytes,
                "wall_clock_seconds": self.wall_clock_seconds,
            },
        )


@dataclass(frozen=True, slots=True)
class AppliedControl:
    """Evidence of one resource control's enforcement on a backend."""

    kind: ResourceControlKind
    applied: bool
    backend: str
    limit_value: int | None

    def __post_init__(self) -> None:
        _require_enum(self.kind, ResourceControlKind, "kind")
        _require_bool_type(self.applied, "applied")
        _require_non_empty_str(self.backend, "backend")
        if self.limit_value is not None:
            _require_int_range(self.limit_value, "limit_value", 0, _MEMORY_MAX_BYTES)


class ResourceBackend(str, Enum):
    """Backends that can apply resource controls."""

    MACOS_SEATBELT = "macos-seatbelt"
    LINUX_BWRAP = "linux-bwrap"
    RLIMIT = "rlimit"
    UNSUPPORTED = "unsupported"


# Which controls each backend actually applies. RLIMIT applies the full set;
# OS sandbox (Seatbelt/Bubblewrap) applies output bounding and (via the
# restricted runner) RLIMIT CPU/memory/process/file limits. Where a control is
# absent it is reported not-applied rather than implied.
def backend_supports_rlimit(platform: str) -> bool:
    """Return whether the platform supports RLIMIT-based controls."""

    _require_non_empty_str(platform, "platform")
    return platform in ("linux", "darwin") or platform.startswith("linux")


def applied_controls(
    budget: ResourceBudget,
    backend: ResourceBackend,
    *,
    platform: str = "",
) -> tuple[AppliedControl, ...]:
    """Compute the applied-control evidence for a budget on a backend.

    A control is applied only if the backend genuinely enforces it; otherwise it
    is recorded with ``applied=False`` and ``limit_value=None`` so the guarantee
    lowers rather than being implied.
    """

    _require_resource_budget(budget)
    _require_enum(backend, ResourceBackend, "backend")
    effective_platform = platform or sys.platform
    rlimit_ok = backend_supports_rlimit(effective_platform)
    controls: list[AppliedControl] = []
    for kind in ResourceControlKind:
        limit = _budget_value(budget, kind)
        applied = False
        if kind is ResourceControlKind.OUTPUT_BYTES:
            # Output bounding is applied by the executor on every backend.
            applied = True
        elif rlimit_ok and backend in (
            ResourceBackend.LINUX_BWRAP,
            ResourceBackend.MACOS_SEATBELT,
            ResourceBackend.RLIMIT,
        ):
            applied = True
        controls.append(
            AppliedControl(
                kind=kind,
                applied=applied,
                backend=backend.value,
                limit_value=limit if applied else None,
            )
        )
    return tuple(controls)


def _budget_value(budget: ResourceBudget, kind: ResourceControlKind) -> int:
    if kind is ResourceControlKind.CPU:
        return budget.cpu_seconds
    if kind is ResourceControlKind.MEMORY:
        return budget.memory_bytes
    if kind is ResourceControlKind.PROCESSES:
        return budget.process_count
    if kind is ResourceControlKind.OPEN_FILES:
        return budget.open_file_count
    if kind is ResourceControlKind.OUTPUT_BYTES:
        return budget.output_bytes
    return budget.wall_clock_seconds


def _require_schema_version(value: object) -> None:
    if value != RESOURCE_BUDGET_SCHEMA_VERSION:
        raise ValueError("unsupported resource budget schema version")


def _require_resource_budget(value: object) -> None:
    if not isinstance(value, ResourceBudget):
        raise ValueError("budget must be a ResourceBudget")


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be an exact {enum_type.__name__} value")


def _require_bool_type(value: object, label: str) -> None:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")


def _require_non_empty_str(value: object, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")


def _require_int_range(value: object, label: str, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")


__all__ = [
    "CONTROL_TO_GUARANTEE",
    "RESOURCE_BUDGET_SCHEMA_VERSION",
    "AppliedControl",
    "ResourceBackend",
    "ResourceBudget",
    "ResourceControlKind",
    "applied_controls",
    "backend_supports_rlimit",
]
