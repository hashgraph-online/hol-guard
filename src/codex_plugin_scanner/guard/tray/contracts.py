"""Typed contracts for the HOL Guard tray icon.

All platform-independent types, enums, state machines, and result shapes
live here. Platform adapters and the lifecycle service consume these
contracts — never the reverse.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------

LOCATOR_SCHEMA_VERSION: int = 1
"""Current private locator schema version.

Increment when the locator JSON structure changes. Older versions must
report ``unsupported_schema`` rather than silently deleting unknown state.
"""

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrayPlatform(str, enum.Enum):
    """Operating-system platform for tray registration."""

    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"

    @classmethod
    def current(cls) -> TrayPlatform | None:
        """Return the current platform or None if unsupported."""
        import sys

        if sys.platform == "darwin":
            return cls.MACOS
        if sys.platform == "win32":
            return cls.WINDOWS
        if sys.platform.startswith("linux"):
            return cls.LINUX
        return None


class TrayBackend(str, enum.Enum):
    """pystray backend selected for the current platform/session."""

    APPKIT = "appkit"
    """macOS NSStatusItem via PyObjC."""

    WIN32 = "win32"
    """Windows NotifyIcon via Win32 API."""

    APPINDICATOR = "appindicator"
    """Linux AppIndicator/Ayatana."""

    GTK = "gtk"
    """Linux GTK status icon."""

    XORG = "xorg"
    """Linux Xorg fallback."""

    NONE = "none"
    """No usable backend detected."""


class TrayState(str, enum.Enum):
    """Lifecycle state of the tray icon for one Guard home."""

    ABSENT = "absent"
    """No registration, no running process."""

    SUPPORTED = "supported"
    """Platform is capable but nothing is installed."""

    INSTALLED = "installed"
    """Registration exists but process is not running."""

    STARTING = "starting"
    """Process launched, awaiting readiness confirmation."""

    RUNNING = "running"
    """Process is running and icon is visible."""

    STOPPING = "stopping"
    """Stop requested, awaiting process exit."""

    STALE = "stale"
    """Locator exists but process is dead or unverified."""

    REPAIR_REQUIRED = "repair_required"
    """Registration or locator is malformed and needs repair."""

    UNSUPPORTED = "unsupported"
    """Platform/session lacks a usable tray backend."""

    FAILED = "failed"
    """Last operation failed; see reason code."""

    @classmethod
    def valid_transitions(cls, current: TrayState) -> frozenset[TrayState]:
        """Return the set of states reachable from ``current``."""
        _transitions: dict[TrayState, frozenset[TrayState]] = {
            cls.ABSENT: frozenset({cls.SUPPORTED, cls.UNSUPPORTED}),
            cls.SUPPORTED: frozenset({cls.INSTALLED, cls.UNSUPPORTED, cls.ABSENT}),
            cls.INSTALLED: frozenset({cls.STARTING, cls.STALE, cls.REPAIR_REQUIRED, cls.ABSENT, cls.SUPPORTED}),
            cls.STARTING: frozenset({cls.RUNNING, cls.FAILED, cls.STALE}),
            cls.RUNNING: frozenset({cls.STOPPING, cls.STALE, cls.FAILED}),
            cls.STOPPING: frozenset({cls.INSTALLED, cls.STALE, cls.ABSENT}),
            cls.STALE: frozenset({cls.STARTING, cls.REPAIR_REQUIRED, cls.ABSENT, cls.SUPPORTED}),
            cls.REPAIR_REQUIRED: frozenset({cls.INSTALLED, cls.ABSENT, cls.SUPPORTED}),
            cls.UNSUPPORTED: frozenset({cls.ABSENT}),
            cls.FAILED: frozenset({cls.STARTING, cls.REPAIR_REQUIRED, cls.ABSENT, cls.SUPPORTED}),
        }
        return _transitions.get(current, frozenset())

    def can_transition_to(self, target: TrayState) -> bool:
        """Check whether ``self`` can transition to ``target``."""
        return target in TrayState.valid_transitions(self)


class TrayReasonCode(str, enum.Enum):
    """Stable reason codes for tray operations and diagnostics."""

    OK = "ok"
    ALREADY_RUNNING = "already_running"
    ALREADY_INSTALLED = "already_installed"
    NOT_INSTALLED = "not_installed"
    NOT_RUNNING = "not_running"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    UNSUPPORTED_SESSION = "unsupported_session"
    BACKEND_IMPORT_FAILED = "backend_import_failed"
    BACKEND_INIT_FAILED = "backend_init_failed"
    DEPENDENCY_MISSING = "dependency_missing"
    NO_GRAPHICAL_SESSION = "no_graphical_session"
    NO_DISPLAY = "no_display"
    STARTUP_REGISTRATION_FAILED = "startup_registration_failed"
    STARTUP_REGISTRATION_MALFORMED = "startup_registration_malformed"
    STARTUP_REGISTRATION_COLLISION = "startup_registration_collision"
    LOCATOR_MALFORMED = "locator_malformed"
    LOCATOR_STALE = "locator_stale"
    LOCATOR_SCHEMA_UNSUPPORTED = "locator_schema_unsupported"
    PROCESS_NOT_OWNED = "process_not_owned"
    PROCESS_PID_REUSED = "process_pid_reused"
    PROCESS_START_TIMEOUT = "process_start_timeout"
    PROCESS_STOP_TIMEOUT = "process_stop_timeout"
    DAEMON_UNAVAILABLE = "daemon_unavailable"
    DASHBOARD_OPEN_FAILED = "dashboard_open_failed"
    AUTH_TOKEN_MISSING = "auth_token_missing"
    UPDATE_HANDOFF_FAILED = "update_handoff_failed"
    LAUNCHER_PATH_CHANGED = "launcher_path_changed"
    CRASH_LOOP_DETECTED = "crash_loop_detected"
    INTERNAL_ERROR = "internal_error"


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrayCapability:
    """Result of probing whether the current platform/session can show a tray icon.

    ``supported`` is True only when both the OS and a usable graphical tray
    backend are available. OS name alone is insufficient.
    """

    platform: TrayPlatform | None
    backend: TrayBackend
    supported: bool
    reason: TrayReasonCode
    details: str = ""
    """Human-readable explanation of why the capability is or is not available."""

    def to_payload(self) -> dict[str, object]:
        return {
            "platform": self.platform.value if self.platform else None,
            "backend": self.backend.value,
            "supported": self.supported,
            "reason": self.reason.value,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Process identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrayProcessIdentity:
    """Complete identity of a running tray process.

    PID alone is insufficient — PID reuse could cause us to kill an unrelated
    process. All fields must match before any stop/kill decision.
    """

    pid: int
    process_start_fingerprint: str
    """OS-level process start time or create-time stamp, used to detect PID reuse."""

    executable: str
    """Absolute path to the Python interpreter running the tray."""

    command: str
    """Full command line of the tray process."""

    guard_home: str
    """Resolved Guard home directory for this tray instance."""

    package_version: str
    """HOL Guard package version at process start."""

    backend: TrayBackend
    """Selected pystray backend."""

    registration_generation: int
    """Monotonic counter incremented on each registration change."""

    def matches(self, other: TrayProcessIdentity) -> bool:
        """Check whether two identities refer to the same owned process.

        All distinguishing fields must match: PID, start fingerprint,
        executable, command line, guard home, package version, backend, and
        registration generation. A mismatch on any field means the PID may
        have been reused or the process replaced — refuse to act on it.
        """
        return (
            self.pid == other.pid
            and self.process_start_fingerprint == other.process_start_fingerprint
            and self.executable == other.executable
            and self.command == other.command
            and self.guard_home == other.guard_home
            and self.package_version == other.package_version
            and self.backend == other.backend
            and self.registration_generation == other.registration_generation
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "process_start_fingerprint": self.process_start_fingerprint,
            "executable": self.executable,
            "command": self.command,
            "guard_home": self.guard_home,
            "package_version": self.package_version,
            "backend": self.backend.value,
            "registration_generation": self.registration_generation,
        }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrayRegistration:
    """Serialized platform startup registration (LaunchAgent / scheduled task / XDG autostart).

    This is the inspected state of the OS-level startup object, not the
    generated content. It must be byte-for-byte or identity-matched before
    any modification.
    """

    platform: TrayPlatform
    label: str
    """Stable platform-specific identifier (e.g. ``org.hol.guard.tray``)."""

    target_path: str
    """Absolute path to the startup registration file/object."""

    program_arguments: tuple[str, ...]
    """Structured argument array passed to the launcher — never a shell string."""

    run_at_login: bool
    """Whether the registration starts the tray at graphical login."""

    owned: bool
    """Whether the registration is verifiably HOL Guard-owned."""

    generation: int
    """Registration generation counter for identity verification."""

    def to_payload(self) -> dict[str, object]:
        return {
            "platform": self.platform.value,
            "label": self.label,
            "target_path": self.target_path,
            "program_arguments": list(self.program_arguments),
            "run_at_login": self.run_at_login,
            "owned": self.owned,
            "generation": self.generation,
        }


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrayStatus:
    """Complete status of the tray icon for one Guard home.

    This is the read-only result returned by ``hol-guard tray status`` and
    consumed by the dashboard settings UI. It never contains secrets,
    tokens, or authenticated URL fragments.
    """

    state: TrayState
    capability: TrayCapability
    registration: TrayRegistration | None
    process: TrayProcessIdentity | None
    reason: TrayReasonCode
    recovery_command: str
    """Exact CLI command the user can run to recover from the current state."""

    last_ready: datetime | None
    """Last time the tray reported readiness, or None."""

    def to_payload(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "capability": self.capability.to_payload(),
            "registration": self.registration.to_payload() if self.registration else None,
            "process": self.process.to_payload() if self.process else None,
            "reason": self.reason.value,
            "recovery_command": self.recovery_command,
            "last_ready": self.last_ready.isoformat() if self.last_ready else None,
        }


# ---------------------------------------------------------------------------
# Lifecycle result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrayLifecycleResult:
    """Result of a tray lifecycle operation (install/start/stop/restart/uninstall).

    Every CLI command and daemon action returns this shape. The ``ok`` field
    is the authoritative success indicator; ``reason`` provides the stable
    machine-readable code for diagnostics and troubleshooting.
    """

    ok: bool
    state: TrayState
    reason: TrayReasonCode
    message: str
    """Human-readable summary suitable for Rich rendering."""

    recovery_command: str = ""
    """CLI command to recover, or empty if not applicable."""

    process: TrayProcessIdentity | None = None
    """Process identity if a process was started or is running."""

    def to_payload(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "state": self.state.value,
            "reason": self.reason.value,
            "message": self.message,
            "recovery_command": self.recovery_command,
            "process": self.process.to_payload() if self.process else None,
        }


# ---------------------------------------------------------------------------
# Private locator (on-disk state)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TrayLocator:
    """Private on-disk locator for a running tray process.

    Stored under ``guard_home`` with restrictive permissions. Contains
    complete process identity for safe stop/restart decisions. Never
    contains daemon tokens, URL fragments, or secrets.

    The locator is written atomically and validated before any process
    control decision. A stale or malformed locator is treated as
    non-owned state — never as proof that a process may be killed.
    """

    schema_version: int
    package_version: str
    pid: int
    process_start_fingerprint: str
    executable: str
    command: str
    guard_home: str
    backend: TrayBackend
    registration_generation: int
    last_ready: datetime | None = None
    """Last time the tray process reported readiness."""

    crash_count: int = 0
    """Number of abnormal exits since the last successful start."""

    last_crash: datetime | None = None
    """Timestamp of the most recent abnormal exit."""

    def to_process_identity(self) -> TrayProcessIdentity:
        """Convert to an immutable process identity for validation."""
        return TrayProcessIdentity(
            pid=self.pid,
            process_start_fingerprint=self.process_start_fingerprint,
            executable=self.executable,
            command=self.command,
            guard_home=self.guard_home,
            package_version=self.package_version,
            backend=self.backend,
            registration_generation=self.registration_generation,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "package_version": self.package_version,
            "pid": self.pid,
            "process_start_fingerprint": self.process_start_fingerprint,
            "executable": self.executable,
            "command": self.command,
            "guard_home": self.guard_home,
            "backend": self.backend.value,
            "registration_generation": self.registration_generation,
            "last_ready": self.last_ready.isoformat() if self.last_ready else None,
            "crash_count": self.crash_count,
            "last_crash": self.last_crash.isoformat() if self.last_crash else None,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, object]) -> TrayLocator:
        """Parse a locator from a JSON-decoded payload.

        Raises ``ValueError`` if the schema version is unsupported or
        required fields are missing/invalid. Callers must catch this and
        report ``locator_malformed`` or ``locator_schema_unsupported``.
        """
        schema = _coerce_int(payload.get("schema_version"))
        if schema == 0:
            raise ValueError("missing schema_version")
        if schema > LOCATOR_SCHEMA_VERSION:
            raise ValueError(f"unsupported locator schema version {schema} > {LOCATOR_SCHEMA_VERSION}")

        backend_raw = payload.get("backend")
        try:
            backend = TrayBackend(str(backend_raw)) if backend_raw else TrayBackend.NONE
        except ValueError:
            backend = TrayBackend.NONE

        last_ready_raw = payload.get("last_ready")
        last_ready = _parse_datetime(last_ready_raw) if last_ready_raw else None

        last_crash_raw = payload.get("last_crash")
        last_crash = _parse_datetime(last_crash_raw) if last_crash_raw else None

        return cls(
            schema_version=schema,
            package_version=str(payload.get("package_version", "")),
            pid=_coerce_int(payload.get("pid")),
            process_start_fingerprint=str(payload.get("process_start_fingerprint", "")),
            executable=str(payload.get("executable", "")),
            command=str(payload.get("command", "")),
            guard_home=str(payload.get("guard_home", "")),
            backend=backend,
            registration_generation=_coerce_int(payload.get("registration_generation")),
            last_ready=last_ready,
            crash_count=_coerce_int(payload.get("crash_count", 0)),
            last_crash=last_crash,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_int(value: object) -> int:
    """Safely coerce a value to int, returning 0 on failure."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _parse_datetime(value: object) -> datetime | None:
    """Parse an ISO-format datetime string, returning None on failure."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRAY_REGISTRATION_LABEL = "org.hol.guard.tray"
"""Stable platform-agnostic registration label used across all platforms."""

MAX_CRASH_RETRIES = 3
"""Maximum restart attempts within the crash-loop window."""

CRASH_LOOP_WINDOW_SECONDS = 600
"""10-minute window for crash-loop detection."""

PROCESS_START_TIMEOUT_SECONDS = 15
"""Maximum time to wait for a tray process to report readiness."""

PROCESS_STOP_TIMEOUT_SECONDS = 5
"""Maximum time to wait for a tray process to exit after a stop request."""

DASHBOARD_OPEN_COALESCE_SECONDS = 2.0
"""Minimum interval between dashboard-open activations from the tray."""
