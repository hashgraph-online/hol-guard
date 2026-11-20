"""Live daemon identity and peer checks, answered by native `daemon-manage`.

The runtime reads the authenticated daemon state, proves it with the
daemon's health details (and, when asked, a dashboard session), and decides
which live daemon a caller may use or must keep. The daemon auth value is
returned only for an endpoint the caller is about to call.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_daemon_manage import _ask, _current_state

if TYPE_CHECKING:
    from .runtime_transition import TransitionPlan


@dataclass(frozen=True)
class DaemonArtifactBinding:
    """A read-only identity filter, never a lifecycle authorization capability."""

    executable: Path
    executable_sha256: str
    package_version: str

    def __post_init__(self) -> None:
        if (
            not self.executable.is_absolute()
            or len(self.executable_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.executable_sha256)
            or not self.package_version
        ):
            raise ValueError("Exact daemon artifact binding is invalid.")

    @classmethod
    def from_transition_plan(cls, plan: TransitionPlan, side: str) -> DaemonArtifactBinding:
        """Use the planned executable dependency, not an archive receipt digest."""
        from .runtime_transition import TransitionError

        if side not in {"candidate", "predecessor"}:
            raise TransitionError("daemon_artifact_binding_invalid")
        payload = plan.payload()
        artifact = cast(dict[str, object], payload[side])
        path = Path(str(artifact["path"]))
        for change in cast(list[dict[str, object]], payload["files"]):
            identity = change.get("artifact_identity")
            digest = change.get("expected_digest")
            if (
                change["path"] == str(path)
                and isinstance(identity, dict)
                and cast(dict[str, object], identity).get("role") == "artifact"
                and isinstance(digest, str)
            ):
                return cls(path, digest, str(artifact["version"]))
        raise TransitionError("daemon_artifact_dependency_missing")

    def matches(self, state: dict[str, object]) -> bool:
        return (
            state.get("executable") == str(self.executable)
            and state.get("source_root") == str(self.executable)
            and state.get("runtime_fingerprint") == self.executable_sha256
            and state.get("package_version") == self.package_version
        )

    def request(self) -> dict[str, object]:
        return {
            "executable": str(self.executable),
            "executable_sha256": self.executable_sha256,
            "package_version": self.package_version,
        }


def _mapping(value: object) -> dict[str, object] | None:
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def probe_live_guard_daemon_identity(
    guard_home: Path,
    *,
    session_timeout: float = 1.0,
    verify_dashboard: bool = True,
    expected_artifact: DaemonArtifactBinding | None = None,
    deadline_monotonic: float | None = None,
) -> tuple[dict[str, object] | None, str]:
    """Return identity plus a safe reason for health or session failure."""
    try:
        timeout = float(session_timeout)
    except (TypeError, ValueError, OverflowError):
        return None, "service_unresponsive"
    if deadline_monotonic is not None:
        if isinstance(deadline_monotonic, bool) or not math.isfinite(deadline_monotonic):
            return None, "service_unresponsive"
        timeout = min(timeout, deadline_monotonic - time.monotonic())
    if not math.isfinite(timeout) or timeout <= 0.0:
        return None, "service_unresponsive"
    try:
        answer = _ask(
            "live_identity",
            guard_home,
            timeout=timeout,
            verify_dashboard=verify_dashboard,
            expected_artifact=expected_artifact.request() if expected_artifact is not None else None,
        )
    except (OSError, RuntimeError, ValueError):
        return None, "identity_unverified"
    reason = answer.get("reason")
    return _mapping(answer.get("identity")), reason if isinstance(reason, str) else "identity_unverified"


def verified_live_guard_daemon_identity(
    guard_home: Path,
    *,
    session_timeout: float = 1.0,
    expected_artifact: DaemonArtifactBinding | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, object] | None:
    """Return authenticated live daemon identity after state and health agree."""
    identity, reason = probe_live_guard_daemon_identity(
        guard_home,
        session_timeout=session_timeout,
        verify_dashboard=False,
        expected_artifact=expected_artifact,
        deadline_monotonic=deadline_monotonic,
    )
    return identity if reason == "healthy" else None


def _peer(guard_home: Path, query: str, **args: object) -> dict[str, object]:
    try:
        return _ask("peer", guard_home, query=query, **args)
    except (OSError, RuntimeError, ValueError):
        return {}


def daemon_source_is_desktop_core(source_root: object) -> bool:
    """True when daemon state points at a Desktop Core sidecar tree."""
    if not isinstance(source_root, str) or not source_root.strip():
        return False
    from .native_daemon_manage import _implicit_daemon_guard_home

    return _peer(_implicit_daemon_guard_home(), "desktop_core", source_root=source_root).get("matches") is True


def live_desktop_owned_daemon(guard_home: Path) -> dict[str, object] | None:
    """A verified live daemon identity that Guard Desktop owns and respawns."""
    return _mapping(_peer(guard_home, "desktop_owned").get("identity"))


def load_guard_daemon_endpoint(guard_home: Path) -> tuple[str, str] | None:
    """A verified daemon endpoint: the current runtime's, else the Desktop owner's."""
    answer = _peer(guard_home, "endpoint", current=_current_state())
    url, auth = answer.get("url"), answer.get("auth")
    if isinstance(url, str) and url.strip() and isinstance(auth, str) and auth.strip():
        return url, auth
    return None


def load_guard_daemon_endpoint_url(guard_home: Path) -> str | None:
    """The URL of a verified current-runtime or Desktop-owned endpoint."""
    endpoint = load_guard_daemon_endpoint(guard_home)
    return endpoint[0] if endpoint is not None else None


def retained_newer_runtime_payload(
    guard_home: Path,
    *,
    minimum_version: str | None = None,
) -> dict[str, object] | None:
    """Retain a live newer runtime only after signed state and loopback health agree."""
    from .. import version as package_version

    required = minimum_version or package_version.__version__
    return _mapping(_peer(guard_home, "retained_newer", minimum_version=required).get("payload"))


def retained_desktop_owner_payload(
    guard_home: Path,
    *,
    minimum_version: str | None = None,
) -> dict[str, object] | None:
    """A refresh result that keeps a verified Desktop-owned daemon."""
    return _mapping(_peer(guard_home, "retained_desktop_owner", minimum_version=minimum_version).get("payload"))


def daemon_refresh_outcome_succeeded(payload: object, *, allow_not_running: bool = False) -> bool:
    """Accept a refresh that restarted, retained another owner, or found nothing running."""
    if not isinstance(payload, dict):
        return False
    status = payload.get("status")
    if status == "not_running":
        return allow_not_running
    return (
        status in {"restarted", "retained_newer_runtime", "retained_desktop_owner"}
        and payload.get("runtime_verified") is True
    )


def retained_desktop_owner_note(daemon_version: object) -> str:
    version_text = f" (version {daemon_version})" if isinstance(daemon_version, str) and daemon_version else ""
    return (
        f"Kept the Guard Desktop daemon{version_text} running; "
        "it will load the new package when the Desktop app updates."
    )


__all__ = [
    "DaemonArtifactBinding",
    "daemon_refresh_outcome_succeeded",
    "daemon_source_is_desktop_core",
    "live_desktop_owned_daemon",
    "load_guard_daemon_endpoint",
    "load_guard_daemon_endpoint_url",
    "probe_live_guard_daemon_identity",
    "retained_desktop_owner_note",
    "retained_desktop_owner_payload",
    "retained_newer_runtime_payload",
    "verified_live_guard_daemon_identity",
]
