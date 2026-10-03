"""Authenticated verification for an already-running Guard daemon."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ..runtime_transition import TransitionPlan

from .discovery import load_authenticated_daemon_state
from .manager import GUARD_DAEMON_COMPATIBILITY_VERSION, load_guard_daemon_auth_token


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
        from ..runtime_transition import TransitionError

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


def _proxy_disabled_health_details(
    url: str,
    auth_token: str,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object] | None:
    """Use the bounded loopback client without changing authenticated identity checks."""
    from .client import read_guard_health_details

    if deadline_monotonic is None:
        return read_guard_health_details(url, auth_token)
    return read_guard_health_details(url, auth_token, deadline_monotonic=deadline_monotonic)


def verified_live_guard_daemon_identity(
    guard_home: Path,
    *,
    expected_artifact: DaemonArtifactBinding | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, object] | None:
    """Return authenticated live daemon identity after state and health agree."""

    if deadline_monotonic is not None and (
        isinstance(deadline_monotonic, bool)
        or not math.isfinite(deadline_monotonic)
        or time.monotonic() >= deadline_monotonic
    ):
        return None
    state = load_authenticated_daemon_state(guard_home)
    if not isinstance(state, dict):
        return None
    if expected_artifact is not None and not expected_artifact.matches(state):
        return None
    version_text = state.get("package_version")
    host = state.get("host")
    port = state.get("port")
    pid = state.get("pid")
    runtime_fingerprint = state.get("runtime_fingerprint")
    token = load_guard_daemon_auth_token(guard_home)
    if (
        not isinstance(version_text, str)
        or not isinstance(host, str)
        or host not in {"127.0.0.1", "::1"}
        or not isinstance(port, int)
        or not 1 <= port <= 65_535
        or state.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION
        or not isinstance(runtime_fingerprint, str)
        or not runtime_fingerprint
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(token, str)
        or not token
    ):
        return None
    url_host = f"[{host}]" if host == "::1" else host
    daemon_url = f"http://{url_host}:{port}"
    details = (
        _proxy_disabled_health_details(daemon_url, token)
        if deadline_monotonic is None
        else _proxy_disabled_health_details(daemon_url, token, deadline_monotonic=deadline_monotonic)
    )
    identity_fields = ("package_version", "compatibility_version", "runtime_fingerprint", "pid")
    details_guard_home = details.get("guard_home") if isinstance(details, dict) else None
    if (
        not isinstance(details, dict)
        or details.get("ok") is not True
        or not isinstance(details_guard_home, str)
        or not details_guard_home
        or any(details.get(field) != state.get(field) for field in identity_fields)
    ):
        return None
    try:
        resolved_details_home = Path(details_guard_home).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved_details_home != guard_home.expanduser().resolve():
        return None
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return None
    if load_authenticated_daemon_state(guard_home) != state or (
        deadline_monotonic is not None and time.monotonic() >= deadline_monotonic
    ):
        return None
    return {**state, "daemon_url": daemon_url}


__all__ = ["DaemonArtifactBinding", "verified_live_guard_daemon_identity"]
