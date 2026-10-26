"""Collect the executables configured MCP servers would launch.

Candidates come from the MCP server entries Guard already reads from harness
configs. This module only discovers those servers and builds the native
``runtime-identity-probe`` launch request: each server's configured command,
its own ``PATH`` when it sets one, the launch directory, and the process
environment values a search path may reference. The native probe resolves the
launch (search path lookup, relative anchoring, ``#!`` interpreter) and
describes the files without starting anything; this module maps its reply back
to the servers that launch each executable. Environment values go to the
native command and never into a report.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .adapters.mcp_servers import observable_stdio_servers_with_proxy
from .models import HarnessDetection
from .runtime_identity_assessment import RuntimeIdentityError
from .runtime_identity_probe import RuntimeProbe, probe_runtime_launches

MAX_RUNTIME_CANDIDATES = 64
# Variables the native lookup always needs: the search path, its extensions and the home directory.
_ALWAYS_SHARED = frozenset({"PATH", "PATHEXT", "HOME", "USERPROFILE"})
_NAME = re.compile(r"\w+")
_ROLES = frozenset({"launch", "interpreter"})


@dataclass(frozen=True)
class RuntimeCandidate:
    """One executable path and the configured servers that launch it."""

    path: str
    sources: tuple[tuple[str, str, str], ...]  # (harness, server name, role)


@dataclass(frozen=True)
class UnresolvedLaunch:
    """A configured command no search path resolved to an executable."""

    harness: str
    server: str
    command: str
    lookup: str  # "search_path" for a bare command, "configured_path" for an explicit path


@dataclass(frozen=True)
class RuntimeCandidates:
    candidates: tuple[RuntimeCandidate, ...]
    unresolved: tuple[UnresolvedLaunch, ...]
    truncated: bool


@dataclass(frozen=True)
class _Server:
    harness: str
    name: str
    command: str


def collect_runtime_candidates(
    detections: Sequence[HarnessDetection],
    *,
    environment: Mapping[str, str] | None = None,
    workspace_dir: Path | None = None,
    limit: int = MAX_RUNTIME_CANDIDATES,
) -> tuple[RuntimeCandidates, RuntimeProbe]:
    """Resolve and describe every enabled stdio MCP server's launch executable natively."""

    process_environment = os.environ if environment is None else environment
    # A launch runs in the workspace, or in this process's directory without one.
    launch_dir = os.path.abspath(workspace_dir if workspace_dir is not None else Path.cwd())
    servers: list[_Server] = []
    specs: list[dict[str, object]] = []
    for detection in detections:
        for server in observable_stdio_servers_with_proxy(detection):
            if not server.enabled:
                continue
            command = server.command.strip()
            servers.append(_Server(server.harness, server.name, command))
            spec: dict[str, object] = {"command": command, "launch_dir": launch_dir}
            configured = _configured_path(server.env)
            if configured is not None:
                spec["configured_path"] = configured
            specs.append(spec)
    if not specs:
        return RuntimeCandidates((), (), False), RuntimeProbe((), (), (), (), False)
    probe = probe_runtime_launches(
        specs,
        environment=_shared_environment(process_environment, specs),
        candidate_limit=limit,
    )
    return _map_launches(servers, probe), probe


def _configured_path(server_env: Mapping[str, str]) -> str | None:
    return next((value for key, value in server_env.items() if key.upper() == "PATH"), None)


def _shared_environment(environment: Mapping[str, str], specs: Sequence[dict[str, object]]) -> dict[str, str]:
    """Only the variables a launch could read: the lookup variables and names a configured PATH mentions."""

    mentioned = {
        word.upper()
        for spec in specs
        if isinstance(path := spec.get("configured_path"), str)
        for word in _NAME.findall(path)
    }
    wanted = _ALWAYS_SHARED | mentioned
    return {key: value for key, value in environment.items() if key.upper() in wanted}


def _map_launches(servers: Sequence[_Server], probe: RuntimeProbe) -> RuntimeCandidates:
    if len(probe.launches) != len(servers):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    found: dict[str, list[tuple[str, str, str]]] = {}
    unresolved: list[UnresolvedLaunch] = []
    for server, launch in zip(servers, probe.launches, strict=True):
        if launch["state"] == "unresolved":
            lookup = launch.get("lookup")
            unresolved.append(
                UnresolvedLaunch(
                    server.harness,
                    server.name,
                    server.command,
                    lookup if isinstance(lookup, str) else "search_path",
                )
            )
            continue
        for target in _targets(launch):
            found.setdefault(target["path"], []).append((server.harness, server.name, target["role"]))
    candidates = tuple(
        RuntimeCandidate(path=path, sources=tuple(dict.fromkeys(sources))) for path, sources in sorted(found.items())
    )
    return RuntimeCandidates(
        candidates=candidates, unresolved=tuple(unresolved), truncated=probe.candidate_limit_reached
    )


def _targets(launch: Mapping[str, object]) -> list[dict[str, str]]:
    targets = launch.get("targets")
    if not isinstance(targets, list):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    rows: list[dict[str, str]] = []
    for target in targets:
        path = target.get("path") if isinstance(target, dict) else None
        role = target.get("role") if isinstance(target, dict) else None
        if not isinstance(path, str) or role not in _ROLES:
            raise RuntimeIdentityError("runtime_identity_probe_failed")
        rows.append({"path": path, "role": str(role)})
    return rows


__all__ = [
    "MAX_RUNTIME_CANDIDATES",
    "RuntimeCandidate",
    "RuntimeCandidates",
    "UnresolvedLaunch",
    "collect_runtime_candidates",
]
