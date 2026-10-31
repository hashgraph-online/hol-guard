"""Evidence contract for the HOL Plugin Release workflow.

A release run records what the plugin at one commit ships and how it scanned:
the scanner result, the Plugin Kit check summary, the runtimes the Kit can
package it for, and the plugin's permission surface (its MCP servers, the
hosts they reach, the environment variables they read, and whether it ships
hooks). HOL compares the surface with the previous release to show what
changed. When the release declares packages, the evidence also records the
digest and size of its CycloneDX SBOM, which binds that file to the
attestation.

Scanner findings, file contents, prompts, credentials, environment variable
values, header values and actor identity are never included.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal
from urllib.parse import urlsplit

from .plugin_release_sbom import SbomSummary

SCHEMA_VERSION = "plugin-release/v1"
CLAIM = (
    "This commit was scanned by HOL Guard and checked by the HOL Plugin Kit under the recorded "
    "versions, and the evidence carries a GitHub-signed provenance attestation. It does not mean "
    "vulnerability-free, and packaged runtimes were not load-tested."
)
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TEMPLATE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SEVERITIES = frozenset({"none", "info", "low", "medium", "high", "critical"})
_MAX_SERVERS = 50
_MAX_CODES = 50
_MAX_TEXT = 200

Visibility = Literal["public", "private"]


@dataclass(frozen=True)
class McpServerSurface:
    name: str
    transport: Literal["stdio", "http", "sse"]
    command: str | None
    package: str | None
    host: str | None
    env_vars: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeSupport:
    runtime: str
    supported: bool


@dataclass(frozen=True)
class PluginReleaseEvidence:
    schema_version: Literal["plugin-release/v1"]
    repository: str
    commit_sha: str
    ref: str
    workflow_run_id: str
    guard_version: str
    plugin_name: str | None
    plugin_version: str | None
    scan_profile: str
    score: int
    grade: str
    max_severity: str
    findings_total: int
    check_passed: bool
    check_errors: int
    check_warnings: int
    check_codes: tuple[str, ...]
    runtimes: tuple[RuntimeSupport, ...]
    skills: int
    commands: int
    agents: int
    hooks: bool
    mcp_servers: tuple[McpServerSurface, ...]
    generated_at: str
    visibility: Visibility
    claim: str
    sensitive_content_included: Literal[False]
    sbom: SbomSummary | None = None


def _text(value: object, *, limit: int = _MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned[:limit] if cleaned else None


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _command_name(command: str) -> str:
    """The program's file name, so local paths never reach the evidence."""

    name = PureWindowsPath(command).name if "\\" in command else PurePosixPath(command).name
    return name[:_MAX_TEXT] or command[:_MAX_TEXT]


_PACKAGE_LAUNCHERS = frozenset({"npx", "bunx", "uvx", "pnpx"})
_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*(?:(?:@|==)[A-Za-z0-9._+~^-]+)?$")


def _package(command: str, args: object) -> str | None:
    """The package a known launcher (npx, bunx, uvx, pnpx) starts.

    Only a value shaped like a package name is kept, so an argument that
    carries a token or a path is never copied into the evidence.
    """

    if _command_name(command).removesuffix(".cmd").removesuffix(".exe") not in _PACKAGE_LAUNCHERS:
        return None
    if not isinstance(args, list):
        return None
    for arg in args:
        if not isinstance(arg, str) or not arg or arg.startswith("-"):
            continue
        return arg if len(arg) <= _MAX_TEXT and _PACKAGE_RE.fullmatch(arg) else None
    return None


def _host(url: object) -> str | None:
    if not isinstance(url, str) or not url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower()[:_MAX_TEXT] if host else None


def _env_vars(server: Mapping[str, object]) -> tuple[str, ...]:
    names: set[str] = set()
    env = server.get("env")
    if isinstance(env, Mapping):
        names.update(value for value in env.values() if isinstance(value, str) and _ENV_NAME_RE.fullmatch(value))
    headers = server.get("headers")
    if isinstance(headers, Mapping):
        for value in headers.values():
            if isinstance(value, str):
                names.update(_TEMPLATE_RE.findall(value))
    return tuple(sorted(names))


def mcp_server_surface(name: str, server: Mapping[str, object]) -> McpServerSurface:
    command = _text(server.get("command"))
    transport_value = server.get("transport")
    transport: Literal["stdio", "http", "sse"]
    if command is not None:
        transport = "stdio"
    elif transport_value == "sse":
        transport = "sse"
    else:
        transport = "http"
    return McpServerSurface(
        name=name[:_MAX_TEXT],
        transport=transport,
        command=_command_name(command) if command else None,
        package=_package(command, server.get("args")) if command else None,
        host=None if command else _host(server.get("url")),
        env_vars=_env_vars(server),
    )


def build_plugin_release_evidence(
    *,
    repository: str,
    commit_sha: str,
    ref: str,
    workflow_run_id: str,
    guard_version: str,
    scan_profile: str,
    score: int,
    grade: str,
    max_severity: str,
    findings_total: int,
    check_report: Mapping[str, object],
    visibility: Visibility,
    generated_at: datetime | None = None,
) -> PluginReleaseEvidence:
    """Builds evidence from the scanner outputs and ``hol-guard plugin check --json``."""

    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must be owner/name")
    if not _SHA_RE.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a lowercase 40-character git SHA")
    if not ref or len(ref) > 255:
        raise ValueError("ref is invalid")
    if not workflow_run_id.isdigit() or len(workflow_run_id) > 32:
        raise ValueError("workflow_run_id must be numeric")
    if not guard_version or len(guard_version) > 64:
        raise ValueError("guard_version is invalid")
    if not scan_profile or len(scan_profile) > 64:
        raise ValueError("scan_profile is invalid")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("score must be an integer from 0 to 100")
    if not grade or len(grade) > 8:
        raise ValueError("grade is invalid")
    if max_severity not in _SEVERITIES:
        raise ValueError("max_severity is invalid")
    if isinstance(findings_total, bool) or not isinstance(findings_total, int) or findings_total < 0:
        raise ValueError("findings_total must be a non-negative integer")
    if visibility not in {"public", "private"}:
        raise ValueError("visibility must be public or private")
    observed = generated_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")

    plugin = check_report.get("plugin")
    plugin = plugin if isinstance(plugin, Mapping) else {}
    summary = check_report.get("summary")
    summary = summary if isinstance(summary, Mapping) else {}
    diagnostics = check_report.get("diagnostics")
    codes = sorted(
        {
            code
            for item in (diagnostics if isinstance(diagnostics, Sequence) else ())
            if isinstance(item, Mapping) and isinstance(code := item.get("code"), str) and code
        }
    )[:_MAX_CODES]
    runtimes_value = check_report.get("runtimes")
    runtimes = tuple(
        sorted(
            (
                RuntimeSupport(runtime=runtime[:64], supported=item.get("supported") is True)
                for item in (runtimes_value if isinstance(runtimes_value, Sequence) else ())
                if isinstance(item, Mapping) and isinstance(runtime := item.get("runtime"), str)
            ),
            key=lambda support: support.runtime,
        )
    )
    servers_value = plugin.get("mcp_servers")
    servers = tuple(
        mcp_server_surface(name, server)
        for name, server in sorted((servers_value if isinstance(servers_value, Mapping) else {}).items())
        if isinstance(name, str) and isinstance(server, Mapping)
    )
    if len(servers) > _MAX_SERVERS:
        # A partial surface would hide what the release can reach, so refuse instead of truncating.
        raise ValueError(f"the plugin declares more than {_MAX_SERVERS} MCP servers")
    skills = plugin.get("skills")
    commands = plugin.get("commands")
    agents = plugin.get("agents")

    return PluginReleaseEvidence(
        schema_version=SCHEMA_VERSION,
        repository=repository,
        commit_sha=commit_sha,
        ref=ref,
        workflow_run_id=workflow_run_id,
        guard_version=guard_version,
        plugin_name=_text(plugin.get("name")),
        plugin_version=_text(plugin.get("version"), limit=100),
        scan_profile=scan_profile,
        score=score,
        grade=grade,
        max_severity=max_severity,
        findings_total=findings_total,
        check_passed=check_report.get("passed") is True,
        check_errors=_count(summary.get("errors")),
        check_warnings=_count(summary.get("warnings")),
        check_codes=tuple(codes),
        runtimes=runtimes,
        skills=len(skills) if isinstance(skills, list) else 0,
        commands=len(commands) if isinstance(commands, list) else 0,
        agents=len(agents) if isinstance(agents, list) else 0,
        hooks=isinstance(plugin.get("hooks"), str),
        mcp_servers=servers,
        generated_at=observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        visibility=visibility,
        claim=CLAIM,
        sensitive_content_included=False,
    )


def plugin_release_evidence_dict(evidence: PluginReleaseEvidence) -> dict[str, object]:
    document = asdict(evidence)
    if document["sbom"] is None:
        # Evidence without an SBOM keeps the exact bytes, and digest, it had before the field existed.
        del document["sbom"]
    return document


def plugin_release_evidence_json(evidence: PluginReleaseEvidence) -> str:
    return json.dumps(plugin_release_evidence_dict(evidence), sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def plugin_release_evidence_sha256(evidence: PluginReleaseEvidence) -> str:
    return hashlib.sha256(plugin_release_evidence_json(evidence).encode("utf-8")).hexdigest()
