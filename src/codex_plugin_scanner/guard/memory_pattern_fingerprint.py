"""Normalized memory pattern fingerprints for Guard decision events.

A memory pattern fingerprint groups repeated human decisions on the same
behavioral pattern so Cloud can build Suggested Memory candidates. Fingerprints
must be stable enough to group equivalent requests but narrow enough to avoid
over-broad trust: ``npm install lodash`` and ``npm i lodash`` group together,
while ``read`` or ``pi:project:read`` alone must NEVER be a fingerprint.

Fingerprint format: ``<kind>:<dimension1>:<dimension2>:...`` where dimensions
are lowercased, order-stable, and stripped of volatile qualifiers (paths,
versions, timestamps, identifiers). Each builder returns ``None`` when the
input is too generic to remember safely.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

MemoryPatternKind = Literal[
    "command_pattern",
    "package_install_pattern",
    "mcp_tool_pattern",
    "file_read_pattern",
    "generic_artifact_pattern",
]

def build_exact_command_memory_artifact_id(command: str | None) -> str | None:
    """Build a local policy key that matches only the remembered command."""
    normalized = command.strip() if command is not None else ""
    if not normalized:
        return None
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"memory:exact-command:{digest}"

# Bare labels that are too generic to ever anchor reusable memory. They describe
# a capability category, not a concrete behavior the user repeatedly chose.
_GENERIC_FINGERPRINT_LABELS: frozenset[str] = frozenset(
    {
        "read",
        "write",
        "bash",
        "grep",
        "shell",
        "job",
        "task",
        "edit",
        "eval",
        "ask",
        "todo",
        "yield",
        "goal",
        "browser",
        "irc",
        "github",
        "glob",
        "tool",
        "mcp",
        "skill",
        "rg",
        "cat",
        "pi:project:read",
        "pi:project:write",
        "pi:project",
        "project:read",
        "project:write",
    }
)

# Commands whose only value is a single generic verb (no concrete target).
_BARE_COMMAND_VERBS: frozenset[str] = frozenset(
    {"read", "write", "bash", "grep", "shell", "edit", "eval", "ls", "echo"}
)

_PACKAGE_MANAGERS: frozenset[str] = frozenset(
    {"npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "gem", "brew"}
)
_PACKAGE_INSTALL_SUBCOMMANDS: frozenset[str] = frozenset({"install", "i", "add", "ci", "in", "up", "upgrade"})
_TOOL_ACTION_ARTIFACT_TYPES: frozenset[str] = frozenset({"tool_action_request", "tool_output"})


@dataclass(frozen=True, slots=True)
class MemoryPatternFingerprint:
    """Stable fingerprint + the concrete dimensions that produced it."""

    fingerprint: str
    kind: MemoryPatternKind
    components: dict[str, str]

    def to_payload(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "components": dict(self.components),
        }


def build_memory_pattern_fingerprint(
    *,
    command: str | None,
    artifact_type: str | None = None,
    artifact_id: str | None = None,
    artifact_name: str | None = None,
    harness: str | None = None,
) -> MemoryPatternFingerprint | None:
    """Build the most specific fingerprint available for a decision.

    Returns ``None`` when the available signal is too generic to anchor memory.
    Tool action/output rows use their concrete artifact identity rather than
    reinterpreting display text as a shell or package-manager command.
    """
    normalized_artifact_type = _normalize_token(artifact_type)
    if normalized_artifact_type in _TOOL_ACTION_ARTIFACT_TYPES:
        candidate = _try_generic_artifact(
            artifact_id,
            artifact_name,
            artifact_type,
            harness,
        )
    else:
        if command is not None and _has_unquoted_shell_control_operator(command):
            return None
        candidate = (
            _try_package_install(command, harness)
            or _try_mcp_tool(command, harness, artifact_id)
            or _try_file_read(command, harness, artifact_type)
            or _try_shell_command(command, harness)
            or _try_generic_artifact(artifact_id, artifact_name, artifact_type, harness)
        )
    if candidate is None:
        return None
    if _is_generic_label(candidate.fingerprint):
        return None
    return candidate


def _is_generic_label(fingerprint: str) -> bool:
    normalized = fingerprint.strip().lower()
    if not normalized:
        return True
    return normalized in _GENERIC_FINGERPRINT_LABELS


def _has_unquoted_shell_control_operator(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for character in command:
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if quote is None and character in {"\n", ";", "&", "|"}:
            return True
    return False


def _normalize_token(value: str | None) -> str | None:
    if value is None:
        return None
    token = value.strip().lower()
    return token or None


def _digest(kind: MemoryPatternKind, dimensions: Iterable[tuple[str, str | None]]) -> str:
    parts = [kind]
    for _key, value in dimensions:
        if value:
            parts.append(value)
    joined = ":".join(parts)
    if len(joined) <= 96:
        return joined
    # Long concrete commands hash to a stable short digest so grouping still
    # works without storing volatile path/identifier noise in the fingerprint.
    suffix = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    head = joined[:64].rstrip(":")
    return f"{head}:{suffix}"


def _split_command(command: str | None) -> list[str]:
    if command is None:
        return []
    cleaned = command.strip()
    if not cleaned:
        return []
    # Treat ``&&``, ``;``, ``|``, and newline as separators and take the first
    # segment — that is the concrete action the user is being asked about.
    first_segment = re.split(r"[\n;&|]+", cleaned)[0].strip()
    if not first_segment:
        return []
    return first_segment.split()


def _try_package_install(
    command: str | None,
    harness: str | None,
) -> MemoryPatternFingerprint | None:
    tokens = _split_command(command)
    if len(tokens) < 2:
        return None
    manager = tokens[0].lower()
    if manager not in _PACKAGE_MANAGERS:
        return None
    subcommand = tokens[1].lower() if len(tokens) >= 2 else None
    # ``bun add``, ``npm install``, ``pip install`` — subcommand then package.
    add_managers = {"cargo", "go", "uv"}
    install_subcommand = bool(subcommand and subcommand in _PACKAGE_INSTALL_SUBCOMMANDS)
    add_subcommand = manager in add_managers and subcommand == "add"
    is_install = install_subcommand or add_subcommand
    if not is_install:
        return None
    # Skip flags/options between the subcommand and the package name so commands
    # like ``npm install -g pm2`` or ``pip install -U requests`` resolve the
    # package rather than the flag.
    raw_package: str | None = None
    for token in tokens[2:]:
        if token.startswith("-"):
            continue
        raw_package = token
        break
    if raw_package is None:
        return None
    package = _strip_package_version(raw_package)
    if not package:
        return None
    ecosystem = _ecosystem_for_manager(manager)
    components = {
        "ecosystem": ecosystem,
        "package": package,
        "manager": manager,
    }
    if harness:
        components["harness"] = _normalize_token(harness) or "unknown"
    return MemoryPatternFingerprint(
        fingerprint=_digest("package_install_pattern", sorted(components.items())),
        kind="package_install_pattern",
        components=components,
    )


def _strip_package_version(raw_package: str) -> str:
    package = raw_package.strip().strip("\"'").strip()
    # Preserve npm scopes: a leading ``@`` denotes a scoped package
    # (``@types/node``), not a version separator. Only ``@`` that appears after
    # the first character pins a version (``lodash@1.0``).
    is_scoped = package.startswith("@")
    for separator in ("==", ">=", "<=", "!=", "~=", ">", "<"):
        if separator in package:
            package = package.split(separator, 1)[0]
    if is_scoped:
        # Scoped package: keep the leading scope, drop only a trailing version.
        if "@" in package[1:]:
            package = package[0] + package[1:].split("@", 1)[0]
    else:
        package = package.split("@", 1)[0]
    return package.strip().lower()


def _ecosystem_for_manager(manager: str) -> str:
    if manager in {"npm", "pnpm", "yarn", "bun"}:
        return "npm"
    if manager in {"pip", "pip3", "uv", "poetry"}:
        return "pypi"
    if manager == "cargo":
        return "cargo"
    if manager == "go":
        return "goproxy"
    if manager == "gem":
        return "rubygems"
    if manager == "brew":
        return "homebrew"
    return manager


def _try_mcp_tool(
    command: str | None,
    harness: str | None,
    artifact_id: str | None,
) -> MemoryPatternFingerprint | None:
    match = None
    if command:
        match = re.search(r"mcp__([a-z0-9_-]+)__([a-z0-9_]+)", command, re.IGNORECASE)
    if match:
        server = match.group(1).lower()
        tool = match.group(2).lower()
        if not server or not tool:
            return None
        components = {"server": server, "tool": tool}
        if harness:
            components["harness"] = _normalize_token(harness) or "unknown"
        return MemoryPatternFingerprint(
            fingerprint=_digest("mcp_tool_pattern", sorted(components.items())),
            kind="mcp_tool_pattern",
            components=components,
        )
    artifact = _normalize_token(artifact_id)
    if artifact and artifact.startswith("mcp:"):
        parts = artifact.split(":")
        if len(parts) >= 3:
            server = parts[1].lower()
            tool = parts[2].lower()
            components = {"server": server, "tool": tool}
            if harness:
                components["harness"] = _normalize_token(harness) or "unknown"
            return MemoryPatternFingerprint(
                fingerprint=_digest("mcp_tool_pattern", sorted(components.items())),
                kind="mcp_tool_pattern",
                components=components,
            )
    return None


def _try_file_read(
    command: str | None,
    harness: str | None,
    artifact_type: str | None,
) -> MemoryPatternFingerprint | None:
    if artifact_type is None or artifact_type.lower() not in {
        "file",
        "path",
        "config",
        "file_read",
        "file_read_request",
    }:
        return None
    tokens = _split_command(command)
    if not tokens:
        return None
    verb = tokens[0].lower()
    if verb not in {"read", "cat", "head", "tail", "less", "more", "view"}:
        return None
    if len(tokens) < 2:
        return None
    raw_path = tokens[1]
    family = _path_family(raw_path)
    if not family:
        return None
    components = {"verb": verb, "path_family": family}
    if harness:
        components["harness"] = _normalize_token(harness) or "unknown"
    return MemoryPatternFingerprint(
        fingerprint=_digest("file_read_pattern", sorted(components.items())),
        kind="file_read_pattern",
        components=components,
    )


def _path_family(raw_path: str) -> str | None:
    path = raw_path.strip().strip("\"'").strip()
    if not path or path.startswith("-"):
        return None
    normalized = re.sub(r"/+", "/", path).lower()
    # Collapse volatile identifiers (hashes, uuids, numbers, env vars).
    normalized = re.sub(r"\b[a-f0-9]{16,}\b", "<hash>", normalized)
    normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", normalized)
    normalized = re.sub(r"\$\{?\w+\}?", "<env>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    # Keep the directory family (first two segments) so repeated reads of the
    # same project area group, but the exact filename does not over-broaden.
    segments = [segment for segment in normalized.split("/") if segment]
    if not segments:
        return None
    family_segments = segments[:3]
    return "/".join(family_segments)


def _try_shell_command(
    command: str | None,
    harness: str | None,
) -> MemoryPatternFingerprint | None:
    tokens = _split_command(command)
    if len(tokens) < 2:
        return None
    executable = tokens[0].lower()
    if executable in _BARE_COMMAND_VERBS:
        return None
    # Normalize the subcommand family for common multi-word tools.
    subcommand = tokens[1].lower().lstrip("-")
    if not subcommand:
        return None
    components: dict[str, str] = {"executable": executable, "subcommand": subcommand}
    # Capture a concrete target for git/docker/gh/rg families when present.
    if executable in {"git", "docker", "gh", "rg", "grep", "curl", "kubectl"} and len(tokens) >= 3:
        target = tokens[2].lower().lstrip("-")
        if target and not target.startswith("-"):
            components["target"] = target
    if harness:
        components["harness"] = _normalize_token(harness) or "unknown"
    return MemoryPatternFingerprint(
        fingerprint=_digest("command_pattern", sorted(components.items())),
        kind="command_pattern",
        components=components,
    )


def _try_generic_artifact(
    artifact_id: str | None,
    artifact_name: str | None,
    artifact_type: str | None,
    harness: str | None,
) -> MemoryPatternFingerprint | None:
    artifact = _normalize_token(artifact_id) or _normalize_token(artifact_name)
    if not artifact:
        return None
    if _is_generic_label(artifact):
        return None
    components: dict[str, str] = {"artifact": artifact}
    kind_value = _normalize_token(artifact_type) or "artifact"
    components["artifact_type"] = kind_value
    if harness:
        components["harness"] = _normalize_token(harness) or "unknown"
    return MemoryPatternFingerprint(
        fingerprint=_digest("generic_artifact_pattern", sorted(components.items())),
        kind="generic_artifact_pattern",
        components=components,
    )
