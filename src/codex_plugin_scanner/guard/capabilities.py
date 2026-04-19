"""Capability normalization and delta scoring."""

from __future__ import annotations

import re
from pathlib import PurePath
from urllib.parse import urlsplit

from .models import GuardArtifact
from .types import CapabilityDelta, CapabilitySet, TransportKind

_URL_PATTERN = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
_HOST_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_PATH_PATTERN = re.compile(r"(~?/[\w./-]+|\.[/\\][\w./\\-]+)")
_NON_NETWORK_SUFFIXES = {
    "md",
    "json",
    "toml",
    "yaml",
    "yml",
    "txt",
    "py",
    "js",
    "ts",
    "sh",
    "cfg",
    "conf",
    "log",
    "tmp",
    "bak",
    "bin",
}
_SCRIPT_INTERPRETERS = {"python", "python3", "node", "ruby", "perl", "pwsh", "powershell"}
_SHELL_COMMANDS = {"bash", "sh", "zsh", "cmd", "powershell", "pwsh"}
_SUBPROCESS_TOKENS = (
    "subprocess",
    "os.system",
    "child_process",
    "spawn(",
    "exec(",
    "bash -c",
    "sh -c",
    "zsh -c",
    "powershell -command",
)
_SECRET_HINTS = (
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "python package credentials"),
    (".aws/credentials", "aws shared credentials"),
    (".ssh/", "ssh material"),
    (".gnupg/", "gpg material"),
    (".docker/config.json", "docker credentials"),
    (".kube/config", "kubeconfig"),
    (".git-credentials", "git credential store"),
)


def normalize_artifact_capabilities(artifact: GuardArtifact) -> CapabilitySet:
    """Normalize artifact-level capabilities into stable typed fields."""

    combined = _combined_text(artifact)
    network_hosts = sorted(_extract_network_hosts(combined, artifact.url))
    network_schemes = sorted(_extract_network_schemes(combined, artifact.url))
    filesystem_paths = sorted(set(_PATH_PATTERN.findall(combined)))
    secret_classes = sorted(_extract_secret_classes(combined, artifact))
    interpreters = sorted(_extract_interpreters(artifact, combined))
    shell_wrappers = sorted(_extract_shell_wrappers(artifact))
    subprocess_invocation = _has_subprocess_intent(combined, artifact)
    transport = _normalize_transport(artifact)

    return CapabilitySet(
        network_hosts=tuple(network_hosts),
        network_schemes=tuple(network_schemes),
        filesystem_paths=tuple(filesystem_paths),
        secret_classes=tuple(secret_classes),
        subprocess_invocation=subprocess_invocation,
        interpreters=tuple(interpreters),
        shell_wrappers=tuple(shell_wrappers),
        publisher=artifact.publisher,
        transport=transport,
    )


def compute_capability_delta(before: CapabilitySet | None, after: CapabilitySet) -> tuple[CapabilityDelta, ...]:
    """Compute semantic capability deltas between two normalized snapshots."""

    deltas: list[CapabilityDelta] = []
    if before is None:
        deltas.extend(_first_seen_deltas(after))
        return tuple(deltas)

    before_hosts = set(before.network_hosts)
    after_hosts = set(after.network_hosts)
    for host in sorted(after_hosts - before_hosts):
        deltas.append(
            CapabilityDelta(
                delta_type="new_network_host",
                before=None,
                after=host,
                severity=8,
                explanation=f"Artifact introduced a new remote host: {host}.",
            )
        )

    if before.publisher != after.publisher and after.publisher is not None:
        deltas.append(
            CapabilityDelta(
                delta_type="publisher_changed",
                before=before.publisher,
                after=after.publisher,
                severity=7,
                explanation="Artifact publisher changed from the previous snapshot.",
            )
        )

    if before.transport != after.transport:
        deltas.append(
            CapabilityDelta(
                delta_type="transport_changed",
                before=before.transport,
                after=after.transport,
                severity=6,
                explanation="Artifact transport changed and may alter execution boundaries.",
            )
        )

    new_secret_classes = sorted(set(after.secret_classes) - set(before.secret_classes))
    if new_secret_classes:
        deltas.append(
            CapabilityDelta(
                delta_type="secret_scope_expanded",
                before=", ".join(before.secret_classes) if before.secret_classes else None,
                after=", ".join(after.secret_classes),
                severity=9,
                explanation=(
                    "Artifact now references additional secret-bearing classes: " + ", ".join(new_secret_classes) + "."
                ),
            )
        )

    new_filesystem_paths = sorted(set(after.filesystem_paths) - set(before.filesystem_paths))
    if new_filesystem_paths:
        deltas.append(
            CapabilityDelta(
                delta_type="filesystem_scope_expanded",
                before=", ".join(before.filesystem_paths[:3]) if before.filesystem_paths else None,
                after=", ".join(after.filesystem_paths[:3]),
                severity=5,
                explanation="Artifact expanded filesystem path scope.",
            )
        )

    if not before.subprocess_invocation and after.subprocess_invocation:
        deltas.append(
            CapabilityDelta(
                delta_type="subprocess_added",
                before="false",
                after="true",
                severity=8,
                explanation="Artifact gained subprocess or shell execution behavior.",
            )
        )

    new_interpreters = sorted(set(after.interpreters) - set(before.interpreters))
    if new_interpreters:
        deltas.append(
            CapabilityDelta(
                delta_type="interpreter_changed",
                before=", ".join(before.interpreters) if before.interpreters else None,
                after=", ".join(after.interpreters),
                severity=6,
                explanation="Artifact now uses additional interpreters.",
            )
        )

    if set(after.shell_wrappers) != set(before.shell_wrappers):
        deltas.append(
            CapabilityDelta(
                delta_type="approval_surface_changed",
                before=", ".join(before.shell_wrappers) if before.shell_wrappers else None,
                after=", ".join(after.shell_wrappers) if after.shell_wrappers else None,
                severity=6,
                explanation="Artifact shell-wrapper behavior changed and requires review.",
            )
        )

    return tuple(deltas)


def severity_from_deltas(deltas: tuple[CapabilityDelta, ...]) -> int:
    """Resolve the dominant severity from computed deltas."""

    if not deltas:
        return 1
    return max(delta.severity for delta in deltas)


def _first_seen_deltas(after: CapabilitySet) -> list[CapabilityDelta]:
    deltas: list[CapabilityDelta] = []
    if after.network_hosts:
        deltas.append(
            CapabilityDelta(
                delta_type="new_network_host",
                before=None,
                after=", ".join(after.network_hosts[:3]),
                severity=7,
                explanation="First-seen artifact declares remote network hosts.",
            )
        )
    if after.secret_classes:
        deltas.append(
            CapabilityDelta(
                delta_type="secret_scope_expanded",
                before=None,
                after=", ".join(after.secret_classes),
                severity=8,
                explanation="First-seen artifact references sensitive local secret classes.",
            )
        )
    if after.subprocess_invocation:
        deltas.append(
            CapabilityDelta(
                delta_type="subprocess_added",
                before=None,
                after="true",
                severity=7,
                explanation="First-seen artifact includes subprocess or shell execution behavior.",
            )
        )
    if after.transport != "local":
        deltas.append(
            CapabilityDelta(
                delta_type="transport_changed",
                before="local",
                after=after.transport,
                severity=5,
                explanation="First-seen artifact uses remote or hybrid transport.",
            )
        )
    if after.publisher:
        deltas.append(
            CapabilityDelta(
                delta_type="publisher_changed",
                before=None,
                after=after.publisher,
                severity=4,
                explanation="First-seen artifact declares a publisher identity.",
            )
        )
    return deltas


def _combined_text(artifact: GuardArtifact) -> str:
    values = [
        artifact.name,
        artifact.command or "",
        artifact.url or "",
        " ".join(artifact.args),
        str(artifact.metadata.get("request_summary") or ""),
        str(artifact.metadata.get("runtime_request_summary") or ""),
        str(artifact.metadata.get("prompt_summary") or ""),
    ]
    env_keys = artifact.metadata.get("env_keys")
    if isinstance(env_keys, list):
        values.extend(str(item) for item in env_keys if isinstance(item, str))
    return " ".join(value for value in values if value)


def _extract_network_hosts(text: str, url: str | None) -> set[str]:
    hosts: set[str] = set()
    if url:
        parsed = urlsplit(url)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    for candidate in _URL_PATTERN.findall(text):
        parsed = urlsplit(candidate)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    for candidate in _HOST_PATTERN.findall(text):
        if candidate.count(".") < 1:
            continue
        lowered = candidate.lower()
        suffix = lowered.rsplit(".", 1)[-1]
        if suffix in _NON_NETWORK_SUFFIXES:
            continue
        hosts.add(lowered)
    return hosts


def _extract_network_schemes(text: str, url: str | None) -> set[str]:
    schemes: set[str] = set()
    if url:
        parsed = urlsplit(url)
        if parsed.scheme:
            schemes.add(parsed.scheme.lower())
    for candidate in _URL_PATTERN.findall(text):
        parsed = urlsplit(candidate)
        if parsed.scheme:
            schemes.add(parsed.scheme.lower())
    if "ssh " in text.lower() or "scp " in text.lower():
        schemes.add("ssh")
    return schemes


def _extract_secret_classes(text: str, artifact: GuardArtifact) -> set[str]:
    classes: set[str] = set()
    lowered = text.lower()
    for hint, label in _SECRET_HINTS:
        if hint in lowered:
            classes.add(label)
    env_keys = artifact.metadata.get("env_keys")
    if isinstance(env_keys, list):
        for value in env_keys:
            if not isinstance(value, str):
                continue
            lowered_key = value.lower()
            if any(token in lowered_key for token in ("token", "secret", "password", "key", "credential", "auth")):
                classes.add("sensitive environment key")
                break
    return classes


def _extract_interpreters(artifact: GuardArtifact, text: str) -> set[str]:
    interpreters: set[str] = set()
    command_name = PurePath(artifact.command or "").name.lower()
    if command_name in _SCRIPT_INTERPRETERS:
        interpreters.add(command_name)
    lowered = text.lower()
    for candidate in _SCRIPT_INTERPRETERS:
        if f"{candidate} " in lowered or f"{candidate}-" in lowered or f"{candidate}(" in lowered:
            interpreters.add(candidate)
    return interpreters


def _extract_shell_wrappers(artifact: GuardArtifact) -> set[str]:
    wrappers: set[str] = set()
    command_name = PurePath(artifact.command or "").name.lower()
    if command_name in _SHELL_COMMANDS:
        wrappers.add(command_name)
    for arg in artifact.args:
        if arg in {"-c", "-lc", "/c"}:
            wrappers.add(f"{command_name}:{arg}" if command_name else arg)
    return wrappers


def _has_subprocess_intent(text: str, artifact: GuardArtifact) -> bool:
    lowered = text.lower()
    if any(token in lowered for token in _SUBPROCESS_TOKENS):
        return True
    command_name = PurePath(artifact.command or "").name.lower()
    return command_name in _SHELL_COMMANDS and any(arg in {"-c", "-lc", "/c"} for arg in artifact.args)


def _normalize_transport(artifact: GuardArtifact) -> TransportKind:
    transport = (artifact.transport or "").lower()
    if transport in {"http", "https", "ws", "wss", "sse", "remote"}:
        return "remote"
    if transport in {"hybrid", "bridge"}:
        return "hybrid"
    if artifact.url is not None and artifact.url.startswith(("http://", "https://")):
        return "remote"
    return "local"
