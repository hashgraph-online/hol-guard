"""Structured Guard agent inventory contract and safe serializers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

InventoryItemKind = Literal[
    "agent",
    "skill",
    "mcp_server",
    "mcp_tool",
    "plugin",
    "channel",
    "hook",
    "overlay",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
]
InventoryCapability = Literal[
    "reads_files",
    "reads_secrets",
    "writes_files",
    "deletes_files",
    "runs_shell",
    "executes_code",
    "network_egress",
    "network_ingress",
    "posts_messages",
    "reads_messages",
    "uses_browser",
    "uses_clipboard",
    "uses_model_sampling",
    "changes_permissions",
    "loads_remote_code",
    "unknown",
]
InventoryFindingSource = Literal["cisco-mcp-scanner", "cisco-skill-scanner", "hol-detector", "docker-proof", "metadata"]
InventorySeverity = Literal["critical", "high", "medium", "low", "info"]
InventoryConfidence = Literal["high", "medium", "low", "unknown"]
InventoryDriftState = Literal["new", "changed", "removed", "unchanged"]
DockerProofStatus = Literal["passed", "failed", "skipped", "stale"]
AgentInventoryType = Literal["hermes", "openclaw", "codex", "claude-code", "cursor", "gemini", "opencode"]
_AGENT_INVENTORY_TYPES: tuple[AgentInventoryType, ...] = (
    "hermes",
    "openclaw",
    "codex",
    "claude-code",
    "cursor",
    "gemini",
    "opencode",
)

_SENSITIVE_KEY_RE = re.compile(
    r"(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)",
    re.IGNORECASE,
)
_WHITESPACE_RE = re.compile(r"\s+")
_IGNORED_TREE_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv", "node_modules"}
_MAX_FINGERPRINT_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class GuardAgentInventoryFinding:
    finding_id: str
    source: InventoryFindingSource
    severity: InventorySeverity
    confidence: InventoryConfidence
    title: str
    artifact_id: str
    check_id: str
    summary: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GuardAgentInventoryDrift:
    drift_id: str
    item_id: str
    state: InventoryDriftState
    previous_hash: str | None
    current_hash: str | None
    changed_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GuardAgentInventoryDockerProof:
    proof_id: str
    agent_id: str
    agent_type: str
    image_reference: str
    status: DockerProofStatus
    captured_at: str
    log_hash: str
    redaction_report: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GuardAgentIntegrationRun:
    run_id: str
    agent_id: str
    agent_type: str
    status: Literal["started", "completed", "failed"]
    started_at: str
    completed_at: str | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class GuardHarnessSetupStep:
    step_id: str
    agent_type: str
    status: Literal["not_started", "running", "completed", "failed"]
    label: str
    safe_command: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class GuardInventoryRiskComponent:
    component_id: str
    source: InventoryFindingSource
    severity: InventorySeverity
    confidence: InventoryConfidence
    score_delta: int
    summary: str


@dataclass(frozen=True, slots=True)
class GuardInventorySource:
    source_id: str
    source_type: Literal["config", "docker", "scanner", "runtime", "repository"]
    status: Literal["available", "missing", "failed"]
    captured_at: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class GuardAgentInventoryItem:
    item_id: str
    item_kind: InventoryItemKind
    display_name: str
    source_fingerprint: str
    content_hash: str
    capability_categories: tuple[InventoryCapability, ...]
    risk_level: InventorySeverity = "info"
    security_score: int = 100
    scanner_sources: tuple[InventoryFindingSource, ...] = ()
    drift_state: InventoryDriftState = "unchanged"
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GuardAgentInventorySnapshot:
    snapshot_id: str
    agent_id: str
    agent_type: AgentInventoryType
    generated_at: str
    runtime_version: str | None = None
    items: tuple[GuardAgentInventoryItem, ...] = ()
    findings: tuple[GuardAgentInventoryFinding, ...] = ()
    drift: tuple[GuardAgentInventoryDrift, ...] = ()
    docker_proofs: tuple[GuardAgentInventoryDockerProof, ...] = ()
    sources: tuple[GuardInventorySource, ...] = ()
    redaction_report: dict[str, object] = field(default_factory=dict)


def serialize_inventory_snapshot(snapshot: GuardAgentInventorySnapshot) -> dict[str, object]:
    payload = _safe_json(asdict(snapshot))
    if not isinstance(payload, dict):
        raise TypeError("Inventory snapshot serialization produced invalid payload.")
    return payload


def inventory_snapshot_from_detection(
    detection: object,
    *,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None = None,
    runtime_version: str | None = None,
) -> GuardAgentInventorySnapshot:
    harness = str(getattr(detection, "harness", "unknown"))
    artifacts = tuple(getattr(detection, "artifacts", ()))
    items = tuple(
        _item_from_artifact(
            harness,
            artifact,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
        for artifact in artifacts
    )
    config_paths = tuple(dict.fromkeys(str(path) for path in getattr(detection, "config_paths", ())))
    sources = tuple(
        GuardInventorySource(
            source_id=f"{harness}:config:{fingerprint_text(redact_local_path(path, home_dir=home_dir))[:12]}",
            source_type="config",
            status="available",
            captured_at=generated_at,
            detail=redact_local_path(path, home_dir=home_dir),
        )
        for path in config_paths
    )
    snapshot_hash = fingerprint_mapping(
        {
            "agent_type": harness,
            "generated_at": generated_at,
            "item_ids": [item.item_id for item in items],
        }
    )
    return GuardAgentInventorySnapshot(
        snapshot_id=f"{harness}:snapshot:{snapshot_hash[:24]}",
        agent_id=f"{harness}:local",
        agent_type=_agent_type(harness),
        generated_at=generated_at,
        runtime_version=runtime_version,
        items=items,
        sources=sources,
        redaction_report={
            "rawSecretsIncluded": False,
            "redactedFields": ("headers", "env", "url", "paths"),
        },
    )


def fingerprint_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint_mapping(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return fingerprint_text(encoded)


def inventory_item_id(agent_type: str, item_kind: str, display_name: str, semantic_text: str) -> str:
    normalized_text = _WHITESPACE_RE.sub(" ", semantic_text.strip())
    digest = fingerprint_mapping(
        {
            "agent_type": agent_type,
            "display_name": display_name.strip().lower(),
            "item_kind": item_kind,
            "semantic_text": normalized_text,
        }
    )
    return f"{agent_type}:{item_kind}:{digest[:24]}"


def fingerprint_path_tree(root: Path, *, home_dir: Path | None = None) -> str:
    entries: list[dict[str, str]] = []
    if root.is_file():
        paths = [root]
    else:
        paths = sorted(
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.name != ".env"
            and not any(part in _IGNORED_TREE_DIR_NAMES for part in path.parts)
        )
    for path in paths:
        safe_path = redact_local_path(path, home_dir=home_dir)
        content_hash = _fingerprint_file_bytes(path)
        entries.append({"path": safe_path, "sha256": content_hash})
    return fingerprint_mapping(entries)


def redact_local_path(path: str | Path, *, home_dir: Path | None = None) -> str:
    candidate = Path(path)
    if home_dir is None:
        return candidate.name
    try:
        relative = candidate.resolve().relative_to(home_dir.resolve())
    except ValueError:
        return candidate.name
    return f"{{home}}/{relative.as_posix()}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): "present_redacted" if _SENSITIVE_KEY_RE.search(key) else "present" for key in headers}


def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    hostname = parsed.hostname or parsed.netloc
    netloc = hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    redacted_pairs = [
        (key, "redacted" if _SENSITIVE_KEY_RE.search(key) else item)
        for key, item in parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(redacted_pairs), parsed.fragment))


def classify_endpoint_host(value: str | None) -> Literal["none", "local_loopback", "local_private", "remote_public"]:
    if not value:
        return "none"
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "local_loopback"
    try:
        if ipaddress.ip_address(host).is_private:
            return "local_private"
    except ValueError:
        pass
    return "remote_public"


def _item_from_artifact(
    harness: str,
    artifact: object,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> GuardAgentInventoryItem:
    artifact_id = str(getattr(artifact, "artifact_id", "artifact"))
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    name = str(getattr(artifact, "name", artifact_id))
    safe_metadata = _safe_artifact_metadata(artifact, home_dir=home_dir, workspace_dir=workspace_dir)
    item_kind = _item_kind(artifact_type)
    semantic_text = fingerprint_mapping(
        {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "name": name,
            "metadata": safe_metadata,
        }
    )
    return GuardAgentInventoryItem(
        item_id=artifact_id,
        item_kind=item_kind,
        display_name=name,
        source_fingerprint=fingerprint_mapping({"harness": harness, "artifact_id": artifact_id}),
        content_hash=semantic_text,
        capability_categories=_capabilities_for_artifact(artifact_type, safe_metadata),
        risk_level=_risk_level(safe_metadata),
        scanner_sources=("hol-detector",),
        metadata=safe_metadata,
    )


def _agent_type(value: str) -> AgentInventoryType:
    for agent_type in _AGENT_INVENTORY_TYPES:
        if value == agent_type:
            return agent_type
    return "codex"


def _item_kind(artifact_type: str) -> InventoryItemKind:
    if artifact_type in {"skill", "skill_file"}:
        return "skill"
    if artifact_type == "mcp_server":
        return "mcp_server"
    if artifact_type == "channel":
        return "channel"
    if artifact_type in {"gateway_config", "config"}:
        return "agent"
    return "plugin"


def _capabilities_for_artifact(
    artifact_type: str,
    metadata: dict[str, object],
) -> tuple[InventoryCapability, ...]:
    capabilities: set[InventoryCapability] = set()
    if artifact_type in {"skill", "skill_file"}:
        capabilities.add("reads_files")
    if artifact_type == "mcp_server":
        capabilities.add("network_egress")
        if metadata.get("transport") == "stdio":
            capabilities.add("runs_shell")
    if artifact_type == "channel":
        capabilities.update({"reads_messages", "posts_messages", "network_ingress"})
    if bool(metadata.get("has_env_secrets")) or bool(metadata.get("has_auth_headers")):
        capabilities.add("reads_secrets")
    return tuple(sorted(capabilities)) if capabilities else ("unknown",)


def _risk_level(metadata: dict[str, object]) -> InventorySeverity:
    if metadata.get("has_auth_headers") or metadata.get("has_env_secrets"):
        return "high"
    if metadata.get("endpointHostClass") == "remote_public":
        return "medium"
    return "info"


def _safe_artifact_metadata(
    artifact: object,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> dict[str, object]:
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    raw_metadata = getattr(artifact, "metadata", {})
    metadata = _sanitize_paths(raw_metadata if isinstance(raw_metadata, dict) else {}, home_dir, workspace_dir)
    config_path = getattr(artifact, "config_path", None)
    command = getattr(artifact, "command", None)
    url = getattr(artifact, "url", None)
    transport = getattr(artifact, "transport", None)
    if isinstance(config_path, str) and config_path:
        metadata["configPath"] = _redact_known_path(config_path, home_dir, workspace_dir)
    if isinstance(command, str) and command:
        metadata["command"] = _redact_command_value(command, home_dir, workspace_dir)
    if isinstance(url, str) and url:
        metadata["url"] = redact_url(url)
        metadata["endpointHostClass"] = classify_endpoint_host(url)
    if isinstance(transport, str) and transport:
        metadata["transport"] = transport
    metadata["artifactType"] = artifact_type
    return metadata


def _sanitize_paths(value: object, home_dir: Path, workspace_dir: Path | None) -> object:
    if isinstance(value, Path):
        return _redact_known_path(str(value), home_dir, workspace_dir)
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            string_key = str(key)
            if _SENSITIVE_KEY_RE.search(string_key):
                redacted[string_key] = item if isinstance(item, bool) else "present_redacted"
                continue
            redacted[string_key] = _sanitize_paths(item, home_dir, workspace_dir)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_sanitize_paths(item, home_dir, workspace_dir) for item in value]
    if isinstance(value, str):
        if "://" in value:
            return redact_url(value)
        return _redact_known_path(value, home_dir, workspace_dir)
    return value


def _redact_known_path(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    path = Path(value)
    if path.is_absolute():
        home_redacted = redact_local_path(path, home_dir=home_dir)
        if home_redacted.startswith("{home}/"):
            return home_redacted
        if workspace_dir is not None:
            try:
                relative = path.resolve().relative_to(workspace_dir.resolve())
                return f"{{workspace}}/{relative.as_posix()}"
            except (OSError, RuntimeError, ValueError):
                return path.name
        return path.name
    return value


def _redact_command_value(value: str, home_dir: Path, workspace_dir: Path | None) -> str:
    path_redacted = _redact_known_path(value, home_dir, workspace_dir)
    if path_redacted != value:
        return path_redacted
    redacted = re.sub(
        r"(?i)(authorization:\s*bearer\s+)\S+",
        r"\1redacted",
        value,
    )
    redacted = re.sub(
        r"(?i)((?:api[_-]?key|auth|password|secret|token)=)\S+",
        r"\1redacted",
        redacted,
    )
    if "://" in redacted:
        return redact_url(redacted)
    return redacted


def _safe_json(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    if isinstance(value, Path):
        return value.name
    if isinstance(value, str):
        return value
    return value


def _fingerprint_file_bytes(path: Path) -> str:
    digest = hashlib.sha256()
    remaining = _MAX_FINGERPRINT_FILE_BYTES
    with path.open("rb") as file_handle:
        while remaining > 0:
            chunk = file_handle.read(min(65536, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()
