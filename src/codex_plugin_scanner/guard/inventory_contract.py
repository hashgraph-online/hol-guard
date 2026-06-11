"""Structured Guard agent inventory contract and safe serializers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

InventoryItemKind = Literal[
    "agent",
    "daemon_plugin",
    "harness",
    "model_provider",
    "package",
    "prompt_pack",
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
_SENSITIVE_VALUE_RE = re.compile(r"(?i)(gh[pousr]_[a-z0-9_]+|sk-[a-z0-9_-]+|guard_live_[a-z0-9_-]+|bearer\s+\S+)")
_UNSAFE_PATH_MARKERS = (
    "".join(("/", "Users", "/")),
    "".join(("/", "home", "/")),
    "".join(("/", "root", "/")),
    "".join(("\\", "Users", "\\")),
    "".join(("/", "var", "/", "folders", "/")),
    "".join(("/", "workspace", "/")),
    "".join(("/", "tmp", "/")),
    "".join(("/", "etc", "/")),
    "".join(("/", "mnt", "/")),
)
_SERIALIZER_UNSAFE_PATH_PATTERN = (
    r"(?:^|[\s\"'=:({])(?:" + "|".join(re.escape(marker) for marker in _UNSAFE_PATH_MARKERS) + ")"
)
_SERIALIZER_UNSAFE_PATH_RE = re.compile(_SERIALIZER_UNSAFE_PATH_PATTERN, re.IGNORECASE)
_SERIALIZER_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|password|secret|token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*(?!redacted\b)\S+",
)
_SERIALIZER_REDACTED_VALUE = "[REDACTED]"
_SAFE_SERIALIZED_MARKERS = frozenset(
    {
        _SERIALIZER_REDACTED_VALUE,
        "present_redacted",
        "present",
        "redacted",
        "malformed_url_redacted",
    }
)
_WHITESPACE_RE = re.compile(r"\s+")
_MCP_READ_RE = re.compile(
    r"(?<![a-z0-9])(read|reads|reading|search|searches|list|lists)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_DELETE_RE = re.compile(
    r"(?<![a-z0-9])(delete|deletes|remove|removes|destroy|destroys)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_WRITE_RE = re.compile(
    r"(?<![a-z0-9])(write|writes|update|updates|create|creates|modify|modifies)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_SHELL_RE = re.compile(
    r"(?<![a-z0-9])(shell|command|commands|execute|exec|subprocess)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_SECRET_RE = re.compile(
    r"(?<![a-z0-9])(secret|secrets|token|tokens|password|passwords|credential|credentials|api[_\-\s]?key|apiKey)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_NETWORK_RE = re.compile(
    r"(?<![a-z0-9])(http|url|urls|network|fetch|webhook|webhooks)(?![a-z0-9])",
    re.IGNORECASE,
)
_MCP_MODEL_RE = re.compile(r"(?<![a-z0-9])(sampling|model|models|llm)(?![a-z0-9])", re.IGNORECASE)
_MCP_PERMISSION_RE = re.compile(
    r"(?<![a-z0-9])(permission|permissions|chmod)(?![a-z0-9])",
    re.IGNORECASE,
)
_IGNORED_TREE_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".ruff_cache", ".venv", "node_modules"}
_MAX_FINGERPRINT_FILE_BYTES = 1024 * 1024
_AIBOM_METADATA_KEYS = (
    "instructionRole",
    "registryIdentity",
    "sourceLinks",
    "sourceOfTruth",
    "trustResolution",
    "versionInfo",
)


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


def _snake_to_camel_case_key(key: str) -> str:
    if "_" not in key:
        return key
    head, *tail = key.split("_")
    return head + "".join(part[:1].upper() + part[1:] if part else "" for part in tail)


def _normalize_redaction_report(report: object) -> dict[str, object]:
    if not isinstance(report, dict):
        return {"rawSecretsIncluded": False, "redactedFields": []}
    raw_secrets = report.get("rawSecretsIncluded")
    if raw_secrets is None:
        raw_secrets = report.get("raw_secret_values")
    if raw_secrets is None:
        raw_secrets = report.get("raw_secrets_included", False)
    redacted_fields = report.get("redactedFields")
    if redacted_fields is None:
        redacted_fields = report.get("redacted_fields", [])
    return {
        "rawSecretsIncluded": raw_secrets is True,
        "redactedFields": list(redacted_fields) if isinstance(redacted_fields, (list, tuple)) else [],
    }


_INVENTORY_DATETIME_KEYS = frozenset(
    {
        "capturedAt",
        "completedAt",
        "firstSeenAt",
        "generatedAt",
        "lastSeenAt",
        "startedAt",
    }
)

_FREE_FORM_RECORD_KEYS = frozenset({"metadata", "evidence"})


def _normalize_inventory_datetime(value: object) -> object:
    if not isinstance(value, str) or not value.strip():
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, TypeError):
        return value


def _inventory_contract_json(value: object) -> object:
    if isinstance(value, list):
        return [_inventory_contract_json(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            camel_key = _snake_to_camel_case_key(str(key))
            if camel_key in _FREE_FORM_RECORD_KEYS:
                normalized[camel_key] = item
                continue
            if camel_key == "redactionReport":
                normalized[camel_key] = _normalize_redaction_report(item)
                continue
            if camel_key in _INVENTORY_DATETIME_KEYS:
                normalized[camel_key] = _normalize_inventory_datetime(item)
                continue
            normalized[camel_key] = _inventory_contract_json(item)
        return normalized
    return value


def serialize_inventory_snapshot(snapshot: GuardAgentInventorySnapshot) -> dict[str, object]:
    payload = _safe_json(asdict(snapshot))
    if not isinstance(payload, dict):
        raise TypeError("Inventory snapshot serialization produced invalid payload.")
    contract = _inventory_contract_json(payload)
    if not isinstance(contract, dict):
        raise TypeError("Inventory snapshot serialization produced invalid payload.")
    _assert_serialized_inventory_payload_safe(contract)
    return contract


def extract_aibom_metadata_extensions(metadata: dict[str, object]) -> dict[str, object]:
    """Return redacted AIBOM metadata extensions for CLI and inventory JSON output."""

    extensions = {key: _safe_json(metadata[key]) for key in _AIBOM_METADATA_KEYS if key in metadata}
    source_of_truth = extensions.get("sourceOfTruth")
    if "sourceLinks" not in extensions and isinstance(source_of_truth, dict):
        extensions["sourceLinks"] = [_safe_json(source_of_truth)]
    return extensions


def inventory_snapshot_from_detection(
    detection: object,
    *,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None = None,
    runtime_version: str | None = None,
    cisco_runs: tuple[object, ...] = (),
    include_symlinks: bool = True,
    follow_unsafe_symlinks: bool = False,
) -> GuardAgentInventorySnapshot:
    from .aibom_detection import discover_shared_workspace_aibom_artifacts

    harness = str(getattr(detection, "harness", "unknown"))
    artifacts = list(getattr(detection, "artifacts", ()))
    if workspace_dir is not None:
        existing_ids = {str(getattr(artifact, "artifact_id", "")) for artifact in artifacts}
        for artifact in discover_shared_workspace_aibom_artifacts(
            harness,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        ):
            if artifact.artifact_id not in existing_ids:
                artifacts.append(artifact)
                existing_ids.add(artifact.artifact_id)
    artifacts = tuple(artifacts)
    items: list[GuardAgentInventoryItem] = []
    for artifact in artifacts:
        item = _item_from_artifact(
            harness,
            artifact,
            generated_at=generated_at,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            include_symlinks=include_symlinks,
            follow_unsafe_symlinks=follow_unsafe_symlinks,
        )
        items.append(item)
        items.extend(_mcp_tool_items_from_artifact(harness, artifact, item))
    config_paths = tuple(dict.fromkeys(str(path) for path in getattr(detection, "config_paths", ())))
    config_sources = tuple(
        GuardInventorySource(
            source_id=f"{harness}:config:{fingerprint_text(redact_local_path(path, home_dir=home_dir))[:12]}",
            source_type="config",
            status="available",
            captured_at=generated_at,
            detail=redact_local_path(path, home_dir=home_dir),
        )
        for path in config_paths
    )
    item_tuple = tuple(items)
    cisco_findings = _cisco_inventory_findings(
        cisco_runs,
        items=item_tuple,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    symlink_findings = _symlink_findings_from_items(harness, item_tuple) if include_symlinks else ()
    sources = (*config_sources, *_cisco_inventory_sources(cisco_runs))
    snapshot_hash = fingerprint_mapping(
        {
            "agent_type": harness,
            "generated_at": generated_at,
            "item_ids": [item.item_id for item in items],
            "finding_ids": [finding.finding_id for finding in cisco_findings],
        }
    )
    return GuardAgentInventorySnapshot(
        snapshot_id=f"{harness}:snapshot:{snapshot_hash[:24]}",
        agent_id=f"{harness}:local",
        agent_type=_agent_type(harness),
        generated_at=generated_at,
        runtime_version=runtime_version,
        items=item_tuple,
        findings=(*cisco_findings, *symlink_findings),
        sources=sources,
        redaction_report={
            "rawSecretsIncluded": False,
            "redactedFields": ("headers", "env", "url", "paths", "ciscoFindingText"),
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
    except (OSError, RuntimeError, ValueError):
        return candidate.name
    return f"{{home}}/{relative.as_posix()}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): "present_redacted" if _SENSITIVE_KEY_RE.search(key) else "present" for key in headers}


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "malformed_url_redacted"
    hostname = parsed.hostname or parsed.netloc
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
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
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "remote_public"
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
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path | None,
    include_symlinks: bool = True,
    follow_unsafe_symlinks: bool = False,
) -> GuardAgentInventoryItem:
    artifact_id = str(getattr(artifact, "artifact_id", "artifact"))
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    name = str(getattr(artifact, "name", artifact_id))
    safe_metadata = _safe_artifact_metadata(artifact, home_dir=home_dir, workspace_dir=workspace_dir)
    item_kind = _item_kind(artifact_type)
    safe_metadata = _apply_aibom_metadata_enrichment(
        artifact,
        captured_at=generated_at,
        item_kind=item_kind,
        metadata=safe_metadata,
        workspace_dir=workspace_dir,
    )
    if include_symlinks:
        safe_metadata = _apply_source_of_truth_metadata(
            artifact,
            harness=harness,
            item_kind=item_kind,
            metadata=safe_metadata,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            follow_unsafe_symlinks=follow_unsafe_symlinks,
        )
    semantic_text = fingerprint_mapping(
        {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "name": name,
            "metadata": safe_metadata,
        }
    )
    content_hash = _resolve_item_content_hash(safe_metadata, semantic_text)
    return GuardAgentInventoryItem(
        item_id=artifact_id,
        item_kind=item_kind,
        display_name=name,
        source_fingerprint=fingerprint_mapping({"harness": harness, "artifact_id": artifact_id}),
        content_hash=content_hash,
        capability_categories=_capabilities_for_artifact(artifact_type, safe_metadata),
        risk_level=_risk_level(safe_metadata),
        scanner_sources=("hol-detector",),
        metadata=safe_metadata,
    )


def _mcp_tool_items_from_artifact(
    harness: str,
    artifact: object,
    server_item: GuardAgentInventoryItem,
) -> tuple[GuardAgentInventoryItem, ...]:
    artifact_type = str(getattr(artifact, "artifact_type", "unknown"))
    if artifact_type != "mcp_server":
        return ()
    raw_metadata = getattr(artifact, "metadata", {})
    if not isinstance(raw_metadata, dict):
        return ()
    raw_tools = _mcp_tool_definitions(raw_metadata)
    if not raw_tools:
        return ()

    items: list[GuardAgentInventoryItem] = []
    for raw_tool in raw_tools:
        if not isinstance(raw_tool, dict):
            continue
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        display_name = _string_value(raw_tool.get("title")) or name
        description = _string_value(raw_tool.get("description")) or ""
        input_schema = _first_present_value(raw_tool, "inputSchema", "input_schema")
        output_schema = _first_present_value(raw_tool, "outputSchema", "output_schema")
        annotations = raw_tool.get("annotations")
        safe_annotations = annotations if isinstance(annotations, dict) else {}
        metadata = {
            "serverItemId": server_item.item_id,
            "toolName": name,
            "title": display_name,
            "descriptionHash": fingerprint_text(description),
            "inputSchemaHash": fingerprint_mapping(input_schema) if input_schema is not None else None,
            "outputSchemaHash": fingerprint_mapping(output_schema) if output_schema is not None else None,
            "annotations": safe_annotations,
            "schemaPresent": input_schema is not None or output_schema is not None,
        }
        capabilities = _capabilities_for_mcp_tool(name, description, input_schema, safe_annotations)
        semantic_hash = fingerprint_mapping(
            {
                "server": server_item.item_id,
                "name": name,
                "description": description,
                "inputSchema": input_schema,
                "outputSchema": output_schema,
                "annotations": safe_annotations,
            }
        )
        items.append(
            GuardAgentInventoryItem(
                item_id=f"{server_item.item_id}:tool:{name}",
                item_kind="mcp_tool",
                display_name=display_name,
                source_fingerprint=fingerprint_mapping(
                    {"harness": harness, "server": server_item.item_id, "tool": name}
                ),
                content_hash=semantic_hash,
                capability_categories=capabilities,
                risk_level=_risk_level_for_capabilities(capabilities),
                scanner_sources=("hol-detector",),
                metadata=metadata,
            )
        )
    return tuple(items)


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _first_present_value(mapping: dict[str, object], *keys: str) -> object | None:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _mcp_tool_definitions(metadata: dict[str, object]) -> tuple[dict[str, object], ...]:
    tools: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for key in ("tools", "tool_schemas", "toolSchemas"):
        raw_tools = metadata.get(key)
        if not isinstance(raw_tools, list):
            continue
        for raw_tool in raw_tools:
            if not isinstance(raw_tool, dict):
                continue
            name = raw_tool.get("name")
            if not isinstance(name, str) or not name.strip() or name in seen_names:
                continue
            tools.append(raw_tool)
            seen_names.add(name)
    return tuple(tools)


def _mcp_schema_signal_text(value: object) -> str:
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            if key in {"$schema", "$id"}:
                continue
            parts.append(key)
            parts.append(_mcp_schema_signal_text(item))
        return " ".join(part for part in parts if part)
    if isinstance(value, list):
        return " ".join(_mcp_schema_signal_text(item) for item in value)
    if isinstance(value, str):
        return value
    return ""


def _capabilities_for_mcp_tool(
    name: str,
    description: str,
    input_schema: object,
    annotations: dict[str, object],
) -> tuple[InventoryCapability, ...]:
    text = f"{name} {description} {_mcp_schema_signal_text(input_schema)}".lower()
    capabilities: set[InventoryCapability] = set()
    if annotations.get("readOnlyHint") is True or _MCP_READ_RE.search(text):
        capabilities.add("reads_files")
    if annotations.get("destructiveHint") is True or _MCP_DELETE_RE.search(text):
        capabilities.update({"writes_files", "deletes_files"})
    if annotations.get("writeHint") is True or _MCP_WRITE_RE.search(text):
        capabilities.add("writes_files")
    if _MCP_SHELL_RE.search(text):
        capabilities.add("runs_shell")
    if _MCP_SECRET_RE.search(text):
        capabilities.add("reads_secrets")
    if _MCP_NETWORK_RE.search(text):
        capabilities.add("network_egress")
    if _MCP_MODEL_RE.search(text):
        capabilities.add("uses_model_sampling")
    if _MCP_PERMISSION_RE.search(text):
        capabilities.add("changes_permissions")
    return tuple(sorted(capabilities)) if capabilities else ("unknown",)


def _risk_level_for_capabilities(capabilities: tuple[InventoryCapability, ...]) -> InventorySeverity:
    if any(capability in capabilities for capability in ("deletes_files", "reads_secrets", "runs_shell")):
        return "high"
    if any(
        capability in capabilities
        for capability in ("writes_files", "network_egress", "uses_model_sampling", "changes_permissions")
    ):
        return "medium"
    return "info"


def _cisco_inventory_findings(
    cisco_runs: tuple[object, ...],
    *,
    items: tuple[GuardAgentInventoryItem, ...],
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[GuardAgentInventoryFinding, ...]:
    findings: list[GuardAgentInventoryFinding] = []
    seen: set[str] = set()
    for run in cisco_runs:
        source = _cisco_source(run)
        if source is None:
            continue
        run_status = str(getattr(run, "status", "unknown"))
        run_message = _safe_finding_text(
            str(getattr(run, "message", "")),
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
        duration_ms = getattr(run, "duration_ms", None)
        for raw_finding in tuple(getattr(run, "findings", ()) or ()):
            rule_id = str(getattr(raw_finding, "rule_id", "cisco-finding") or "cisco-finding")
            title = _safe_finding_text(
                str(getattr(raw_finding, "title", "Cisco scanner finding") or "Cisco scanner finding"),
                home_dir=home_dir,
                workspace_dir=workspace_dir,
            )
            file_path = getattr(raw_finding, "file_path", None)
            safe_path = (
                _redact_known_path(str(file_path), home_dir, workspace_dir)
                if isinstance(file_path, str) and file_path
                else None
            )
            line_number = getattr(raw_finding, "line_number", None)
            finding_hash = fingerprint_mapping(
                {
                    "source": source,
                    "rule_id": rule_id,
                    "title": title,
                    "path": safe_path,
                    "line": line_number if isinstance(line_number, int) else None,
                }
            )
            finding_id = f"{source}:{rule_id}:{finding_hash[:16]}"
            if finding_id in seen:
                continue
            seen.add(finding_id)
            severity = _inventory_severity(getattr(raw_finding, "severity", "info"))
            findings.append(
                GuardAgentInventoryFinding(
                    finding_id=finding_id,
                    source=source,
                    severity=severity,
                    confidence="high" if run_status == "enabled" else "unknown",
                    title=title,
                    artifact_id=_artifact_id_for_cisco_finding(safe_path, items),
                    check_id=rule_id,
                    summary=_safe_finding_text(
                        str(getattr(raw_finding, "description", "") or ""),
                        home_dir=home_dir,
                        workspace_dir=workspace_dir,
                    ),
                    evidence={
                        "scannerStatus": run_status,
                        "scannerMessage": run_message,
                        "filePath": safe_path,
                        "lineNumber": line_number if isinstance(line_number, int) else None,
                        "durationMs": duration_ms if isinstance(duration_ms, int) else None,
                        "riskComponent": {
                            "source": source,
                            "severity": severity,
                            "confidence": "high" if run_status == "enabled" else "unknown",
                            "scoreDelta": _score_delta_for_severity(severity),
                        },
                    },
                )
            )
    return tuple(findings)


def _cisco_inventory_sources(cisco_runs: tuple[object, ...]) -> tuple[GuardInventorySource, ...]:
    sources: list[GuardInventorySource] = []
    for run in cisco_runs:
        source = _cisco_source(run)
        if source is None:
            continue
        status = str(getattr(run, "status", "unknown"))
        detail = _safe_source_detail(run)
        sources.append(
            GuardInventorySource(
                source_id=f"{source}:{fingerprint_mapping({'status': status, 'detail': detail})[:12]}",
                source_type="scanner",
                status=_source_status_for_cisco_status(status),
                detail=detail,
            )
        )
    return tuple(sources)


def _cisco_source(run: object) -> InventoryFindingSource | None:
    source = str(getattr(run, "source", ""))
    if source in {"cisco-mcp-scanner", "cisco-skill-scanner"}:
        return source
    return None


def _inventory_severity(value: object) -> InventorySeverity:
    severity_value = str(getattr(value, "value", value)).strip().lower()
    if severity_value in {"critical", "high", "medium", "low", "info"}:
        return severity_value
    return "info"


def _score_delta_for_severity(severity: InventorySeverity) -> int:
    return {"critical": -40, "high": -25, "medium": -12, "low": -5, "info": 0}[severity]


def _artifact_id_for_cisco_finding(
    safe_path: str | None,
    items: tuple[GuardAgentInventoryItem, ...],
) -> str:
    if safe_path is None:
        return "unknown"
    for item in items:
        config_path = item.metadata.get("configPath")
        if isinstance(config_path, str) and (config_path == safe_path or config_path.endswith(safe_path)):
            return item.item_id
    return "unknown"


def _source_status_for_cisco_status(status: str) -> Literal["available", "missing", "failed"]:
    if status == "enabled":
        return "available"
    if status in {"failed", "timed_out"}:
        return "failed"
    return "missing"


def _safe_source_detail(run: object) -> str:
    status = str(getattr(run, "status", "unknown"))
    metadata = getattr(run, "metadata", {})
    finding_count = None
    if isinstance(metadata, dict):
        candidate = metadata.get("totalFindings")
        if isinstance(candidate, int):
            finding_count = candidate
    suffix = f", findings={finding_count}" if finding_count is not None else ""
    return f"status={status}{suffix}"


def _safe_finding_text(value: str, *, home_dir: Path, workspace_dir: Path | None) -> str:
    redacted = _SENSITIVE_VALUE_RE.sub("redacted", value)
    redacted = _redact_command_value(redacted, home_dir, workspace_dir)
    return redacted[:500]


def _agent_type(value: str) -> AgentInventoryType:
    for agent_type in _AGENT_INVENTORY_TYPES:
        if value == agent_type:
            return agent_type
    return "codex"


def _item_kind(artifact_type: str) -> InventoryItemKind:
    mapping: dict[str, InventoryItemKind] = {
        "skill": "skill",
        "skill_file": "skill",
        "mcp_server": "mcp_server",
        "mcp_tool": "mcp_tool",
        "channel": "channel",
        "gateway_config": "agent",
        "config": "agent",
        "agent": "agent",
        "hook": "hook",
        "instruction": "overlay",
        "overlay": "overlay",
        "command": "prompt_pack",
        "extension": "plugin",
        "plugin": "plugin",
        "plugin-file": "plugin",
        "repository": "repository",
        "container_image": "container_image",
        "policy": "policy",
        "secret_reference": "secret_reference",
        "network_endpoint": "network_endpoint",
        "guard_launcher_shim": "harness",
        "package": "package",
        "daemon_plugin": "daemon_plugin",
        "model_provider": "model_provider",
        "prompt_pack": "prompt_pack",
    }
    return mapping.get(artifact_type, "plugin")


def _resolve_item_content_hash(metadata: dict[str, object], semantic_text: str) -> str:
    for key in ("content_hash", "directory_hash"):
        candidate = metadata.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    version_info = metadata.get("versionInfo")
    if isinstance(version_info, dict):
        version_hash = version_info.get("contentHash")
        if isinstance(version_hash, str) and version_hash:
            return version_hash
    return semantic_text


def _safe_roots_for_inspection(
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[Path, ...]:
    roots: list[Path] = [home_dir]
    if workspace_dir is not None:
        roots.insert(0, workspace_dir)
    return tuple(roots)


def _apply_source_of_truth_metadata(
    artifact: object,
    *,
    harness: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    home_dir: Path,
    workspace_dir: Path | None,
    follow_unsafe_symlinks: bool = False,
) -> dict[str, object]:
    from .aibom_symlink import inspect_aibom_source_path, source_of_truth_metadata_from_inspection

    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str) or not config_path:
        return metadata
    path = Path(config_path)
    if not path.is_symlink():
        return metadata
    inspection = inspect_aibom_source_path(
        path,
        safe_roots=_safe_roots_for_inspection(home_dir=home_dir, workspace_dir=workspace_dir),
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        follow_unsafe_symlinks=follow_unsafe_symlinks,
    )
    source_link_id = f"{harness}:{item_kind}:{inspection.source_fingerprint[:24]}"
    enriched = dict(metadata)
    enriched["sourceOfTruth"] = source_of_truth_metadata_from_inspection(
        inspection,
        source_link_id=source_link_id,
    )
    return enriched


def _symlink_findings_from_items(
    harness: str,
    items: tuple[GuardAgentInventoryItem, ...],
) -> tuple[GuardAgentInventoryFinding, ...]:
    findings: list[GuardAgentInventoryFinding] = []
    for item in items:
        source_of_truth = item.metadata.get("sourceOfTruth")
        if not isinstance(source_of_truth, dict):
            continue
        validation_state = source_of_truth.get("validationState")
        if validation_state == "valid":
            continue
        if not isinstance(validation_state, str):
            continue
        severity: InventorySeverity = "high" if validation_state in {"loop", "escape_blocked"} else "medium"
        findings.append(
            GuardAgentInventoryFinding(
                finding_id=f"{harness}:symlink:{item.item_id}:{validation_state}",
                source="hol-detector",
                severity=severity,
                confidence="high",
                title=f"Symlink source {validation_state.replace('_', ' ')}",
                artifact_id=item.item_id,
                check_id=f"aibom.symlink.{validation_state}",
                summary=f"Inventory item references a symlink source in state {validation_state}.",
                evidence={
                    "validationState": validation_state,
                    "sourceFingerprint": source_of_truth.get("sourceFingerprint"),
                    "pathClass": source_of_truth.get("pathClass"),
                },
            )
        )
    return tuple(findings)


def _apply_aibom_metadata_enrichment(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    workspace_dir: Path | None,
) -> dict[str, object]:
    from .aibom_detection import instruction_role_for_path
    from .aibom_trust_metadata import apply_local_trust_metadata

    enriched = dict(metadata)
    if item_kind == "overlay" and "instructionRole" not in enriched:
        config_path = getattr(artifact, "config_path", None)
        if isinstance(config_path, str):
            role = instruction_role_for_path(Path(config_path))
            if role is not None:
                enriched["instructionRole"] = role
    return apply_local_trust_metadata(
        artifact,
        captured_at=captured_at,
        item_kind=item_kind,
        metadata=enriched,
        workspace_dir=workspace_dir,
    )


def _capabilities_for_artifact(
    artifact_type: str,
    metadata: dict[str, object],
) -> tuple[InventoryCapability, ...]:
    capabilities: set[InventoryCapability] = set()
    if artifact_type in {"skill", "skill_file"}:
        capabilities.add("reads_files")
    if artifact_type in {"instruction", "overlay", "command"}:
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
    redacted = re.sub(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^\s]+",
        lambda match: redact_url(match.group(0)),
        value,
    )
    redacted = re.sub(
        r"(^|\s)(/[^\s]+)",
        lambda match: f"{match.group(1)}{_redact_known_path(match.group(2), home_dir, workspace_dir)}",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(authorization:\s*bearer\s+)\S+",
        r"\1redacted",
        redacted,
    )
    redacted = re.sub(
        r"(?i)((?:api[_-]?key|auth|password|secret|token)=)\S+",
        r"\1redacted",
        redacted,
    )
    redacted = re.sub(
        r"(?i)((?:--)?(?:api[_-]?key|auth|password|secret|token)\s+)\S+",
        r"\1redacted",
        redacted,
    )
    return redacted


def _sanitize_serializer_string(
    value: str,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> str:
    if value in _SAFE_SERIALIZED_MARKERS:
        return value
    if parent_sensitive or (parent_key and _SENSITIVE_KEY_RE.search(parent_key)):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_UNSAFE_PATH_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SENSITIVE_VALUE_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    if _SERIALIZER_SECRET_ASSIGNMENT_RE.search(value):
        return _SERIALIZER_REDACTED_VALUE
    return value


def _assert_serialized_inventory_payload_safe(payload: object) -> None:
    encoded = json.dumps(payload, sort_keys=True)
    if (
        _SERIALIZER_UNSAFE_PATH_RE.search(encoded)
        or _SENSITIVE_VALUE_RE.search(encoded)
        or _SERIALIZER_SECRET_ASSIGNMENT_RE.search(encoded)
    ):
        raise ValueError("Inventory snapshot serialization produced unsafe payload.")


def _safe_json(
    value: object,
    *,
    parent_key: str = "",
    parent_sensitive: bool = False,
) -> object:
    key_sensitive = parent_sensitive or bool(parent_key and _SENSITIVE_KEY_RE.search(parent_key))
    if isinstance(value, dict):
        return {
            _sanitize_serializer_string(str(key), parent_sensitive=parent_sensitive): _safe_json(
                item,
                parent_key=str(key),
                parent_sensitive=key_sensitive,
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_safe_json(item, parent_key=parent_key, parent_sensitive=parent_sensitive) for item in value]
    if isinstance(value, Path):
        return value.name
    if isinstance(value, str):
        return _sanitize_serializer_string(
            value,
            parent_key=parent_key,
            parent_sensitive=parent_sensitive,
        )
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
