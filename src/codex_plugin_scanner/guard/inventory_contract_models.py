"""Inventory value types and immutable wire-contract models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .inventory_agent_types import AgentInventoryType

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
    description: str
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
