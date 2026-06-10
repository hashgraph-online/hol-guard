"""Attach local HCS trust domain evidence to AIBOM inventory metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from ..checks.skill_security import resolve_skill_security_context
from ..models import ScanOptions
from ..trust_mcp_scoring import build_mcp_domain
from ..trust_models import TrustAdapterScore, TrustComponentScore, TrustDomainScore
from ..trust_plugin_scoring import build_plugin_domain
from ..trust_skill_scoring import build_skill_domain

_INVENTORY_TRUST_SCAN_OPTIONS = ScanOptions(cisco_skill_scan="off")

InventoryItemKind = Literal[
    "agent",
    "channel",
    "container_image",
    "daemon_plugin",
    "harness",
    "hook",
    "mcp_server",
    "mcp_tool",
    "model_provider",
    "network_endpoint",
    "overlay",
    "package",
    "plugin",
    "policy",
    "prompt_pack",
    "repository",
    "secret_reference",
    "skill",
]


def trust_resolution_from_domain(
    domain: TrustDomainScore,
    *,
    captured_at: str,
) -> dict[str, object]:
    return {
        "resolutionSource": "local",
        "status": "local",
        "trustScore": round(domain.score),
        "trustComponents": _trust_components_from_domain(domain),
        "capturedAt": captured_at,
        "metadata": {
            "profileId": domain.profile_id,
            "profileVersion": domain.profile_version,
            "scorer": "hol-guard-local",
            "specId": domain.spec_id,
            "specVersion": domain.spec_version,
            "trustDomain": domain.domain,
        },
    }


def apply_local_trust_metadata(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    workspace_dir: Path | None,
) -> dict[str, object]:
    if item_kind not in {"skill", "plugin", "mcp_server"}:
        return metadata
    if isinstance(metadata.get("trustResolution"), dict):
        return metadata
    if isinstance(metadata.get("registryIdentity"), dict):
        return metadata

    domain = _local_trust_domain_for_artifact(
        artifact,
        item_kind=item_kind,
        workspace_dir=workspace_dir,
    )
    if domain is None:
        return metadata

    enriched = dict(metadata)
    enriched["trustResolution"] = trust_resolution_from_domain(domain, captured_at=captured_at)
    return enriched


def _local_trust_domain_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    workspace_dir: Path | None,
) -> TrustDomainScore | None:
    trust_root = _trust_root_for_artifact(artifact, item_kind=item_kind, workspace_dir=workspace_dir)
    if trust_root is None:
        return None
    if item_kind == "plugin":
        return build_plugin_domain(trust_root, ())
    if item_kind == "skill":
        context = resolve_skill_security_context(trust_root, _INVENTORY_TRUST_SCAN_OPTIONS)
        return build_skill_domain(trust_root, context)
    if item_kind == "mcp_server":
        return build_mcp_domain(trust_root, ())
    return None


def _trust_root_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    workspace_dir: Path | None,
) -> Path | None:
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str) or not config_path.strip():
        return None
    path = Path(config_path)
    if not path.exists():
        return None

    if item_kind == "skill":
        skill_dir = path.parent if path.name.lower() == "skill.md" else path
        for candidate in (skill_dir, *skill_dir.parents):
            if (candidate / ".codex-plugin" / "plugin.json").is_file():
                return candidate
            if workspace_dir is not None and candidate.resolve() == workspace_dir.resolve():
                break
        return skill_dir if skill_dir.is_dir() else None

    if item_kind == "mcp_server":
        if path.is_file():
            return path.parent
        return path if path.is_dir() else None

    if item_kind == "plugin":
        if path.is_dir():
            return path
        parent = path.parent
        return parent if parent.is_dir() else None

    return None


def _trust_components_from_domain(domain: TrustDomainScore) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    for adapter in domain.adapters:
        if not adapter.emitted:
            continue
        components.extend(_trust_components_from_adapter(adapter))
        if len(components) >= 32:
            break
    return components[:32]


def _trust_components_from_adapter(adapter: TrustAdapterScore) -> list[dict[str, object]]:
    return [_trust_component_row(adapter, component) for component in adapter.components]


def _trust_component_row(
    adapter: TrustAdapterScore,
    component: TrustComponentScore,
) -> dict[str, object]:
    score = round(component.score)
    status = "positive"
    if score < 40:
        status = "critical"
    elif score < 70:
        status = "warning"
    payload: dict[str, object] = {
        "componentId": f"{adapter.adapter_id}:{component.key}",
        "confidence": 85,
        "label": adapter.label,
        "score": score,
        "status": status,
        "summary": component.rationale,
        "weight": adapter.weight,
    }
    if component.evidence:
        payload["evidence"] = {"lines": list(component.evidence)}
    return payload
