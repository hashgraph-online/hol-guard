"""Attach local HCS trust domain evidence to AIBOM inventory metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from ..checks.skill_security import resolve_skill_security_context
from ..models import ScanOptions, Severity
from ..trust_instruction_scoring import build_instruction_domain
from ..trust_mcp_scoring import build_mcp_domain, build_mcp_surface_domain
from ..trust_models import TrustAdapterScore, TrustComponentScore, TrustDomainScore
from ..trust_plugin_scoring import build_plugin_domain
from ..trust_skill_scoring import build_skill_domain
from .runtime.evidence_hash import guard_evidence_hash

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

TrustLayerType = Literal["local_baseline", "cisco_skill_scanner", "cisco_mcp_scanner"]

_LOCAL_BASELINE_ITEM_KINDS = frozenset(
    {
        "agent",
        "daemon_plugin",
        "hook",
        "mcp_server",
        "mcp_tool",
        "overlay",
        "plugin",
        "policy",
        "prompt_pack",
        "skill",
    }
)
_INSTRUCTION_BASELINE_ITEM_KINDS = frozenset({"agent", "daemon_plugin", "hook", "overlay", "policy", "prompt_pack"})


def trust_resolution_from_domain(
    domain: TrustDomainScore,
    *,
    captured_at: str,
) -> dict[str, object]:
    from .inventory_contract import _normalize_inventory_datetime

    trust_components = _trust_components_from_domain(domain)
    normalized_captured_at = _normalize_inventory_datetime(captured_at)
    metadata = {
        "profileId": domain.profile_id,
        "profileVersion": domain.profile_version,
        "scorer": "hol-guard-local",
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "trustDomain": domain.domain,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        "evidence": _local_baseline_evidence_payload(
            domain,
            captured_at=normalized_captured_at,
            trust_components=trust_components,
        ),
        "evidenceHash": _trust_evidence_hash(
            {
                "capturedAt": normalized_captured_at,
                "resolutionSource": "local",
                "status": "local",
                "trustScore": round(domain.score),
                "trustComponents": trust_components,
                "trustDomain": domain.domain,
            }
        ),
    }

    return {
        "resolutionSource": "local",
        "status": "local",
        "trustScore": round(domain.score),
        "trustComponents": trust_components,
        "capturedAt": normalized_captured_at,
        "metadata": metadata,
    }


def apply_local_trust_metadata(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    workspace_dir: Path | None,
    cisco_runs: tuple[object, ...] = (),
) -> dict[str, object]:
    enriched = dict(metadata)
    trust_layers: list[dict[str, object]] = []

    if item_kind in _LOCAL_BASELINE_ITEM_KINDS and not isinstance(
        metadata.get("trustResolution"),
        dict,
    ):
        domain = _local_trust_domain_for_artifact(
            artifact,
            item_kind=item_kind,
            metadata=metadata,
            workspace_dir=workspace_dir,
        )
        if domain is not None:
            enriched["trustResolution"] = trust_resolution_from_domain(domain, captured_at=captured_at)
            trust_layers.append(_trust_layer_from_domain(domain, captured_at=captured_at))

    trust_layers.extend(
        _cisco_trust_layers_for_artifact(
            artifact,
            item_kind=item_kind,
            captured_at=captured_at,
            cisco_runs=cisco_runs,
            workspace_dir=workspace_dir,
        )
    )

    local_security = _local_security_for_artifact(
        artifact,
        item_kind=item_kind,
        metadata=metadata,
        captured_at=captured_at,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    )
    if local_security is not None:
        enriched["localSecurity"] = local_security

    if trust_layers:
        enriched["trustLayers"] = _merge_trust_layers(metadata.get("trustLayers"), trust_layers)
    return enriched


def _local_security_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    captured_at: str,
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    skill_security = _local_skill_security_for_artifact(
        artifact,
        item_kind=item_kind,
        metadata=metadata,
        captured_at=captured_at,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    )
    if skill_security is not None:
        return skill_security
    return _local_mcp_security_for_artifact(
        artifact,
        item_kind=item_kind,
        captured_at=captured_at,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    )


def _local_skill_security_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    captured_at: str,
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    from .inventory_contract import _normalize_inventory_datetime

    if item_kind != "skill" or metadata.get("artifactType") != "skill":
        return None

    trust_root = _trust_root_for_artifact(artifact, item_kind=item_kind, workspace_dir=workspace_dir)
    if trust_root is None:
        return None

    run = next(
        (
            candidate
            for candidate in cisco_runs
            if getattr(candidate, "source", None) == "cisco-skill-scanner"
            and _matches_skill_cisco_run(
                artifact,
                item_kind=item_kind,
                run=candidate,
                workspace_dir=workspace_dir,
            )
        ),
        None,
    )
    if run is None:
        return None

    status = str(getattr(run, "status", "unknown"))
    normalized_captured_at = _normalize_inventory_datetime(captured_at)
    findings = _local_skill_security_findings(run, skill_root=trust_root)
    findings = sorted(
        findings,
        key=lambda finding: (finding.get("file", ""), finding.get("ruleId", ""), finding.get("message", "")),
    )
    severity_counts = _cisco_severity_counts(run)
    analyzers_used = _cisco_analyzers_used(run)
    score = _cisco_layer_score(severity_counts, analyzers_used=analyzers_used) if status == "enabled" else None
    safety = None
    if score is not None:
        safety = {
            "score": score,
            "label": _local_skill_security_label(score),
            "findingsTotal": len(findings),
            "highFindings": sum(1 for finding in findings if finding["severity"] == "high"),
            "scriptsTotal": _local_skill_scripts_total(run),
            "permissionsMissing": [],
        }

    run_metadata = getattr(run, "metadata", None)
    metadata_payload: dict[str, object] = {
        "scannerSource": str(getattr(run, "source", "unknown")),
        "message": str(getattr(run, "message", "")),
        "findingsBySeverity": severity_counts,
        "totalFindings": len(findings),
    }
    duration_ms = getattr(run, "duration_ms", None)
    if isinstance(duration_ms, int):
        metadata_payload["durationMs"] = duration_ms
    if isinstance(run_metadata, dict):
        for key in ("analyzersUsed", "policyName", "mode", "skillsScanned", "skillsSkipped"):
            value = run_metadata.get(key)
            if value is not None:
                metadata_payload[key] = value

    metadata_payload["evidenceHash"] = guard_evidence_hash(
        {
            "capturedAt": normalized_captured_at,
            "entityType": "skill",
            "findings": findings,
            "provider": "cisco-skill-scanner",
            "safety": safety,
            "source": "local_indexed",
            "status": status,
        }
    )

    return {
        "entityType": "skill",
        "source": "local_indexed",
        "provider": "cisco-skill-scanner",
        "status": status,
        "capturedAt": normalized_captured_at,
        "safety": safety,
        "findings": findings,
        "metadata": metadata_payload,
    }


def _local_mcp_security_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    captured_at: str,
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    from .inventory_contract import _normalize_inventory_datetime

    if item_kind not in {"mcp_server", "mcp_tool"} or getattr(artifact, "artifact_type", None) not in {
        "mcp_server",
        "mcp_tool",
    }:
        return None

    trust_root = _trust_root_for_artifact(artifact, item_kind=item_kind, workspace_dir=workspace_dir)
    if trust_root is None:
        return None

    run = next(
        (
            candidate
            for candidate in cisco_runs
            if getattr(candidate, "source", None) == "cisco-mcp-scanner"
            and _matches_mcp_cisco_run(artifact, run=candidate)
        ),
        None,
    )
    if run is None:
        return None

    status = str(getattr(run, "status", "unknown"))
    normalized_captured_at = _normalize_inventory_datetime(captured_at)
    scan_root = _cisco_run_target_path(run) or trust_root
    findings = _local_mcp_security_findings(run, scan_root=scan_root)
    findings = sorted(
        findings,
        key=lambda finding: (finding.get("file", ""), finding.get("ruleId", ""), finding.get("message", "")),
    )
    severity_counts = _cisco_severity_counts(run)
    analyzers_used = _cisco_analyzers_used(run)
    score = _cisco_layer_score(severity_counts, analyzers_used=analyzers_used) if status == "enabled" else None
    safety = None
    if score is not None:
        safety = {
            "score": score,
            "label": _local_skill_security_label(score),
            "findingsTotal": len(findings),
            "highFindings": sum(1 for finding in findings if finding["severity"] == "high"),
            "scriptsTotal": _local_mcp_targets_total(run),
            "targetsScanned": _local_mcp_targets_total(run),
            "permissionsMissing": [],
        }

    run_metadata = getattr(run, "metadata", None)
    metadata_payload: dict[str, object] = {
        "scannerSource": str(getattr(run, "source", "unknown")),
        "message": str(getattr(run, "message", "")),
        "findingsBySeverity": severity_counts,
        "totalFindings": len(findings),
    }
    duration_ms = getattr(run, "duration_ms", None)
    if isinstance(duration_ms, int):
        metadata_payload["durationMs"] = duration_ms
    if isinstance(run_metadata, dict):
        for key in ("analyzersUsed", "scanMode", "mode", "targetsScanned"):
            value = run_metadata.get(key)
            if value is not None:
                metadata_payload[key] = value

    metadata_payload["evidenceHash"] = guard_evidence_hash(
        {
            "capturedAt": normalized_captured_at,
            "entityType": item_kind,
            "findings": findings,
            "provider": "cisco-mcp-scanner",
            "safety": safety,
            "source": "local_indexed",
            "status": status,
        }
    )

    return {
        "entityType": item_kind,
        "source": "local_indexed",
        "provider": "cisco-mcp-scanner",
        "status": status,
        "capturedAt": normalized_captured_at,
        "safety": safety,
        "findings": findings,
        "metadata": metadata_payload,
    }


def _local_mcp_security_findings(
    run: object,
    *,
    scan_root: Path,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    try:
        resolved_scan_root = scan_root.resolve()
    except OSError:
        resolved_scan_root = scan_root
    for finding in tuple(getattr(run, "findings", ()) or ()):
        file_path = getattr(finding, "file_path", None)
        if isinstance(file_path, str) and file_path.strip():
            raw_path = Path(file_path)
            path = raw_path if raw_path.is_absolute() else scan_root / raw_path
            if not _paths_related(scan_root, path):
                continue
            try:
                relative_file = str(path.resolve().relative_to(resolved_scan_root))
            except ValueError:
                relative_file = path.name
        else:
            relative_file = ".mcp.json"

        results.append(
            {
                "ruleId": str(getattr(finding, "rule_id", "unknown")),
                "severity": _local_skill_security_severity(getattr(finding, "severity", None)),
                "file": relative_file,
                "message": _local_mcp_security_message(finding),
            }
        )
    return results


def _local_mcp_security_message(finding: object) -> str:
    description = getattr(finding, "description", None)
    if isinstance(description, str) and description.strip():
        return description.strip()
    title = getattr(finding, "title", None)
    if isinstance(title, str) and title.strip():
        return title.strip()
    return "MCP security finding"


def _local_mcp_targets_total(run: object) -> int:
    metadata = getattr(run, "metadata", None)
    if isinstance(metadata, dict):
        value = metadata.get("targetsScanned")
        if isinstance(value, int):
            return max(0, value)
    return 0


def _local_skill_security_findings(
    run: object,
    *,
    skill_root: Path,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for finding in tuple(getattr(run, "findings", ()) or ()):
        file_path = getattr(finding, "file_path", None)
        if isinstance(file_path, str) and file_path.strip():
            path = Path(file_path)
            if not _paths_related(skill_root, path):
                continue
            try:
                relative_file = str(path.resolve().relative_to(skill_root.resolve()))
            except ValueError:
                relative_file = path.name
        else:
            relative_file = "SKILL.md"

        results.append(
            {
                "ruleId": str(getattr(finding, "rule_id", "unknown")),
                "severity": _local_skill_security_severity(getattr(finding, "severity", None)),
                "file": relative_file,
                "message": _local_skill_security_message(finding),
            }
        )
    return results


def _local_skill_security_severity(value: object) -> str:
    severity = value.value if isinstance(value, Severity) else str(value).lower()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _local_skill_security_message(finding: object) -> str:
    description = getattr(finding, "description", None)
    if isinstance(description, str) and description.strip():
        return description.strip()
    title = getattr(finding, "title", None)
    if isinstance(title, str) and title.strip():
        return title.strip()
    return "Skill security finding"


def _local_skill_security_label(score: int) -> str:
    if score >= 90:
        return "safe"
    if score >= 70:
        return "review"
    if score >= 45:
        return "caution"
    return "unsafe"


def _local_skill_scripts_total(run: object) -> int:
    metadata = getattr(run, "metadata", None)
    if isinstance(metadata, dict):
        value = metadata.get("skillsScanned")
        if isinstance(value, int):
            return max(0, value)
    return 0


def _metadata_string(metadata: dict[str, object], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) and value else None


def _local_trust_domain_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    workspace_dir: Path | None,
) -> TrustDomainScore | None:
    trust_root = _trust_root_for_artifact(artifact, item_kind=item_kind, workspace_dir=workspace_dir)
    if trust_root is None:
        return None
    if item_kind == "plugin":
        return build_plugin_domain(trust_root, ())
    if item_kind == "skill":
        context = resolve_skill_security_context(trust_root, _INVENTORY_TRUST_SCAN_OPTIONS)
        skill_domain = build_skill_domain(trust_root, context)
        if skill_domain is not None:
            return skill_domain
        if getattr(artifact, "artifact_type", None) == "skill_file":
            config_path = getattr(artifact, "config_path", None)
            if isinstance(config_path, str) and config_path.strip():
                file_path = Path(config_path)
                if file_path.is_file():
                    return build_instruction_domain(file_path, role="skill_file", item_kind="skill")
        return None
    if item_kind == "mcp_server":
        return build_mcp_domain(trust_root, ()) or build_mcp_surface_domain(
            name=getattr(artifact, "name", None),
            command=getattr(artifact, "command", None),
            url=getattr(artifact, "url", None),
            transport=getattr(artifact, "transport", None),
        )
    if item_kind == "mcp_tool":
        return build_mcp_surface_domain(
            name=str(metadata.get("toolName") or metadata.get("title") or ""),
            command=_metadata_string(metadata, "serverCommand"),
            url=_metadata_string(metadata, "serverUrl"),
            transport=_metadata_string(metadata, "serverTransport"),
        )
    if item_kind in _INSTRUCTION_BASELINE_ITEM_KINDS:
        role = metadata.get("instructionRole")
        normalized_role = role if isinstance(role, str) and role else f"{item_kind}_config"
        return build_instruction_domain(trust_root, role=normalized_role, item_kind=item_kind)
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
            if path.name.lower() != "skill.md" and (candidate / "SKILL.md").is_file():
                return candidate
            if (
                getattr(artifact, "artifact_type", None) == "skill_file"
                and candidate.parent.name.lower() == "skills"
                and ((candidate / "README.md").is_file() or (candidate / "SECURITY.md").is_file())
                and _skill_file_name_matches_root(artifact, candidate)
            ):
                return candidate
            if workspace_dir is not None and candidate.resolve() == workspace_dir.resolve():
                break
        return skill_dir if skill_dir.is_dir() else None

    if item_kind in {"mcp_server", "mcp_tool"}:
        if path.is_file():
            return path.parent
        return path if path.is_dir() else None

    if item_kind == "plugin":
        if path.is_dir():
            return path
        parent = path.parent
        return parent if parent.is_dir() else None

    if item_kind in _INSTRUCTION_BASELINE_ITEM_KINDS:
        return path if path.is_file() else None

    return None


def _skill_file_name_matches_root(artifact: object, root: Path) -> bool:
    root_name = root.name
    name = getattr(artifact, "name", None)
    if isinstance(name, str) and (name == root_name or name.startswith(f"{root_name}/")):
        return True
    artifact_id = getattr(artifact, "artifact_id", None)
    return isinstance(artifact_id, str) and f":{root_name}:" in artifact_id


def _trust_layer_from_domain(
    domain: TrustDomainScore,
    *,
    captured_at: str,
) -> dict[str, object]:
    from .inventory_contract import _normalize_inventory_datetime

    trust_components = _trust_components_from_domain(domain)
    normalized_captured_at = _normalize_inventory_datetime(captured_at)
    evidence = _local_baseline_evidence_payload(
        domain,
        captured_at=normalized_captured_at,
        trust_components=trust_components,
    )

    return {
        "layerId": "local_baseline",
        "layerType": "local_baseline",
        "status": "local",
        "trustScore": round(domain.score),
        "trustComponents": trust_components,
        "capturedAt": normalized_captured_at,
        "metadata": {
            "profileId": domain.profile_id,
            "profileVersion": domain.profile_version,
            "scorer": "hol-guard-local",
            "specId": domain.spec_id,
            "specVersion": domain.spec_version,
            "trustDomain": domain.domain,
            "attestationStatus": "unsigned",
            "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
            "evidence": evidence,
            "evidenceHash": _trust_evidence_hash(
                {
                    "capturedAt": normalized_captured_at,
                    "layerId": "local_baseline",
                    "layerType": "local_baseline",
                    "status": "local",
                    "trustScore": round(domain.score),
                    "trustComponents": trust_components,
                    "trustDomain": domain.domain,
                }
            ),
        },
    }


def _local_baseline_evidence_payload(
    domain: TrustDomainScore,
    *,
    captured_at: object,
    trust_components: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "source": "hol-guard-local-baseline",
        "capturedAt": captured_at,
        "trustDomain": domain.domain,
        "profileId": domain.profile_id,
        "profileVersion": domain.profile_version,
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "componentCount": len(trust_components),
        "components": [
            {
                "componentId": str(component.get("componentId", "")),
                "confidence": component.get("confidence"),
                "label": str(component.get("label", "")),
                "score": component.get("score"),
                "status": str(component.get("status", "")),
                "summary": str(component.get("summary", "")),
                "weight": component.get("weight"),
            }
            for component in trust_components
        ],
    }


def _merge_trust_layers(
    existing: object,
    additions: list[dict[str, object]],
) -> list[dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    if isinstance(existing, list):
        for raw_layer in existing:
            if not isinstance(raw_layer, dict):
                continue
            layer_type = raw_layer.get("layerType")
            if isinstance(layer_type, str) and layer_type:
                merged[layer_type] = dict(raw_layer)
    for layer in additions:
        layer_type = layer.get("layerType")
        if isinstance(layer_type, str) and layer_type:
            merged[layer_type] = layer
    return list(merged.values())


def _cisco_trust_layers_for_artifact(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    captured_at: str,
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> list[dict[str, object]]:
    layers: list[dict[str, object]] = []
    for run in cisco_runs:
        source = getattr(run, "source", None)
        if (
            source == "cisco-skill-scanner"
            and item_kind in {"skill", "plugin"}
            and _matches_skill_cisco_run(
                artifact,
                item_kind=item_kind,
                run=run,
                workspace_dir=workspace_dir,
            )
        ):
            layers.append(
                _cisco_trust_layer(
                    run,
                    captured_at=captured_at,
                    layer_id="cisco_skill_scanner",
                    component_id="cisco.skill.score",
                    label="Cisco Skill Scanner",
                )
            )
        if (
            source == "cisco-mcp-scanner"
            and item_kind in {"mcp_server", "mcp_tool"}
            and _matches_mcp_cisco_run(
                artifact,
                run=run,
            )
        ):
            layers.append(
                _cisco_trust_layer(
                    run,
                    captured_at=captured_at,
                    layer_id="cisco_mcp_scanner",
                    component_id="cisco.mcp.score",
                    label="Cisco MCP Scanner",
                )
            )
    return layers


def _matches_skill_cisco_run(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    run: object,
    workspace_dir: Path | None,
) -> bool:
    run_target = _cisco_run_target_path(run)
    if run_target is None:
        return False
    trust_root = _trust_root_for_artifact(artifact, item_kind=item_kind, workspace_dir=workspace_dir)
    if trust_root is None:
        return False
    return _paths_related(trust_root, run_target)


def _matches_mcp_cisco_run(artifact: object, *, run: object) -> bool:
    run_config_path = _cisco_run_config_path(run)
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str) or not config_path.strip():
        return False
    path = Path(config_path)
    if run_config_path is not None:
        return _paths_related(path, run_config_path)
    run_target = _cisco_run_target_path(run)
    if run_target is None:
        return False
    if path.is_file() and (_paths_related(path, run_target) or _paths_related(path.parent, run_target)):
        return True
    return _paths_related(path, run_target)


def _paths_related(left: Path, right: Path) -> bool:
    try:
        left_resolved = left.resolve()
        right_resolved = right.resolve()
    except OSError:
        return False
    return (
        left_resolved == right_resolved
        or left_resolved in right_resolved.parents
        or right_resolved in left_resolved.parents
    )


def _cisco_run_config_path(run: object) -> Path | None:
    metadata = getattr(run, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    config_path = metadata.get("_configPath")
    if not isinstance(config_path, str) or not config_path.strip():
        return None
    return Path(config_path)


def _cisco_run_target_path(run: object) -> Path | None:
    metadata = getattr(run, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    target = metadata.get("_targetPath")
    if isinstance(target, str) and target.strip() and target != "missing":
        return Path(target)
    target = metadata.get("target")
    if not isinstance(target, str) or not target.strip() or target == "missing":
        return None
    return Path(target)


def _cisco_trust_layer(
    run: object,
    *,
    captured_at: str,
    layer_id: TrustLayerType,
    component_id: str,
    label: str,
) -> dict[str, object]:
    from .inventory_contract import _normalize_inventory_datetime

    status = str(getattr(run, "status", "unknown"))
    message = str(getattr(run, "message", ""))
    severity_counts = _cisco_severity_counts(run)
    analyzers_used = _cisco_analyzers_used(run)
    trust_score = _cisco_layer_score(severity_counts, analyzers_used=analyzers_used) if status == "enabled" else None
    trust_components: list[dict[str, object]] = []
    if trust_score is not None:
        component_status = "positive"
        if trust_score < 40:
            component_status = "critical"
        elif trust_score < 70:
            component_status = "warning"
        # Confidence scales with number of analyzers that ran:
        # 1 analyzer = 90, 2 = 95, 3+ = 99
        analyzer_confidence = min(90 + (len(analyzers_used) - 1) * 5, 99)
        trust_components.append(
            {
                "componentId": component_id,
                "confidence": analyzer_confidence,
                "label": label,
                "score": trust_score,
                "status": component_status,
                "summary": message
                or (
                    f"{label} completed with {sum(severity_counts.values())} findings "
                    f"using {len(analyzers_used)} analyzer(s)."
                ),
                "weight": 1.0,
            }
        )

    run_metadata = getattr(run, "metadata", None)
    safe_metadata: dict[str, object] = {
        "scannerSource": str(getattr(run, "source", "unknown")),
        "message": message,
        "totalFindings": sum(severity_counts.values()),
        "findingsBySeverity": severity_counts,
    }
    duration_ms = getattr(run, "duration_ms", None)
    if isinstance(duration_ms, int):
        safe_metadata["durationMs"] = duration_ms
    if isinstance(run_metadata, dict):
        for key in (
            "analyzersUsed",
            "policyName",
            "scanMode",
            "mode",
            "targetsScanned",
            "skillsScanned",
            "skillsSkipped",
        ):
            value = run_metadata.get(key)
            if value is not None:
                safe_metadata[key] = value
    safe_metadata["attestationStatus"] = "unsigned"
    safe_metadata["evidenceProvenance"] = "client_unverified"
    safe_metadata["scannerResolutionSource"] = "local_reported"
    safe_metadata["scannerVerificationRequired"] = "guard_cloud"
    safe_metadata["evidenceSchemaVersion"] = "guard-aibom-cisco-scanner-evidence.v1"
    evidence_payload = _cisco_evidence_payload(
        layer_id=layer_id,
        label=label,
        status=status,
        message=message,
        captured_at=_normalize_inventory_datetime(captured_at),
        trust_score=trust_score,
        trust_components=trust_components,
        metadata=safe_metadata,
    )
    safe_metadata["evidence"] = evidence_payload
    safe_metadata["evidenceHash"] = _trust_evidence_hash(evidence_payload)

    return {
        "layerId": layer_id,
        "layerType": layer_id,
        "status": status,
        "trustScore": trust_score,
        "trustComponents": trust_components,
        "capturedAt": _normalize_inventory_datetime(captured_at),
        "metadata": safe_metadata,
    }


def _cisco_evidence_payload(
    *,
    layer_id: TrustLayerType,
    label: str,
    status: str,
    message: str,
    captured_at: object,
    trust_score: int | None,
    trust_components: list[dict[str, object]],
    metadata: dict[str, object],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "source": metadata.get("scannerSource", "unknown"),
        "layerId": layer_id,
        "label": label,
        "status": status,
        "message": message,
        "capturedAt": captured_at,
        "trustScore": trust_score,
        "componentCount": len(trust_components),
        "totalFindings": metadata.get("totalFindings", 0),
        "findingsBySeverity": metadata.get("findingsBySeverity", {}),
    }
    for key in (
        "analyzersUsed",
        "policyName",
        "scanMode",
        "mode",
        "targetsScanned",
        "skillsScanned",
        "skillsSkipped",
        "durationMs",
    ):
        value = metadata.get(key)
        if value is not None:
            payload[key] = value
    return payload


def _cisco_severity_counts(run: object) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    metadata = getattr(run, "metadata", None)
    if isinstance(metadata, dict):
        raw_counts = metadata.get("findingsBySeverity")
        if isinstance(raw_counts, dict):
            for key in counts:
                value = raw_counts.get(key)
                counts[key] = value if isinstance(value, int) and value >= 0 else 0
            return counts
    for finding in tuple(getattr(run, "findings", ()) or ()):
        severity = getattr(getattr(finding, "severity", None), "value", getattr(finding, "severity", None))
        if isinstance(severity, str) and severity in counts:
            counts[severity] += 1
    return counts


def _cisco_analyzers_used(run: object) -> tuple[str, ...]:
    """Extract analyzer names from a Cisco inventory run."""
    metadata = getattr(run, "metadata", None)
    if isinstance(metadata, dict):
        raw = metadata.get("analyzersUsed")
        if isinstance(raw, (list, tuple)):
            return tuple(str(a) for a in raw if a)
    return ("yara",)


def _cisco_layer_score(
    severity_counts: dict[str, int],
    *,
    analyzers_used: tuple[str, ...] = ("yara",),
) -> int:
    raw_score = 100 - (
        30 * severity_counts["critical"]
        + 12 * severity_counts["high"]
        + 4 * severity_counts["medium"]
        + severity_counts["low"]
    )
    # Ceiling: more analyzers = higher max achievable score.
    # 1 analyzer: max 90, 2: max 95, 3+: max 100.
    # Clean YARA-only can't reach 100; clean multi-analyzer can.
    analyzer_count = len(analyzers_used)
    if analyzer_count >= 3:
        ceiling = 100
    elif analyzer_count == 2:
        ceiling = 95
    else:
        ceiling = 90
    return max(0, min(ceiling, raw_score))


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


def _trust_evidence_hash(payload: dict[str, object]) -> str:
    return guard_evidence_hash(payload)
