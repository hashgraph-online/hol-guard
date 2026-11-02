"""Attach local HCS trust domain evidence to AIBOM inventory metadata.

The item's trust domain is scored here and the scanner runs and findings that
belong to it are picked from the filesystem here. The claims they become, with
their evidence and evidence hashes, come from the native `aibom_trust_claims`
authority.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from ..checks.skill_security import resolve_skill_security_context
from ..models import ScanOptions, Severity
from ..trust_instruction_scoring import build_instruction_domain
from ..trust_mcp_scoring import build_mcp_domain, build_mcp_surface_domain
from ..trust_models import TrustDomainScore
from ..trust_plugin_scoring import build_plugin_domain
from ..trust_skill_scoring import build_skill_domain
from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .trust_metadata_boundary import separate_untrusted_adapter_trust_metadata

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
_MCP_ITEM_KINDS = frozenset({"mcp_server", "mcp_tool"})
# The scanner metadata the claims read; paths and other keys stay here.
_RUN_METADATA_KEYS = (
    "analyzersUsed",
    "findingsBySeverity",
    "mode",
    "policyName",
    "scanMode",
    "skillsScanned",
    "skillsSkipped",
    "targetsScanned",
)


def trust_resolution_from_domain(
    domain: TrustDomainScore,
    *,
    captured_at: str,
) -> dict[str, object]:
    resolution = _native_trust_claims(captured_at=captured_at, domain=domain)["resolution"]
    if not isinstance(resolution, dict):
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    return resolution


def apply_local_trust_metadata(
    artifact: object,
    *,
    captured_at: str,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    workspace_dir: Path | None,
    cisco_runs: tuple[object, ...] = (),
) -> dict[str, object]:
    enriched = separate_untrusted_adapter_trust_metadata(metadata)
    domain = None
    if item_kind in _LOCAL_BASELINE_ITEM_KINDS:
        domain = _local_trust_domain_for_artifact(
            artifact,
            item_kind=item_kind,
            metadata=enriched,
            workspace_dir=workspace_dir,
        )
    cisco_layers = _cisco_layer_requests(
        artifact,
        item_kind=item_kind,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    )
    security = _local_skill_security_request(
        artifact,
        item_kind=item_kind,
        metadata=enriched,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    ) or _local_mcp_security_request(
        artifact,
        item_kind=item_kind,
        cisco_runs=cisco_runs,
        workspace_dir=workspace_dir,
    )
    if domain is None and not cisco_layers and security is None:
        return enriched

    try:
        claims = _native_trust_claims(
            captured_at=captured_at,
            domain=domain,
            cisco_layers=cisco_layers,
            security=security,
        )
    except NativeRunnerAuthorityError:
        # One item's claims never abort the inventory; it ships without them.
        return enriched
    if domain is not None:
        enriched["trustResolution"] = claims["resolution"]
    if claims["local_security"] is not None:
        enriched["localSecurity"] = claims["local_security"]
    if claims["layers"]:
        enriched["trustLayers"] = claims["layers"]
    return enriched


def _native_trust_claims(
    *,
    captured_at: str,
    domain: TrustDomainScore | None,
    cisco_layers: list[dict[str, object]] | None = None,
    security: dict[str, object] | None = None,
) -> dict[str, Any]:
    from .inventory_contract import _normalize_inventory_datetime

    answer = native_runner_authority(
        "aibom_trust_claims",
        {
            "captured_at": _normalize_inventory_datetime(captured_at),
            "domain": None if domain is None else _domain_request(domain),
            "cisco_layers": cisco_layers or [],
            "security": security,
        },
    )
    if not isinstance(answer.get("layers"), list) or not all(key in answer for key in ("resolution", "local_security")):
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    return answer


def _domain_request(domain: TrustDomainScore) -> dict[str, object]:
    return {
        "domain": domain.domain,
        "profile_id": domain.profile_id,
        "profile_version": domain.profile_version,
        "spec_id": domain.spec_id,
        "spec_version": domain.spec_version,
        "score": domain.score,
        "adapters": [
            {
                "adapter_id": adapter.adapter_id,
                "label": adapter.label,
                "weight": adapter.weight,
                "emitted": adapter.emitted,
                "components": [
                    {
                        "key": component.key,
                        "score": component.score,
                        "rationale": component.rationale,
                        "evidence": list(component.evidence),
                    }
                    for component in adapter.components
                ],
            }
            for adapter in domain.adapters
        ],
    }


def _run_request(run: object) -> dict[str, object]:
    raw_metadata = getattr(run, "metadata", None)
    metadata = (
        {key: raw_metadata[key] for key in _RUN_METADATA_KEYS if key in raw_metadata}
        if isinstance(raw_metadata, dict)
        else None
    )
    severities: list[str] = []
    for finding in tuple(getattr(run, "findings", ()) or ()):
        severity = getattr(getattr(finding, "severity", None), "value", getattr(finding, "severity", None))
        if isinstance(severity, str):
            severities.append(severity)
    duration_ms = getattr(run, "duration_ms", None)
    return {
        "status": str(getattr(run, "status", "unknown")),
        "message": str(getattr(run, "message", "")),
        "source": str(getattr(run, "source", "unknown")),
        "duration_ms": duration_ms if isinstance(duration_ms, int) else None,
        "metadata": metadata,
        "finding_severities": severities,
    }


def _finding_request(finding: object, *, file: str) -> dict[str, object]:
    severity = getattr(finding, "severity", None)
    description = getattr(finding, "description", None)
    title = getattr(finding, "title", None)
    return {
        "rule_id": str(getattr(finding, "rule_id", "unknown")),
        "severity": severity.value if isinstance(severity, Severity) else str(severity),
        "file": file,
        "description": description if isinstance(description, str) else None,
        "title": title if isinstance(title, str) else None,
    }


def _local_skill_security_request(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    metadata: dict[str, object],
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> dict[str, object] | None:
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
    return {
        "scanner": "skill",
        "entity_type": "skill",
        "run": _run_request(run),
        "findings": _local_skill_security_findings(run, skill_root=trust_root),
    }


def _local_mcp_security_request(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
    cisco_runs: tuple[object, ...],
    workspace_dir: Path | None,
) -> dict[str, object] | None:
    if item_kind not in _MCP_ITEM_KINDS or getattr(artifact, "artifact_type", None) not in _MCP_ITEM_KINDS:
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
    return {
        "scanner": "mcp",
        "entity_type": item_kind,
        "run": _run_request(run),
        "findings": _local_mcp_security_findings(run, scan_root=_cisco_run_target_path(run) or trust_root),
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
        results.append(_finding_request(finding, file=relative_file))
    return results


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
        results.append(_finding_request(finding, file=relative_file))
    return results


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


def _cisco_layer_requests(
    artifact: object,
    *,
    item_kind: InventoryItemKind,
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
            layers.append({"scanner": "skill", "run": _run_request(run)})
        if source == "cisco-mcp-scanner" and item_kind in _MCP_ITEM_KINDS and _matches_mcp_cisco_run(artifact, run=run):
            layers.append({"scanner": "mcp", "run": _run_request(run)})
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
