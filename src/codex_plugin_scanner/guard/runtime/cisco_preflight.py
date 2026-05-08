"""Cisco scanner preflight helpers for local Guard runtime actions."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig, resolve_risk_action
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.cisco_evidence import cisco_finding_to_risk_signal
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3, RiskSignalV2
from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding

_DEFAULT_SCANNER_TIMEOUT_SECONDS = 5.0
_ACTION_RANK: dict[GuardAction, int] = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}
_SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SOURCE_RISK_CLASS: dict[str, str] = {
    "cisco_skill": "malicious_skill",
    "cisco_mcp": "mcp_dangerous_tool",
    "native": "mcp_dangerous_tool",
    "threat_intel": "mcp_dangerous_tool",
    "runtime_detector": "mcp_dangerous_tool",
}


class CiscoSkillPreflightDetector:
    """Detector wrapper for changed local skill files."""

    detector_id = "cisco.skill"
    categories = ("skill",)

    def detect(self, action: GuardActionEnvelope, context: object) -> tuple[RiskSignalV2, ...]:
        workspace = getattr(context, "workspace", None)
        signals = scan_action_for_cisco_evidence(action, workspace=workspace, sources=("skill",))
        return tuple(cisco_risk_signal_v3_to_v2(signal) for signal in signals)


class CiscoMcpPreflightDetector:
    """Detector wrapper for changed local MCP config."""

    detector_id = "cisco.mcp"
    categories = ("mcp",)

    def detect(self, action: GuardActionEnvelope, context: object) -> tuple[RiskSignalV2, ...]:
        workspace = getattr(context, "workspace", None)
        signals = scan_action_for_cisco_evidence(action, workspace=workspace, sources=("mcp",))
        return tuple(cisco_risk_signal_v3_to_v2(signal) for signal in signals)


def scan_action_for_cisco_evidence(
    action: GuardActionEnvelope,
    *,
    workspace: Path | str | None,
    mode: str = "auto",
    sources: Iterable[str] = ("skill", "mcp"),
    timeout_seconds: float = _DEFAULT_SCANNER_TIMEOUT_SECONDS,
) -> tuple[GuardRiskSignalV3, ...]:
    """Run Cisco preflight scans for changed skill or MCP files referenced by an action."""

    if action.action_type not in {"file_write", "config_change"}:
        return ()
    workspace_path = Path(workspace).expanduser().resolve() if workspace is not None else Path.cwd().resolve()
    requested_sources = frozenset(sources)
    signals: list[GuardRiskSignalV3] = []
    scanned_skill_roots: set[Path] = set()
    scanned_mcp_roots: set[Path] = set()
    for target_path in _resolve_target_paths(action, workspace_path):
        if "skill" in requested_sources and _is_skill_file(target_path):
            skill_root = _skill_scan_root_for_file(target_path, workspace_path)
            if skill_root not in scanned_skill_roots:
                scanned_skill_roots.add(skill_root)
                signals.extend(
                    _skill_findings_to_signals(
                        cisco_skill_scanner.run_cisco_skill_scan(
                            skill_root,
                            mode=mode,
                            timeout_seconds=timeout_seconds,
                        )
                    )
                )
        if "mcp" in requested_sources and target_path.name == ".mcp.json":
            mcp_root = target_path.parent
            if mcp_root not in scanned_mcp_roots:
                scanned_mcp_roots.add(mcp_root)
                signals.extend(
                    _mcp_findings_to_signals(
                        cisco_mcp_scanner.run_cisco_mcp_scan(
                            mcp_root,
                            mode=mode,
                            timeout_seconds=timeout_seconds,
                        )
                    )
                )
    return tuple(signals)


def build_cisco_deep_scan_payload(
    *,
    scan_type: str,
    target: Path,
    mode: str,
    config: GuardConfig,
    harness: str | None = None,
    timeout_seconds: float = _DEFAULT_SCANNER_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Build a stable CLI payload for deep Cisco scanner evidence."""

    if scan_type == "skills":
        scan_root = _skill_scan_root_for_workspace(target)
        summary = cisco_skill_scanner.run_cisco_skill_scan(
            scan_root,
            mode=mode,
            timeout_seconds=timeout_seconds,
        )
        signals = tuple(_skill_findings_to_signals(summary))
        return {
            "scan_type": "skills",
            "scanner": "cisco-skill-scanner",
            "target": str(scan_root),
            "status": summary.status.value,
            "message": summary.message,
            "finding_count": len(signals),
            "target_count": summary.skills_scanned,
            "analyzers_used": list(summary.analyzers_used),
            "scanner_evidence": [signal.to_dict() for signal in signals],
            "policy_action": policy_action_for_cisco_signals(signals, config=config, harness=harness),
        }
    if scan_type == "mcp":
        summary = cisco_mcp_scanner.run_cisco_mcp_scan(
            target,
            mode=mode,
            timeout_seconds=timeout_seconds,
        )
        signals = tuple(_mcp_findings_to_signals(summary))
        return {
            "scan_type": "mcp",
            "scanner": "cisco-mcp-scanner",
            "target": str(target),
            "status": summary.status.value,
            "message": summary.message,
            "finding_count": len(signals),
            "target_count": summary.targets_scanned,
            "analyzers_used": list(summary.analyzers_used),
            "scanner_evidence": [signal.to_dict() for signal in signals],
            "policy_action": policy_action_for_cisco_signals(signals, config=config, harness=harness),
        }
    raise ValueError(f"Unsupported deep scan type: {scan_type}")


def cisco_risk_signal_v3_to_v2(signal: GuardRiskSignalV3) -> RiskSignalV2:
    """Adapt scanner-aware evidence into the existing decision signal contract."""

    return RiskSignalV2(
        signal_id=signal.signal_id,
        category=signal.category,
        severity=signal.severity,
        confidence=signal.confidence,
        detector=signal.source,
        title=signal.title,
        plain_reason=signal.plain_language_summary,
        technical_detail=signal.technical_detail,
        evidence_ref=signal.evidence_ref,
        redaction_level=signal.redaction_level,
        false_positive_hint=signal.recommended_action,
        advisory_id=None,
    )


def policy_action_for_cisco_signals(
    signals: tuple[GuardRiskSignalV3, ...],
    *,
    config: GuardConfig,
    harness: str | None,
) -> GuardAction:
    """Resolve the policy effect of Cisco scanner evidence using configured security level."""

    if not signals:
        return "allow"
    action: GuardAction = "warn"
    for signal in signals:
        risk_class = _SOURCE_RISK_CLASS.get(signal.source, "mcp_dangerous_tool")
        resolved = resolve_risk_action(config, risk_class, harness=harness)
        if resolved is not None and _ACTION_RANK[resolved] > _ACTION_RANK[action]:
            action = resolved
    return action


def _resolve_target_paths(action: GuardActionEnvelope, workspace: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    for target in action.target_paths:
        candidate = Path(target).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        paths.append(candidate.resolve())
    return tuple(paths)


def _is_skill_file(path: Path) -> bool:
    return path.name == "SKILL.md"


def _skill_scan_root_for_file(path: Path, workspace: Path) -> Path:
    parent = path.parent
    if parent.parent.name == "skills":
        return parent.parent
    if parent.name == "skills":
        return parent
    if parent == workspace:
        return parent
    # Default: scan from the containing directory; callers should verify the result is meaningful.
    return parent


def _skill_scan_root_for_workspace(target: Path) -> Path:
    skills_dir = target / "skills"
    if skills_dir.is_dir():
        return skills_dir
    return target


def _skill_findings_to_signals(summary: object) -> tuple[GuardRiskSignalV3, ...]:
    status = getattr(summary, "status", CiscoIntegrationStatus.FAILED)
    findings = getattr(summary, "findings", ())
    return _findings_to_signals(
        findings,
        scanner_status=status,
        scanner_name="Cisco skill scanner",
    )


def _mcp_findings_to_signals(summary: object) -> tuple[GuardRiskSignalV3, ...]:
    status = getattr(summary, "status", CiscoIntegrationStatus.FAILED)
    findings = getattr(summary, "findings", ())
    return _findings_to_signals(
        findings,
        scanner_status=status,
        scanner_name="Cisco MCP scanner",
    )


def _findings_to_signals(
    findings: object,
    *,
    scanner_status: CiscoIntegrationStatus,
    scanner_name: str,
) -> tuple[GuardRiskSignalV3, ...]:
    if not isinstance(findings, tuple | list):
        return ()
    signals: list[GuardRiskSignalV3] = []
    for finding in findings:
        if isinstance(finding, Finding):
            signals.append(
                cisco_finding_to_risk_signal(
                    finding,
                    scanner_status=scanner_status,
                    scanner_name=scanner_name,
                )
            )
    return tuple(signals)
