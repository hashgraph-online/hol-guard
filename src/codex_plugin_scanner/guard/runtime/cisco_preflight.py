"""Cisco scanner preflight helpers for local Guard runtime actions."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.action_lattice import most_restrictive_guard_action
from codex_plugin_scanner.guard.config import GuardConfig, resolve_risk_action
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.cisco_evidence import cisco_finding_to_risk_signal
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3, RiskSignalV2
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding

_DEFAULT_SCANNER_TIMEOUT_SECONDS = 5.0
_SOURCE_RISK_CLASS: dict[str, str] = {
    "cisco_skill": "malicious_skill",
    "cisco_mcp": "mcp_dangerous_tool",
    "native": "mcp_dangerous_tool",
    "threat_intel": "mcp_dangerous_tool",
    "runtime_detector": "mcp_dangerous_tool",
}


_CISCO_DETECTOR_MIN_BUDGET_SECONDS = 0.5
_OUTSIDE_APPROVED_WORKSPACE = "outside_approved_workspace"


@dataclass(frozen=True, slots=True)
class _ApprovedScanRoot:
    path: Path
    label: str


@dataclass(frozen=True, slots=True)
class _ValidatedScanTarget:
    path: Path | None
    scan_root: Path
    approved_root: _ApprovedScanRoot
    kind: str


class _CiscoPathContainmentError(RuntimeError):
    def __init__(self, reason: str, *, approved_root_label: str = "selected-workspace") -> None:
        super().__init__(reason)
        self.reason: str = reason
        self.approved_root_label: str = approved_root_label


class CiscoSkillPreflightDetector:
    """Detector wrapper for changed local skill files."""

    detector_id = "cisco.skill"
    categories = ("skill",)

    def detect(self, action: GuardActionEnvelope, context: object) -> tuple[RiskSignalV2, ...]:
        workspace = getattr(context, "workspace", None)
        config = getattr(context, "config", None)
        timeout_ms: int = getattr(config, "runtime_detector_timeout_ms", 5000) if config is not None else 5000
        budget_seconds = timeout_ms / 1000.0
        if budget_seconds < _CISCO_DETECTOR_MIN_BUDGET_SECONDS:
            return ()
        signals = scan_action_for_cisco_evidence(
            action,
            workspace=workspace,
            approved_scan_roots=getattr(context, "approved_scan_roots", ()),
            sources=("skill",),
            timeout_seconds=budget_seconds,
        )
        return tuple(cisco_risk_signal_v3_to_v2(signal) for signal in signals)


class CiscoMcpPreflightDetector:
    """Detector wrapper for changed local MCP config."""

    detector_id = "cisco.mcp"
    categories = ("mcp",)

    def detect(self, action: GuardActionEnvelope, context: object) -> tuple[RiskSignalV2, ...]:
        workspace = getattr(context, "workspace", None)
        config = getattr(context, "config", None)
        timeout_ms: int = getattr(config, "runtime_detector_timeout_ms", 5000) if config is not None else 5000
        budget_seconds = timeout_ms / 1000.0
        if budget_seconds < _CISCO_DETECTOR_MIN_BUDGET_SECONDS:
            return ()
        signals = scan_action_for_cisco_evidence(
            action,
            workspace=workspace,
            approved_scan_roots=getattr(context, "approved_scan_roots", ()),
            sources=("mcp",),
            timeout_seconds=budget_seconds,
        )
        return tuple(cisco_risk_signal_v3_to_v2(signal) for signal in signals)


def _is_redacted_path(path_str: str) -> bool:
    """Return True when a target path is a redacted placeholder (starts with .../)."""
    return path_str.startswith(".../")


def scan_action_for_cisco_evidence(
    action: GuardActionEnvelope,
    *,
    workspace: Path | str | None,
    approved_scan_roots: Iterable[Path | str] = (),
    mode: str = "auto",
    sources: Iterable[str] = ("skill", "mcp"),
    timeout_seconds: float = _DEFAULT_SCANNER_TIMEOUT_SECONDS,
) -> tuple[GuardRiskSignalV3, ...]:
    """Run Cisco preflight scans for changed skill or MCP files referenced by an action."""

    if action.action_type not in {"file_write", "config_change"}:
        return ()
    requested_sources = frozenset(sources)
    signals: list[GuardRiskSignalV3] = []
    try:
        approved_roots = _canonical_approved_scan_roots(workspace, approved_scan_roots)
    except _CiscoPathContainmentError as exc:
        return (_cisco_path_containment_signal("approved-root", exc),)
    primary_root = approved_roots[0]
    scanned_skill_roots: set[Path] = set()
    scanned_mcp_roots: set[Path] = set()
    redacted_skill_target = False
    redacted_mcp_target = False
    for target_str in action.target_paths:
        target_kind = _cisco_target_kind(target_str, requested_sources)
        if target_kind is None:
            continue
        if _is_redacted_path(target_str):
            redacted_skill_target = redacted_skill_target or target_kind == "skill"
            redacted_mcp_target = redacted_mcp_target or target_kind == "mcp"
            continue
        try:
            validated = _validated_scan_target(
                target_str,
                kind=target_kind,
                resolution_root=primary_root.path,
                approved_roots=approved_roots,
            )
            _revalidate_scan_target(validated)
        except _CiscoPathContainmentError as exc:
            _append_unique_signal(signals, _cisco_path_containment_signal(target_kind, exc))
            continue
        if target_kind == "skill" and validated.scan_root not in scanned_skill_roots:
            scanned_skill_roots.add(validated.scan_root)
            signals.extend(
                _skill_findings_to_signals(
                    cisco_skill_scanner.run_cisco_skill_scan(
                        validated.scan_root,
                        mode=mode,
                        timeout_seconds=timeout_seconds,
                    )
                )
            )
        if target_kind == "mcp" and validated.scan_root not in scanned_mcp_roots:
            scanned_mcp_roots.add(validated.scan_root)
            signals.extend(
                _mcp_findings_to_signals(
                    cisco_mcp_scanner.run_cisco_mcp_scan(
                        validated.scan_root,
                        mode=mode,
                        timeout_seconds=timeout_seconds,
                    )
                )
            )
    if redacted_skill_target:
        try:
            validated = _validated_redacted_scan_target("skill", primary_root)
            _revalidate_scan_target(validated)
        except _CiscoPathContainmentError as exc:
            _append_unique_signal(signals, _cisco_path_containment_signal("skill", exc))
        else:
            if validated.scan_root not in scanned_skill_roots:
                scanned_skill_roots.add(validated.scan_root)
                signals.extend(
                    _skill_findings_to_signals(
                        cisco_skill_scanner.run_cisco_skill_scan(
                            validated.scan_root,
                            mode=mode,
                            timeout_seconds=timeout_seconds,
                        )
                    )
                )
    if redacted_mcp_target:
        try:
            validated = _validated_redacted_scan_target("mcp", primary_root)
            _revalidate_scan_target(validated)
        except _CiscoPathContainmentError as exc:
            _append_unique_signal(signals, _cisco_path_containment_signal("mcp", exc))
        else:
            if validated.scan_root not in scanned_mcp_roots:
                scanned_mcp_roots.add(validated.scan_root)
                signals.extend(
                    _mcp_findings_to_signals(
                        cisco_mcp_scanner.run_cisco_mcp_scan(
                            validated.scan_root,
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
            "mode": mode,
            "status": summary.status.value,
            "message": summary.message,
            "finding_count": len(signals),
            "targets_scanned": summary.skills_scanned,
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
            "mode": mode,
            "status": summary.status.value,
            "message": summary.message,
            "finding_count": len(signals),
            "targets_scanned": summary.targets_scanned,
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
    action: GuardAction = "allow"
    for signal in signals:
        risk_class = _SOURCE_RISK_CLASS.get(signal.source, "mcp_dangerous_tool")
        resolved = resolve_risk_action(config, risk_class, harness=harness)
        if resolved is not None:
            action = most_restrictive_guard_action(action, resolved)
    return action


def _canonical_approved_scan_roots(
    workspace: Path | str | None,
    approved_scan_roots: Iterable[Path | str],
) -> tuple[_ApprovedScanRoot, ...]:
    primary_value = workspace if workspace is not None else Path.cwd()
    primary_path = _canonical_readable_directory(primary_value, label="selected-workspace")
    roots = [_ApprovedScanRoot(primary_path, "selected-workspace")]
    for index, root_value in enumerate(approved_scan_roots, start=1):
        label = f"explicit-root-{index}"
        canonical = _canonical_readable_directory(root_value, label=label)
        if canonical not in {root.path for root in roots}:
            roots.append(_ApprovedScanRoot(canonical, label))
    return tuple(roots)


def _canonical_readable_directory(value: Path | str, *, label: str) -> Path:
    try:
        canonical = Path(value).expanduser().resolve(strict=True)
        metadata = canonical.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise _CiscoPathContainmentError("approved_root_unresolved", approved_root_label=label) from exc
    readable_bits = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    searchable_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not metadata.st_mode & readable_bits
        or not metadata.st_mode & searchable_bits
        or not os.access(canonical, os.R_OK | os.X_OK)
    ):
        raise _CiscoPathContainmentError("approved_root_unreadable", approved_root_label=label)
    return canonical


def _cisco_target_kind(target: str, requested_sources: frozenset[str]) -> str | None:
    target_name = Path(target).name
    if "skill" in requested_sources and target_name == "SKILL.md":
        return "skill"
    if "mcp" in requested_sources and target_name == ".mcp.json":
        return "mcp"
    return None


def _validated_scan_target(
    target: str,
    *,
    kind: str,
    resolution_root: Path,
    approved_roots: tuple[_ApprovedScanRoot, ...],
) -> _ValidatedScanTarget:
    candidate = Path(target).expanduser()
    if not candidate.is_absolute():
        candidate = resolution_root / candidate
    try:
        target_path = candidate.resolve(strict=True)
        target_metadata = target_path.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise _CiscoPathContainmentError("target_unresolved") from exc
    approved_root = _most_specific_approved_root(target_path, approved_roots)
    if approved_root is None:
        raise _CiscoPathContainmentError("target_outside_approved_roots")
    if not stat.S_ISREG(target_metadata.st_mode) or not target_metadata.st_mode & (
        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    ):
        raise _CiscoPathContainmentError(
            "target_not_readable_regular_file",
            approved_root_label=approved_root.label,
        )
    if not os.access(target_path, os.R_OK):
        raise _CiscoPathContainmentError("target_unreadable", approved_root_label=approved_root.label)
    scan_root = _derived_scan_root(target_path, kind=kind, approved_root=approved_root)
    return _ValidatedScanTarget(target_path, scan_root, approved_root, kind)


def _validated_redacted_scan_target(kind: str, primary_root: _ApprovedScanRoot) -> _ValidatedScanTarget:
    scan_root = _skill_scan_root_for_workspace(primary_root.path) if kind == "skill" else primary_root.path
    canonical_scan_root = _canonical_scan_root(scan_root, approved_root=primary_root)
    return _ValidatedScanTarget(None, canonical_scan_root, primary_root, kind)


def _derived_scan_root(
    target_path: Path,
    *,
    kind: str,
    approved_root: _ApprovedScanRoot,
) -> Path:
    candidate = _skill_scan_root_for_file(target_path, approved_root.path) if kind == "skill" else target_path.parent
    return _canonical_scan_root(candidate, approved_root=approved_root)


def _canonical_scan_root(candidate: Path, *, approved_root: _ApprovedScanRoot) -> Path:
    try:
        canonical = candidate.resolve(strict=True)
        metadata = canonical.stat()
        _ = canonical.relative_to(approved_root.path)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _CiscoPathContainmentError(
            "derived_scan_root_outside_approved_root",
            approved_root_label=approved_root.label,
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not metadata.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or not os.access(canonical, os.R_OK | os.X_OK)
    ):
        raise _CiscoPathContainmentError(
            "derived_scan_root_unreadable",
            approved_root_label=approved_root.label,
        )
    return canonical


def _most_specific_approved_root(
    target: Path,
    approved_roots: tuple[_ApprovedScanRoot, ...],
) -> _ApprovedScanRoot | None:
    for root in sorted(approved_roots, key=lambda item: len(item.path.parts), reverse=True):
        try:
            _ = target.relative_to(root.path)
        except ValueError:
            continue
        return root
    return None


def _revalidate_scan_target(target: _ValidatedScanTarget) -> None:
    approved_root = _canonical_readable_directory(target.approved_root.path, label=target.approved_root.label)
    if approved_root != target.approved_root.path:
        raise _CiscoPathContainmentError(
            "approved_root_changed",
            approved_root_label=target.approved_root.label,
        )
    if target.path is not None:
        try:
            resolved_target = target.path.resolve(strict=True)
            target_metadata = resolved_target.stat()
        except (OSError, RuntimeError, ValueError) as exc:
            raise _CiscoPathContainmentError(
                "target_changed",
                approved_root_label=target.approved_root.label,
            ) from exc
        if (
            resolved_target != target.path
            or not stat.S_ISREG(target_metadata.st_mode)
            or not target_metadata.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            or not os.access(resolved_target, os.R_OK)
        ):
            raise _CiscoPathContainmentError(
                "target_changed",
                approved_root_label=target.approved_root.label,
            )
        derived_root = _derived_scan_root(
            resolved_target,
            kind=target.kind,
            approved_root=target.approved_root,
        )
        if derived_root != target.scan_root:
            raise _CiscoPathContainmentError(
                "derived_scan_root_changed",
                approved_root_label=target.approved_root.label,
            )
    revalidated_scan_root = _canonical_scan_root(target.scan_root, approved_root=target.approved_root)
    if revalidated_scan_root != target.scan_root:
        raise _CiscoPathContainmentError(
            "derived_scan_root_changed",
            approved_root_label=target.approved_root.label,
        )


def _cisco_path_containment_signal(kind: str, error: _CiscoPathContainmentError) -> GuardRiskSignalV3:
    signal_suffix = stable_digest_hex(f"{kind}|{error.reason}|{error.approved_root_label}".encode(), length=12)
    return GuardRiskSignalV3(
        signal_id=f"cisco-preflight:{_OUTSIDE_APPROVED_WORKSPACE}:{signal_suffix}",
        source="runtime_detector",
        source_version="1",
        category="filesystem",
        severity="high",
        confidence="strong",
        title="Cisco preflight target is outside the approved workspace",
        plain_language_summary=(
            "Guard did not run the Cisco scanner because the target or derived scan root could not be proven "
            "to remain inside the selected workspace or another explicitly approved folder."
        ),
        technical_detail=f"{_OUTSIDE_APPROVED_WORKSPACE}: {error.reason}",
        evidence_ref=f"approved-root:{error.approved_root_label}",
        scanner_name="Cisco preflight containment",
        scanner_status="failed",
        scanner_rule_id=_OUTSIDE_APPROVED_WORKSPACE,
        redaction_level="redacted",
        source_path=None,
        source_line=None,
        data_source=None,
        data_sink=None,
        recommended_action=(
            "Move the target into the selected workspace or explicitly approve its containing folder, then retry."
        ),
    )


def _append_unique_signal(signals: list[GuardRiskSignalV3], signal: GuardRiskSignalV3) -> None:
    if signal not in signals:
        signals.append(signal)


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
