"""Resident bridge for the Cisco scanner preflight.

Rust owns the authority half of the preflight: which roots an action may
reach, every containment verdict, the mapping of scanner findings to risk
signals and the policy action those signals resolve to. Python only runs the
third-party analyzers between two resident queries, in the bounded scanner
subprocess, and hands back what they reported. It never derives a scan root,
a signal or a verdict, and a missing, unbound or malformed reply raises so
callers fail closed.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from uuid import uuid4

from codex_plugin_scanner.guard.config import GuardConfig, resolve_risk_action
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3, RiskSignalV2
from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

CISCO_PREFLIGHT_FEATURE = "cisco-preflight-v1"
_REQUEST_SCHEMA = "guard-cisco-preflight-request.v1"
_RESULT_SCHEMA = "guard-cisco-preflight-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_DEFAULT_SCANNER_TIMEOUT_SECONDS = 5.0
_CISCO_DETECTOR_MIN_BUDGET_SECONDS = 0.5
_FILE_ACTIONS = frozenset({"file_write", "config_change"})
_TARGET_NAMES = {"skill": "SKILL.md", "mcp": ".mcp.json"}
_RISK_CLASSES = ("malicious_skill", "mcp_dangerous_tool")
UNAVAILABLE = "native_cisco_preflight_unavailable"


class NativeCiscoPreflightError(ValueError):
    """The resident gave no authoritative answer; callers must fail closed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


def _query(query: Mapping[str, object], guard_home: Path | None = None) -> dict[str, object]:
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise NativeCiscoPreflightError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"cisco-preflight-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        response = _resident_request(
            operation="cisco_preflight",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=CISCO_PREFLIGHT_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise NativeCiscoPreflightError from None
    payload = _payload(response, wire, home)
    if payload is None:
        raise NativeCiscoPreflightError
    return payload


def _signals(payload: Mapping[str, object], key: str) -> tuple[GuardRiskSignalV3, ...]:
    entries = payload.get(key)
    if not isinstance(entries, list):
        raise NativeCiscoPreflightError
    try:
        return tuple(GuardRiskSignalV3.from_dict(entry) for entry in entries)
    except (TypeError, ValueError, KeyError):
        raise NativeCiscoPreflightError from None


def _finding_wire(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "source": finding.source,
    }


def _scanned(step: Mapping[str, object], summary: object) -> dict[str, object]:
    status = getattr(summary, "status", CiscoIntegrationStatus.FAILED)
    findings = getattr(summary, "findings", ())
    wire = (
        [_finding_wire(item) for item in findings if isinstance(item, Finding)]
        if isinstance(findings, tuple | list)
        else []
    )
    return {
        **step,
        "status": status.value if isinstance(status, CiscoIntegrationStatus) else "failed",
        "findings": wire,
    }


def _run_analyzer(kind: str, scan_root: Path, *, mode: str, timeout_seconds: float) -> object:
    runner = cisco_skill_scanner.run_cisco_skill_scan if kind == "skill" else cisco_mcp_scanner.run_cisco_mcp_scan
    return runner(scan_root, mode=mode, timeout_seconds=timeout_seconds)


def _candidate_target(target: str, sources: frozenset[str]) -> bool:
    name = Path(target).name
    return any(kind in sources and name == target_name for kind, target_name in _TARGET_NAMES.items())


def scan_action_for_cisco_evidence(
    action: GuardActionEnvelope,
    *,
    workspace: Path | str | None,
    approved_scan_roots: Iterable[Path | str] = (),
    mode: str = "auto",
    sources: Iterable[str] = ("skill", "mcp"),
    timeout_seconds: float = _DEFAULT_SCANNER_TIMEOUT_SECONDS,
) -> tuple[GuardRiskSignalV3, ...]:
    """Cisco preflight evidence for the skill or MCP files an action changes."""

    requested = frozenset(sources)
    if action.action_type not in _FILE_ACTIONS or not any(
        _candidate_target(target, requested) for target in action.target_paths
    ):
        return ()
    try:
        cwd = os.getcwd()
    except OSError:
        raise NativeCiscoPreflightError from None
    try:
        home: str | None = str(Path.home())
    except RuntimeError:
        home = None
    plan = _query(
        {
            "check": "plan",
            "action_type": action.action_type,
            "workspace": None if workspace is None else str(workspace),
            "cwd": cwd,
            "home": home,
            "approved_scan_roots": [str(root) for root in approved_scan_roots],
            "target_paths": list(action.target_paths),
            "sources": sorted(requested),
        }
    )
    steps = plan.get("steps")
    if not isinstance(steps, list) or not all(isinstance(step, dict) for step in steps):
        raise NativeCiscoPreflightError
    if not any(step.get("type") == "scan" for step in steps):
        return _signals({"signals": [step.get("signal") for step in steps]}, "signals")
    ran: list[dict[str, object]] = []
    for step in steps:
        if step.get("type") != "scan":
            ran.append(step)
            continue
        kind, scan_root = step.get("kind"), step.get("scan_root")
        if kind not in _TARGET_NAMES or not isinstance(scan_root, str):
            raise NativeCiscoPreflightError
        summary = _run_analyzer(kind, Path(scan_root), mode=mode, timeout_seconds=timeout_seconds)
        ran.append(_scanned(step, summary))
    return _signals(_query({"check": "evidence", "steps": ran}), "signals")


def policy_action_for_cisco_signals(
    signals: tuple[GuardRiskSignalV3, ...],
    *,
    config: GuardConfig,
    harness: str | None,
) -> GuardAction:
    """The resident's policy effect of Cisco evidence under the configured risk actions."""

    payload = _query(
        {
            "check": "policy_action",
            "signal_sources": [signal.source for signal in signals],
            "configured_actions": {
                risk_class: resolve_risk_action(config, risk_class, harness=harness) for risk_class in _RISK_CLASSES
            },
        }
    )
    action = payload.get("policy_action")
    if not isinstance(action, str):
        raise NativeCiscoPreflightError
    return action  # type: ignore[return-value]


def build_cisco_deep_scan_payload(
    *,
    scan_type: str,
    target: Path,
    mode: str,
    config: GuardConfig,
    harness: str | None = None,
    timeout_seconds: float = _DEFAULT_SCANNER_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Stable CLI payload for deep Cisco scanner evidence."""

    if scan_type not in {"skills", "mcp"}:
        raise ValueError(f"Unsupported deep scan type: {scan_type}")
    kind = "skill" if scan_type == "skills" else "mcp"
    skills_dir = target / "skills"
    scan_root = skills_dir if kind == "skill" and skills_dir.is_dir() else target
    summary = _run_analyzer(kind, scan_root, mode=mode, timeout_seconds=timeout_seconds)
    step = _scanned({"type": "scan", "kind": kind, "scan_root": str(scan_root)}, summary)
    signals = _signals(_query({"check": "evidence", "steps": [step]}), "signals")
    scanned = getattr(summary, "skills_scanned" if kind == "skill" else "targets_scanned", 0)
    return {
        "scan_type": scan_type,
        "scanner": "cisco-skill-scanner" if kind == "skill" else "cisco-mcp-scanner",
        "target": str(scan_root),
        "mode": mode,
        "status": step["status"],
        "message": getattr(summary, "message", ""),
        "finding_count": len(signals),
        "targets_scanned": scanned,
        "analyzers_used": list(getattr(summary, "analyzers_used", ())),
        "scanner_evidence": [signal.to_dict() for signal in signals],
        "policy_action": policy_action_for_cisco_signals(signals, config=config, harness=harness),
    }


def cisco_risk_signal_v3_to_v2(signal: GuardRiskSignalV3) -> RiskSignalV2:
    """Adapt scanner-aware evidence into the decision signal shape (a field projection)."""

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


class _CiscoPreflightDetector:
    detector_id = ""
    categories: tuple[str, ...] = ()
    source = ""

    def detect(self, action: GuardActionEnvelope, context: object) -> tuple[RiskSignalV2, ...]:
        config = getattr(context, "config", None)
        timeout_ms: int = getattr(config, "runtime_detector_timeout_ms", 5000) if config is not None else 5000
        budget_seconds = timeout_ms / 1000.0
        if budget_seconds < _CISCO_DETECTOR_MIN_BUDGET_SECONDS:
            return ()
        signals = scan_action_for_cisco_evidence(
            action,
            workspace=getattr(context, "workspace", None),
            approved_scan_roots=getattr(context, "approved_scan_roots", ()),
            sources=(self.source,),
            timeout_seconds=budget_seconds,
        )
        return tuple(cisco_risk_signal_v3_to_v2(signal) for signal in signals)


class CiscoSkillPreflightDetector(_CiscoPreflightDetector):
    """Detector wrapper for changed local skill files."""

    detector_id = "cisco.skill"
    categories = ("skill",)
    source = "skill"


class CiscoMcpPreflightDetector(_CiscoPreflightDetector):
    """Detector wrapper for changed local MCP config."""

    detector_id = "cisco.mcp"
    categories = ("mcp",)
    source = "mcp"
