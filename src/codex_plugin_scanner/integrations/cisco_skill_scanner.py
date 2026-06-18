"""Cisco skill-scanner integration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..models import Finding, Severity, severity_from_value


class CiscoIntegrationStatus(str, Enum):
    """State of the Cisco skill-scanner integration."""

    ENABLED = "enabled"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class CiscoSkillScanSummary:
    """Normalized summary from a Cisco skill-scanner run."""

    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    skills_scanned: int
    skills_skipped: tuple[str, ...]
    analyzers_used: tuple[str, ...]
    policy_name: str
    total_findings: int
    findings_by_severity: dict[str, int]


def _empty_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def cisco_runtime_unavailable_message() -> str | None:
    if sys.version_info < (3, 14):
        return None
    return (
        "Cisco scanner evidence is unavailable on Python 3.14+ because the patched LiteLLM releases required "
        "by Cisco scanning currently support Python <3.14. HOL Guard will continue without Cisco evidence; "
        "use Python 3.10 through 3.13 for Cisco scanner evidence."
    )


def _normalize_string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()

    items: list[str] = []
    for entry in value:
        if isinstance(entry, str) and entry.strip():
            items.append(entry.strip())
            continue
        if isinstance(entry, dict):
            for key in ("skill_path", "path", "name", "skill_name"):
                candidate = entry.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    items.append(candidate.strip())
                    break
    return tuple(items)


def _build_unavailable_summary(message: str, *, status: CiscoIntegrationStatus) -> CiscoSkillScanSummary:
    return CiscoSkillScanSummary(
        status=status,
        message=message,
        findings=(),
        skills_scanned=0,
        skills_skipped=(),
        analyzers_used=(),
        policy_name="balanced",
        total_findings=0,
        findings_by_severity=_empty_counts(),
    )


def _scan_directory_payload(skills_dir: Path, policy_name: str) -> dict[str, object]:
    from skill_scanner import SkillScanner
    from skill_scanner.core.scan_policy import ScanPolicy

    scanner = SkillScanner(policy=ScanPolicy(preset_base=policy_name))
    report = scanner.scan_directory(skills_dir)
    payload = report.to_dict()
    return payload if isinstance(payload, dict) else {}


_SUBPROCESS_SCAN_SNIPPET = """
from pathlib import Path
import json
import sys
from codex_plugin_scanner.integrations.cisco_skill_scanner import _scan_directory_payload

payload = _scan_directory_payload(Path(sys.argv[1]), sys.argv[2])
Path(sys.argv[3]).write_text(json.dumps(payload), encoding='utf-8')
""".strip()


def _scan_directory_with_timeout(
    skills_dir: Path, policy_name: str, timeout_seconds: float | None
) -> dict[str, object]:
    if timeout_seconds is None:
        return _scan_directory_payload(skills_dir, policy_name)

    file_descriptor, output_name = tempfile.mkstemp(prefix="cisco-skill-scan-", suffix=".json")
    output_path = Path(output_name)
    # Explicit close avoids leaking the temp file descriptor into the child.
    os.close(file_descriptor)

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path)
    try:
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _SUBPROCESS_SCAN_SNIPPET,
                    str(skills_dir),
                    policy_name,
                    str(output_path),
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Cisco skill scanner timed out") from exc

        if result.returncode != 0:
            error_output = result.stderr.strip() or result.stdout.strip()
            if not error_output:
                error_output = f"Cisco skill scanner exited with code {result.returncode}"
            raise RuntimeError(error_output)

        if not output_path.is_file():
            raise RuntimeError("Cisco skill scanner did not produce a result payload")

        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Cisco skill scanner produced invalid JSON output") from exc

        return payload if isinstance(payload, dict) else {}
    finally:
        output_path.unlink(missing_ok=True)


def _to_local_finding(plugin_dir: Path, skill_result: dict[str, object], finding: dict[str, object]) -> Finding:
    skill_path = Path(str(skill_result.get("skill_path", "")))
    relative_skill_path = skill_path
    if skill_path.is_absolute():
        try:
            relative_skill_path = skill_path.relative_to(plugin_dir)
        except ValueError:
            relative_skill_path = Path(skill_path.name)

    finding_path = str(finding.get("file_path") or "").strip()
    full_path = relative_skill_path / finding_path if finding_path else relative_skill_path
    line_number = finding.get("line_number")

    return Finding(
        rule_id=str(finding.get("rule_id") or finding.get("id") or "CISCO-SKILL-SCANNER"),
        severity=severity_from_value(str(finding.get("severity") or "info")),
        category="skill-security",
        title=str(finding.get("title") or "Cisco skill-scanner finding"),
        description=str(finding.get("description") or "Cisco skill-scanner reported a potential issue."),
        remediation=str(finding.get("remediation")) if finding.get("remediation") else None,
        file_path=str(full_path),
        line_number=int(line_number) if isinstance(line_number, int) else None,
        source="cisco-skill-scanner",
    )


def _extract_analyzers_used(results: object) -> tuple[str, ...]:
    if not isinstance(results, list):
        return ()

    analyzers: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        result_analyzers = result.get("analyzers_used", [])
        if isinstance(result_analyzers, list):
            analyzers.extend(str(analyzer) for analyzer in result_analyzers if str(analyzer).strip())
    return tuple(dict.fromkeys(analyzers))


def _extract_skipped_skills(summary: object, results: object) -> tuple[str, ...]:
    skipped: list[str] = []

    if isinstance(summary, dict):
        for key in ("skills_skipped", "skipped_skills", "skipped_skill_paths"):
            skipped.extend(_normalize_string_items(summary.get(key)))

    if isinstance(results, list):
        for result in results:
            if not isinstance(result, dict):
                continue
            result_status = str(result.get("status") or "").strip().lower()
            if result_status == "skipped" or result.get("skipped") is True:
                skipped.extend(
                    _normalize_string_items(
                        [result.get("skill_path") or result.get("path") or result.get("skill_name")]
                    )
                )

    return tuple(dict.fromkeys(skipped))


def run_cisco_skill_scan(
    skills_dir: Path,
    mode: str = "auto",
    policy_name: str = "balanced",
    timeout_seconds: float | None = None,
) -> CiscoSkillScanSummary:
    """Run Cisco skill-scanner against a skills directory when available."""

    if mode == "off":
        return _build_unavailable_summary(
            "Cisco skill scanning disabled by configuration.",
            status=CiscoIntegrationStatus.SKIPPED,
        )
    runtime_message = cisco_runtime_unavailable_message()
    if runtime_message is not None:
        return _build_unavailable_summary(
            runtime_message,
            status=CiscoIntegrationStatus.UNAVAILABLE,
        )

    try:
        __import__("skill_scanner")
        __import__("skill_scanner.core.scan_policy")
    except ImportError:
        if mode == "on":
            return _build_unavailable_summary(
                "Cisco skill scanner is required but not installed. Ensure package dependencies are installed.",
                status=CiscoIntegrationStatus.UNAVAILABLE,
            )
        return _build_unavailable_summary(
            "Cisco skill scanner not installed; deep skill scan skipped.",
            status=CiscoIntegrationStatus.UNAVAILABLE,
        )

    try:
        payload = _scan_directory_with_timeout(skills_dir.resolve(), policy_name, timeout_seconds)
    except TimeoutError:
        return _build_unavailable_summary(
            "Cisco skill scanner timed out before it could finish.",
            status=CiscoIntegrationStatus.TIMED_OUT,
        )
    except Exception as exc:  # pragma: no cover - defensive around third-party code
        return _build_unavailable_summary(
            f"Cisco skill scanner failed: {exc}",
            status=CiscoIntegrationStatus.FAILED,
        )

    findings: list[Finding] = []
    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []
    for result in results:
        if not isinstance(result, dict):
            continue
        skill_findings = result.get("findings", [])
        if not isinstance(skill_findings, list):
            continue
        for finding in skill_findings:
            if isinstance(finding, dict):
                findings.append(_to_local_finding(skills_dir.parent, result, finding))

    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    counts = _empty_counts()
    findings_by_severity = summary.get("findings_by_severity", {})
    if isinstance(findings_by_severity, dict):
        for key, value in findings_by_severity.items():
            if key in counts and isinstance(value, int):
                counts[key] = value

    analyzers_used = _extract_analyzers_used(results)
    skills_skipped = _extract_skipped_skills(summary, results)

    return CiscoSkillScanSummary(
        status=CiscoIntegrationStatus.ENABLED,
        message=f"Cisco skill scanner completed using the {policy_name} policy preset.",
        findings=tuple(findings),
        skills_scanned=int(summary.get("total_skills_scanned", 0)),
        skills_skipped=skills_skipped,
        analyzers_used=analyzers_used,
        policy_name=policy_name,
        total_findings=int(summary.get("total_findings", len(findings))),
        findings_by_severity=counts,
    )
