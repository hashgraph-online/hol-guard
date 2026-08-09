"""Privacy-safe local HOL Guard risk reports.

The report is intentionally coarse. It summarizes protection posture without
serializing prompts, commands, source code, findings, file paths, hostnames,
usernames, secrets, tokens, raw receipts, or workspace contents.
"""

from __future__ import annotations

import hashlib
import html
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Literal

SCHEMA_VERSION = "guard-local-risk-report/v1"

RiskBand = Literal["low", "review", "high"]


@dataclass(frozen=True)
class LocalRiskCheck:
    id: str
    status: Literal["pass", "review", "fail"]
    summary: str


@dataclass(frozen=True)
class LocalRiskReport:
    schema_version: str
    generated_at: str
    guard_version: str
    risk_band: RiskBand
    checks: tuple[LocalRiskCheck, ...]
    managed_harness_count: int
    installed_harnesses: tuple[str, ...]
    review_item_count: int
    pending_approval_count: int
    receipt_count: int
    cloud_sync_configured: bool
    sensitive_content_included: Literal[False]
    certification: Literal[False]
    limitation: str
    integrity_sha256: str


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(0, value)
    return 0


def _safe_harnesses(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _risk_band(checks: Sequence[LocalRiskCheck]) -> RiskBand:
    if any(check.status == "fail" for check in checks):
        return "high"
    if any(check.status == "review" for check in checks):
        return "review"
    return "low"


def _canonical_report_payload(payload: Mapping[str, object]) -> bytes:
    without_digest = {key: value for key, value in payload.items() if key != "integrity_sha256"}
    return json.dumps(without_digest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_local_risk_report(
    status_payload: Mapping[str, object],
    *,
    guard_version: str,
) -> LocalRiskReport:
    """Build a sanitized report from the existing local status payload."""

    harnesses = _safe_harnesses(status_payload.get("harnesses"))
    installed_harnesses = tuple(
        sorted(
            {
                str(item.get("harness"))
                for item in harnesses
                if item.get("installed") is True and isinstance(item.get("harness"), str)
            }
        )
    )
    managed_harness_count = _nonnegative_int(status_payload.get("managed_harnesses"))
    review_item_count = sum(_nonnegative_int(item.get("review_count")) for item in harnesses)
    pending_approval_count = _nonnegative_int(status_payload.get("pending_approvals"))
    receipt_count = _nonnegative_int(status_payload.get("receipt_count"))
    runtime_status = str(status_payload.get("runtime_status") or "offline")
    cloud_sync_configured = bool(status_payload.get("sync_configured"))

    checks: list[LocalRiskCheck] = []
    checks.append(
        LocalRiskCheck(
            id="runtime",
            status="pass" if runtime_status == "active" else "fail",
            summary=(
                "Local Guard runtime is active." if runtime_status == "active" else "Local Guard runtime is not active."
            ),
        )
    )
    checks.append(
        LocalRiskCheck(
            id="managed_harnesses",
            status="pass" if managed_harness_count > 0 else "review",
            summary=(
                f"{managed_harness_count} detected harness(es) are managed by Guard."
                if managed_harness_count > 0
                else "No detected harness is currently managed by Guard."
            ),
        )
    )
    checks.append(
        LocalRiskCheck(
            id="configuration_review",
            status="review" if review_item_count > 0 else "pass",
            summary=(
                f"{review_item_count} managed artifact change(s) need review."
                if review_item_count > 0
                else "No managed artifact changes are waiting for review."
            ),
        )
    )
    checks.append(
        LocalRiskCheck(
            id="pending_approvals",
            status="review" if pending_approval_count > 0 else "pass",
            summary=(
                f"{pending_approval_count} action(s) are waiting for approval."
                if pending_approval_count > 0
                else "No actions are waiting for approval."
            ),
        )
    )

    generated_at = str(status_payload.get("generated_at") or "")
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "guard_version": guard_version,
        "risk_band": _risk_band(checks),
        "checks": [asdict(check) for check in checks],
        "managed_harness_count": managed_harness_count,
        "installed_harnesses": list(installed_harnesses),
        "review_item_count": review_item_count,
        "pending_approval_count": pending_approval_count,
        "receipt_count": receipt_count,
        "cloud_sync_configured": cloud_sync_configured,
        "sensitive_content_included": False,
        "certification": False,
        "limitation": (
            "This is a local posture summary, not a certification or proof that every attack is blocked. "
            "Coverage depends on the installed Guard version, harness, event surface, policy, and runtime state."
        ),
    }
    digest = hashlib.sha256(_canonical_report_payload(base)).hexdigest()
    return LocalRiskReport(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at,
        guard_version=guard_version,
        risk_band=_risk_band(checks),
        checks=tuple(checks),
        managed_harness_count=managed_harness_count,
        installed_harnesses=installed_harnesses,
        review_item_count=review_item_count,
        pending_approval_count=pending_approval_count,
        receipt_count=receipt_count,
        cloud_sync_configured=cloud_sync_configured,
        sensitive_content_included=False,
        certification=False,
        limitation=str(base["limitation"]),
        integrity_sha256=digest,
    )


def local_risk_report_json(report: LocalRiskReport) -> str:
    return json.dumps(asdict(report), sort_keys=True, indent=2) + "\n"


def render_local_risk_report_html(report: LocalRiskReport) -> str:
    check_items = "".join(
        f"<li><strong>{html.escape(check.id)}</strong>: {html.escape(check.status)} — {html.escape(check.summary)}</li>"
        for check in report.checks
    )
    harnesses = ", ".join(html.escape(item) for item in report.installed_harnesses) or "None detected"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="robots" content="noindex,nofollow">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>HOL Guard local risk report</title></head><body>"
        "<main><h1>HOL Guard local risk report</h1>"
        f"<p>Risk band: <strong>{html.escape(report.risk_band)}</strong></p>"
        f"<p>Guard version: {html.escape(report.guard_version)}</p>"
        f"<p>Installed harnesses: {harnesses}</p>"
        f"<ul>{check_items}</ul>"
        f"<p>{html.escape(report.limitation)}</p>"
        f"<p>Integrity SHA-256: <code>{report.integrity_sha256}</code></p>"
        "<p>Sensitive local content included: no.</p>"
        "</main></body></html>\n"
    )


def verify_local_risk_report(report: LocalRiskReport) -> bool:
    payload = asdict(report)
    return report.integrity_sha256 == hashlib.sha256(_canonical_report_payload(payload)).hexdigest()
