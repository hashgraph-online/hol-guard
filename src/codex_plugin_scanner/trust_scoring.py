"""Trust scoring and provenance formatting for scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .checks.skill_security import SkillSecurityContext
from .models import CategoryResult
from .trust_domain_scoring import build_mcp_domain, build_plugin_domain, build_skill_domain
from .trust_helpers import normalize_report_total, round_trust_score
from .trust_models import TrustReport


def build_plugin_trust_report(
    plugin_dir: Path,
    categories: tuple[CategoryResult, ...],
    skill_security_context: SkillSecurityContext,
) -> TrustReport:
    computed_at = datetime.now(timezone.utc).isoformat()
    domains = [
        domain
        for domain in (
            build_plugin_domain(plugin_dir, categories),
            build_skill_domain(plugin_dir, skill_security_context),
            build_mcp_domain(plugin_dir, categories),
        )
        if domain is not None
    ]
    scores = tuple(domain.score for domain in domains)
    return TrustReport(
        total=normalize_report_total(scores),
        include_external=False,
        computed_at=computed_at,
        domains=tuple(domains),
    )


def build_repository_trust_report(plugin_reports: tuple[TrustReport, ...]) -> TrustReport:
    if not plugin_reports:
        return TrustReport(
            total=0.0,
            include_external=False,
            computed_at=datetime.now(timezone.utc).isoformat(),
            domains=(),
        )
    return TrustReport(
        total=round_trust_score(min(report.total for report in plugin_reports)),
        include_external=False,
        computed_at=max(report.computed_at for report in plugin_reports),
        domains=(),
    )
