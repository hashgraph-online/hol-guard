"""Trust scoring and provenance formatting for scan results."""

from __future__ import annotations

from pathlib import Path

from .checks.manifest import load_manifest
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
    manifest = load_manifest(plugin_dir)
    domains = [
        domain
        for domain in (
            build_plugin_domain(plugin_dir, categories),
            build_skill_domain(plugin_dir, manifest, skill_security_context),
            build_mcp_domain(plugin_dir, categories),
        )
        if domain is not None
    ]
    scores = tuple(domain.score for domain in domains)
    return TrustReport(total=normalize_report_total(scores), domains=tuple(domains))


def build_repository_trust_report(plugin_reports: tuple[TrustReport, ...]) -> TrustReport:
    if not plugin_reports:
        return TrustReport(total=0.0, domains=())
    return TrustReport(total=round_trust_score(min(report.total for report in plugin_reports)), domains=())
