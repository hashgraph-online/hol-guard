"""HCS-style top-level plugin trust scoring."""

from __future__ import annotations

from pathlib import Path

from .checks.manifest import load_manifest
from .models import CategoryResult
from .trust_helpers import build_adapter_score, build_domain_score, category_checks, check_percent, is_https_url
from .trust_models import TrustDomainScore
from .trust_specs import PLUGIN_TRUST_SPEC


def build_plugin_domain(plugin_dir: Path, categories: tuple[CategoryResult, ...]) -> TrustDomainScore:
    manifest = load_manifest(plugin_dir)
    manifest_checks = category_checks(categories, "Manifest Validation")
    security_checks = category_checks(categories, "Security")
    operational_checks = category_checks(categories, "Operational Security")
    best_checks = category_checks(categories, "Best Practices")
    marketplace_checks = category_checks(categories, "Marketplace")
    interface = (
        manifest.get("interface") if isinstance(manifest, dict) and isinstance(manifest.get("interface"), dict) else {}
    )
    interface_declared = isinstance(manifest, dict) and "interface" in manifest
    author = manifest.get("author") if isinstance(manifest, dict) and isinstance(manifest.get("author"), dict) else {}
    has_author = isinstance(author.get("name"), str) and bool(author.get("name"))
    has_homepage = is_https_url(manifest.get("homepage") if isinstance(manifest, dict) else None)
    has_repository = is_https_url(manifest.get("repository") if isinstance(manifest, dict) else None)
    keywords = manifest.get("keywords") if isinstance(manifest, dict) else None
    keyword_count = len(keywords) if isinstance(keywords, list) else 0
    has_interface_category = isinstance(interface.get("category"), str) and bool(interface.get("category"))
    discoverability = (
        100.0
        if has_interface_category and keyword_count >= 3
        else 75.0
        if has_interface_category or keyword_count >= 1
        else 0.0
    )
    provenance = (
        100.0
        if has_author and has_homepage and has_repository
        else 70.0
        if has_author and (has_homepage or has_repository)
        else 40.0
        if has_author or has_repository or has_homepage
        else 0.0
    )
    has_marketplace_surface = (plugin_dir / "marketplace.json").exists()
    has_mcp_surface = (plugin_dir / ".mcp.json").exists()

    spec_by_id = {adapter.adapter_id: adapter for adapter in PLUGIN_TRUST_SPEC.adapters}
    adapters = (
        build_adapter_score(
            spec_by_id["verification.manifest-integrity"],
            component_scores={
                "score": (
                    check_percent(manifest_checks, "plugin.json exists") * 0.20
                    + check_percent(manifest_checks, "Valid JSON") * 0.20
                    + check_percent(manifest_checks, "Required fields present") * 0.35
                    + check_percent(manifest_checks, "Version follows semver") * 0.25
                )
            },
            rationales={
                "score": "Manifest integrity blends existence, JSON validity, required fields, and semver checks."
            },
        ),
        build_adapter_score(
            spec_by_id["verification.interface-integrity"],
            component_scores={
                "score": (
                    check_percent(manifest_checks, "Interface metadata complete if declared") * 0.60
                    + check_percent(manifest_checks, "Interface links and assets valid if declared") * 0.40
                )
            }
            if interface_declared
            else None,
            rationales={"score": "Interface integrity applies when the plugin declares an install surface."},
            applicable=interface_declared,
        ),
        build_adapter_score(
            spec_by_id["verification.path-safety"],
            component_scores={"score": check_percent(manifest_checks, "Declared paths are safe")},
            rationales={"score": "Path safety uses the scanner's declared-path safety check."},
        ),
        build_adapter_score(
            spec_by_id["verification.marketplace-alignment"],
            component_scores={
                "score": (
                    check_percent(marketplace_checks, "marketplace.json valid") * 0.35
                    + check_percent(marketplace_checks, "Policy fields present") * 0.35
                    + check_percent(marketplace_checks, "Marketplace sources are safe") * 0.30
                )
            }
            if has_marketplace_surface
            else None,
            rationales={
                "score": "Marketplace alignment applies when repository-scoped marketplace metadata is present."
            },
            applicable=has_marketplace_surface,
        ),
        build_adapter_score(
            spec_by_id["security.disclosure"],
            component_scores={"score": check_percent(security_checks, "SECURITY.md found")},
            rationales={"score": "Disclosure is one explicit signal, not a proxy for the entire security posture."},
        ),
        build_adapter_score(
            spec_by_id["security.license"],
            component_scores={"score": check_percent(security_checks, "LICENSE found")},
            rationales={"score": "License clarity remains a separate scored signal."},
        ),
        build_adapter_score(
            spec_by_id["security.secret-hygiene"],
            component_scores={"score": check_percent(security_checks, "No hardcoded secrets")},
            rationales={"score": "Secret hygiene uses the scanner's hardcoded-secret detection."},
        ),
        build_adapter_score(
            spec_by_id["security.mcp-safety"],
            component_scores={
                "score": (
                    check_percent(security_checks, "No dangerous MCP commands") * 0.50
                    + check_percent(security_checks, "MCP remote transports are hardened") * 0.50
                )
            }
            if has_mcp_surface
            else None,
            rationales={"score": "MCP safety applies only when the plugin declares an MCP surface."},
            applicable=has_mcp_surface,
        ),
        build_adapter_score(
            spec_by_id["security.approval-hygiene"],
            component_scores={"score": check_percent(security_checks, "No approval bypass defaults")},
            rationales={"score": "Approval hygiene checks for bypass-style defaults."},
        ),
        build_adapter_score(
            spec_by_id["metadata.documentation"],
            component_scores={"score": check_percent(best_checks, "README.md found")},
            rationales={"score": "Documentation reflects README coverage for operators and maintainers."},
        ),
        build_adapter_score(
            spec_by_id["metadata.manifest-metadata"],
            component_scores={"score": check_percent(manifest_checks, "Recommended metadata present")},
            rationales={"score": "Manifest metadata tracks the scanner's recommended-metadata check."},
        ),
        build_adapter_score(
            spec_by_id["metadata.discoverability"],
            component_scores={"score": discoverability},
            rationales={"score": "Discoverability uses category plus keyword coverage."},
        ),
        build_adapter_score(
            spec_by_id["metadata.provenance"],
            component_scores={"score": provenance},
            rationales={"score": "Provenance reflects author, homepage, and repository metadata coverage."},
        ),
        build_adapter_score(
            spec_by_id["operations.action-pinning"],
            component_scores={"score": check_percent(operational_checks, "Third-party GitHub Actions pinned to SHAs")},
            rationales={"score": "Action pinning uses the scanner's immutable-action check."},
        ),
        build_adapter_score(
            spec_by_id["operations.permission-scope"],
            component_scores={"score": check_percent(operational_checks, "No write-all GitHub Actions permissions")},
            rationales={"score": "Permission scope uses the least-privilege workflow check."},
        ),
        build_adapter_score(
            spec_by_id["operations.untrusted-checkout"],
            component_scores={"score": check_percent(operational_checks, "No privileged untrusted checkout patterns")},
            rationales={"score": "Untrusted-checkout protection uses the scanner's privileged-workflow check."},
        ),
        build_adapter_score(
            spec_by_id["operations.update-automation"],
            component_scores={
                "score": (
                    check_percent(operational_checks, "Dependabot configured for automation surfaces") * 0.50
                    + check_percent(operational_checks, "Dependency manifests have lockfiles") * 0.50
                )
            },
            rationales={"score": "Update automation combines Dependabot coverage and lockfile hygiene."},
        ),
    )
    return build_domain_score(domain="plugin", spec=PLUGIN_TRUST_SPEC, adapters=adapters)
