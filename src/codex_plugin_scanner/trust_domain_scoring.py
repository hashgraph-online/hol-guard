"""Domain-specific trust scoring."""

from __future__ import annotations

from pathlib import Path

from .checks.manifest import SEMVER_RE, load_manifest
from .checks.skill_security import SkillSecurityContext
from .integrations.cisco_skill_scanner import CiscoIntegrationStatus
from .models import CategoryResult
from .trust_helpers import (
    category_checks,
    check_percent,
    has_required_skill_frontmatter,
    is_https_url,
    load_mcp_payload,
    normalize_adapter_total,
    parse_skill_frontmatter,
    round_trust_score,
    url_host,
    weighted_score,
)
from .trust_models import TrustAdapterScore, TrustComponentScore, TrustDomainScore
from .trust_specs import MCP_TRUST_SPEC, PLUGIN_TRUST_SPEC, SKILL_TRUST_SPEC


def _component(
    key: str,
    values: dict[str, float],
    rationale: str,
) -> TrustComponentScore:
    return TrustComponentScore(key, values[key], rationale)


def _skill_files(plugin_dir: Path, manifest: dict[str, object] | None) -> tuple[Path, ...]:
    if manifest is None:
        return ()
    skills_root = manifest.get("skills")
    if not isinstance(skills_root, str) or not skills_root.strip():
        return ()
    skills_dir = plugin_dir / skills_root
    if not skills_dir.is_dir():
        return ()
    return tuple(sorted(skills_dir.rglob("SKILL.md")))


def build_skill_domain(
    plugin_dir: Path,
    manifest: dict[str, object] | None,
    context: SkillSecurityContext,
) -> TrustDomainScore | None:
    skill_files = _skill_files(plugin_dir, manifest)
    if not skill_files:
        return None

    frontmatters = [payload for payload in (parse_skill_frontmatter(path) for path in skill_files) if payload]
    valid_frontmatters = [payload for payload in frontmatters if has_required_skill_frontmatter(payload)]
    all_frontmatter_valid = len(valid_frontmatters) == len(skill_files)
    descriptions = [str(payload.get("description", "")).strip() for payload in frontmatters]
    average_description_length = (
        sum(len(description) for description in descriptions) / len(descriptions) if descriptions else 0
    )
    tags: list[str] = []
    for payload in frontmatters:
        value = payload.get("tags")
        if isinstance(value, list):
            tags.extend(item for item in value if isinstance(item, str) and item.strip())
        elif isinstance(value, str) and value.strip():
            tags.extend(item.strip() for item in value.split(",") if item.strip())
    interface = manifest.get("interface") if isinstance(manifest, dict) else None
    has_category = (
        isinstance(interface, dict) and isinstance(interface.get("category"), str) and bool(interface.get("category"))
    )
    has_author = (
        isinstance(manifest.get("author"), dict)
        and isinstance(manifest["author"].get("name"), str)
        and bool(manifest["author"].get("name"))
    )
    repository = manifest.get("repository") if isinstance(manifest, dict) else None
    homepage = manifest.get("homepage") if isinstance(manifest, dict) else None
    version = manifest.get("version") if isinstance(manifest, dict) else None
    repo_host = url_host(repository if isinstance(repository, str) else None)
    home_host = url_host(homepage if isinstance(homepage, str) else None)
    same_host = bool(repo_host) and repo_host == home_host

    verified_components = {
        "publisherBound": 100.0 if has_author else 0.0,
        "repoCommitIntegrity": (
            100.0
            if isinstance(repository, str) and repository and isinstance(version, str) and SEMVER_RE.match(version)
            else 0.0
        ),
        "manifestIntegrity": 100.0 if all_frontmatter_valid else 0.0,
        "domainProof": 100.0 if same_host else 0.0,
    }
    verified_components["score"] = weighted_score(
        verified_components,
        {
            "publisherBound": 20.0,
            "repoCommitIntegrity": 40.0,
            "manifestIntegrity": 30.0,
            "domainProof": 10.0,
        },
    )

    has_links = isinstance(homepage, str) and homepage.strip()
    has_repo = isinstance(repository, str) and repository.strip()
    links = 100.0 if has_links and has_repo else 60.0 if has_links or has_repo else 0.0
    if average_description_length >= 160:
        description_score = 100.0
    elif average_description_length >= 80:
        description_score = 85.0
    elif average_description_length >= 30:
        description_score = 65.0
    elif average_description_length >= 10:
        description_score = 40.0
    else:
        description_score = 0.0
    tag_count = len(tags)
    if has_category and tag_count >= 3:
        taxonomy = 100.0
    elif has_category and tag_count >= 1:
        taxonomy = 85.0
    elif has_category or tag_count >= 3:
        taxonomy = 70.0
    elif tag_count >= 1:
        taxonomy = 55.0
    else:
        taxonomy = 0.0
    if has_repo and isinstance(version, str) and SEMVER_RE.match(version):
        provenance = 100.0
    elif has_repo:
        provenance = 70.0
    elif isinstance(version, str) and SEMVER_RE.match(version):
        provenance = 40.0
    else:
        provenance = 0.0
    metadata_components = {
        "links": links,
        "description": description_score,
        "taxonomy": taxonomy,
        "provenance": provenance,
    }
    metadata_components["score"] = weighted_score(
        metadata_components,
        {
            "links": 30.0,
            "description": 25.0,
            "taxonomy": 20.0,
            "provenance": 25.0,
        },
    )

    safety_score = 50.0
    safety_message = "Cisco skill scanning unavailable; using neutral local safety score."
    if context.summary is not None and context.summary.status == CiscoIntegrationStatus.ENABLED:
        unique_findings = {f"{finding.rule_id}:{finding.severity.value}" for finding in context.summary.findings}
        safety_score = 100.0
        for finding_key in unique_findings:
            if finding_key.endswith(":critical"):
                safety_score -= 50.0
            elif finding_key.endswith(":high"):
                safety_score -= 25.0
            elif finding_key.endswith(":medium"):
                safety_score -= 12.0
            elif finding_key.endswith(":low"):
                safety_score -= 6.0
        safety_score = round_trust_score(safety_score)
        safety_message = context.summary.message
    elif context.summary is not None and context.summary.status == CiscoIntegrationStatus.SKIPPED:
        safety_message = context.summary.message

    adapters = (
        TrustAdapterScore(
            adapter_id="verified",
            label="Verification Signals",
            weight=1.0,
            score=normalize_adapter_total(SKILL_TRUST_SPEC.adapters[0].component_keys, verified_components),
            components=(
                _component("score", verified_components, "Broker-aligned weighted verification subtotal."),
                _component("publisherBound", verified_components, "Manifest author is present for bundled skills."),
                _component(
                    "repoCommitIntegrity",
                    verified_components,
                    "Repository and semver version are present for local provenance.",
                ),
                _component(
                    "manifestIntegrity",
                    verified_components,
                    "All bundled skills parse frontmatter with required fields.",
                ),
                _component("domainProof", verified_components, "Homepage and repository hosts align."),
            ),
        ),
        TrustAdapterScore(
            adapter_id="safety",
            label="Safety Signals",
            weight=1.0,
            score=normalize_adapter_total(SKILL_TRUST_SPEC.adapters[1].component_keys, {"score": safety_score}),
            components=(TrustComponentScore("score", safety_score, safety_message),),
        ),
        TrustAdapterScore(
            adapter_id="metadata",
            label="Metadata Completeness",
            weight=0.75,
            score=normalize_adapter_total(SKILL_TRUST_SPEC.adapters[2].component_keys, metadata_components),
            components=(
                _component("score", metadata_components, "Broker-aligned weighted metadata subtotal."),
                _component(
                    "links",
                    metadata_components,
                    "Homepage and repository links are declared for the bundled skill package.",
                ),
                _component(
                    "description",
                    metadata_components,
                    "Skill descriptions are substantive enough for discovery.",
                ),
                _component("taxonomy", metadata_components, "Skills expose category and tag signals for discovery."),
                _component(
                    "provenance",
                    metadata_components,
                    "Repository and version provenance are declared locally.",
                ),
            ),
        ),
    )
    total = round_trust_score((adapters[0].score * 1.0 + adapters[1].score * 1.0 + adapters[2].score * 0.75) / 2.75)
    return TrustDomainScore(
        domain="skills",
        label=SKILL_TRUST_SPEC.label,
        spec_id=SKILL_TRUST_SPEC.spec_id,
        spec_version=SKILL_TRUST_SPEC.version,
        spec_path=SKILL_TRUST_SPEC.spec_path,
        derived_from=SKILL_TRUST_SPEC.derived_from,
        score=total,
        adapters=adapters,
    )


def build_mcp_domain(plugin_dir: Path, categories: tuple[CategoryResult, ...]) -> TrustDomainScore | None:
    payload_state = load_mcp_payload(plugin_dir)
    if payload_state is None:
        return None
    payload = payload_state.payload

    security_checks = category_checks(categories, "Security")
    remotes = payload.get("remotes")
    servers = payload.get("mcpServers")
    remote_entries = remotes if isinstance(remotes, list) else []
    local_servers = servers if isinstance(servers, dict) else {}
    has_named_surfaces = bool(remote_entries) or bool(local_servers)
    secure_remote_urls = (
        all(isinstance(entry, dict) and is_https_url(str(entry.get("url", ""))) for entry in remote_entries)
        if remote_entries
        else True
    )
    local_commands_valid = (
        all(
            isinstance(config, dict)
            and isinstance(config.get("command"), str)
            and bool(config.get("command"))
            and (
                "args" not in config
                or (
                    isinstance(config.get("args"), list) and all(isinstance(value, str) for value in config.get("args"))
                )
            )
            for config in local_servers.values()
        )
        if local_servers
        else True
    )
    config_shape = payload_state.parse_valid and (
        (remotes is None or isinstance(remotes, list)) and (servers is None or isinstance(servers, dict))
    )

    verification_components = {
        "configIntegrity": 100.0 if config_shape else 0.0,
        "executionSafety": check_percent(security_checks, "No dangerous MCP commands"),
        "transportSecurity": check_percent(security_checks, "MCP remote transports are hardened"),
    }
    verification_components["score"] = weighted_score(
        verification_components,
        {
            "configIntegrity": 40.0,
            "executionSafety": 35.0,
            "transportSecurity": 25.0,
        },
    )

    metadata_components = {
        "serverNaming": 100.0 if has_named_surfaces else 0.0,
        "commandOrEndpoint": 100.0 if secure_remote_urls and local_commands_valid and has_named_surfaces else 0.0,
        "configShape": 100.0 if config_shape else 0.0,
    }
    metadata_components["score"] = weighted_score(
        metadata_components,
        {
            "serverNaming": 25.0,
            "commandOrEndpoint": 45.0,
            "configShape": 30.0,
        },
    )

    adapters = (
        TrustAdapterScore(
            adapter_id="verification",
            label="Verification Signals",
            weight=1.0,
            score=normalize_adapter_total(MCP_TRUST_SPEC.adapters[0].component_keys, verification_components),
            components=(
                _component("score", verification_components, "Weighted MCP verification subtotal."),
                _component(
                    "configIntegrity",
                    verification_components,
                    "The .mcp.json surface parses and matches the expected container shape.",
                ),
                _component(
                    "executionSafety",
                    verification_components,
                    "Local MCP commands avoid dangerous execution patterns.",
                ),
                _component(
                    "transportSecurity",
                    verification_components,
                    "Remote MCP transports stay on HTTPS when present.",
                ),
            ),
        ),
        TrustAdapterScore(
            adapter_id="metadata",
            label="Configuration Completeness",
            weight=0.75,
            score=normalize_adapter_total(MCP_TRUST_SPEC.adapters[1].component_keys, metadata_components),
            components=(
                _component("score", metadata_components, "Weighted MCP metadata subtotal."),
                _component(
                    "serverNaming",
                    metadata_components,
                    "MCP surfaces are explicitly named for operators and reviewers.",
                ),
                _component(
                    "commandOrEndpoint",
                    metadata_components,
                    "Every MCP surface declares a concrete local command or remote endpoint.",
                ),
                _component("configShape", metadata_components, "The top-level MCP configuration shape is valid."),
            ),
        ),
    )
    total = round_trust_score((adapters[0].score * 1.0 + adapters[1].score * 0.75) / 1.75)
    return TrustDomainScore(
        domain="mcp",
        label=MCP_TRUST_SPEC.label,
        spec_id=MCP_TRUST_SPEC.spec_id,
        spec_version=MCP_TRUST_SPEC.version,
        spec_path=MCP_TRUST_SPEC.spec_path,
        derived_from=MCP_TRUST_SPEC.derived_from,
        score=total,
        adapters=adapters,
    )


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

    verification_components = {
        "manifestIntegrity": weighted_score(
            {
                "exists": check_percent(manifest_checks, "plugin.json exists"),
                "json": check_percent(manifest_checks, "Valid JSON"),
                "required": check_percent(manifest_checks, "Required fields present"),
                "version": check_percent(manifest_checks, "Version follows semver"),
            },
            {"exists": 20.0, "json": 20.0, "required": 35.0, "version": 25.0},
        ),
        "interfaceIntegrity": weighted_score(
            {
                "metadata": check_percent(manifest_checks, "Interface metadata complete if declared"),
                "links": check_percent(manifest_checks, "Interface links and assets valid if declared"),
            },
            {"metadata": 60.0, "links": 40.0},
        ),
        "pathSafety": check_percent(manifest_checks, "Declared paths are safe"),
        "marketplaceAlignment": weighted_score(
            {
                "valid": check_percent(marketplace_checks, "marketplace.json valid"),
                "policy": check_percent(marketplace_checks, "Policy fields present"),
                "sources": check_percent(marketplace_checks, "Marketplace sources are safe"),
            },
            {"valid": 35.0, "policy": 35.0, "sources": 30.0},
        ),
    }
    verification_components["score"] = weighted_score(
        verification_components,
        {
            "manifestIntegrity": 35.0,
            "interfaceIntegrity": 25.0,
            "pathSafety": 20.0,
            "marketplaceAlignment": 20.0,
        },
    )

    security_components = {
        "disclosure": check_percent(security_checks, "SECURITY.md found"),
        "license": check_percent(security_checks, "LICENSE found"),
        "secretHygiene": check_percent(security_checks, "No hardcoded secrets"),
        "mcpSafety": weighted_score(
            {
                "commands": check_percent(security_checks, "No dangerous MCP commands"),
                "transport": check_percent(security_checks, "MCP remote transports are hardened"),
            },
            {"commands": 50.0, "transport": 50.0},
        ),
        "approvalHygiene": check_percent(security_checks, "No approval bypass defaults"),
    }
    security_components["score"] = weighted_score(
        security_components,
        {
            "disclosure": 15.0,
            "license": 10.0,
            "secretHygiene": 35.0,
            "mcpSafety": 20.0,
            "approvalHygiene": 20.0,
        },
    )

    metadata_components = {
        "documentation": check_percent(best_checks, "README.md found"),
        "manifestMetadata": check_percent(manifest_checks, "Recommended metadata present"),
        "discoverability": discoverability,
        "provenance": provenance,
    }
    metadata_components["score"] = weighted_score(
        metadata_components,
        {
            "documentation": 20.0,
            "manifestMetadata": 35.0,
            "discoverability": 20.0,
            "provenance": 25.0,
        },
    )

    operations_components = {
        "actionPinning": check_percent(operational_checks, "Third-party GitHub Actions pinned to SHAs"),
        "permissionScope": check_percent(operational_checks, "No write-all GitHub Actions permissions"),
        "untrustedCheckout": check_percent(operational_checks, "No privileged untrusted checkout patterns"),
        "updateAutomation": weighted_score(
            {
                "dependabot": check_percent(operational_checks, "Dependabot configured for automation surfaces"),
                "lockfiles": check_percent(operational_checks, "Dependency manifests have lockfiles"),
            },
            {"dependabot": 50.0, "lockfiles": 50.0},
        ),
    }
    operations_components["score"] = weighted_score(
        operations_components,
        {
            "actionPinning": 35.0,
            "permissionScope": 20.0,
            "untrustedCheckout": 25.0,
            "updateAutomation": 20.0,
        },
    )

    adapters = (
        TrustAdapterScore(
            adapter_id="verification",
            label="Manifest And Surface Integrity",
            weight=1.0,
            score=normalize_adapter_total(PLUGIN_TRUST_SPEC.adapters[0].component_keys, verification_components),
            components=(
                _component("score", verification_components, "Weighted plugin verification subtotal."),
                _component(
                    "manifestIntegrity",
                    verification_components,
                    "Manifest presence, syntax, required fields, and versioning stay intact.",
                ),
                _component(
                    "interfaceIntegrity",
                    verification_components,
                    "Interface metadata and assets are complete when declared.",
                ),
                _component(
                    "pathSafety",
                    verification_components,
                    "Declared plugin paths stay within the package root.",
                ),
                _component(
                    "marketplaceAlignment",
                    verification_components,
                    "Marketplace metadata remains structurally aligned when present.",
                ),
            ),
        ),
        TrustAdapterScore(
            adapter_id="security",
            label="Security Posture",
            weight=1.0,
            score=normalize_adapter_total(PLUGIN_TRUST_SPEC.adapters[1].component_keys, security_components),
            components=(
                _component("score", security_components, "Weighted plugin security subtotal."),
                _component(
                    "disclosure",
                    security_components,
                    "SECURITY.md is only one documented disclosure signal, not the whole trust score.",
                ),
                _component("license", security_components, "License clarity is present for downstream consumers."),
                _component(
                    "secretHygiene",
                    security_components,
                    "The source tree is free from hardcoded secret patterns.",
                ),
                _component(
                    "mcpSafety",
                    security_components,
                    "MCP surfaces avoid dangerous commands and insecure remotes.",
                ),
                _component(
                    "approvalHygiene",
                    security_components,
                    "The plugin avoids bypass-style approval defaults.",
                ),
            ),
        ),
        TrustAdapterScore(
            adapter_id="metadata",
            label="Metadata Completeness",
            weight=0.75,
            score=normalize_adapter_total(PLUGIN_TRUST_SPEC.adapters[2].component_keys, metadata_components),
            components=(
                _component("score", metadata_components, "Weighted plugin metadata subtotal."),
                _component(
                    "documentation",
                    metadata_components,
                    "README coverage is present for operators and contributors.",
                ),
                _component(
                    "manifestMetadata",
                    metadata_components,
                    "Recommended manifest metadata is complete.",
                ),
                _component(
                    "discoverability",
                    metadata_components,
                    "Category and keyword signals support marketplace discovery.",
                ),
                _component(
                    "provenance",
                    metadata_components,
                    "Author, homepage, and repository metadata establish provenance.",
                ),
            ),
        ),
        TrustAdapterScore(
            adapter_id="operations",
            label="Operational Hygiene",
            weight=0.75,
            score=normalize_adapter_total(PLUGIN_TRUST_SPEC.adapters[3].component_keys, operations_components),
            components=(
                _component("score", operations_components, "Weighted operational hygiene subtotal."),
                _component(
                    "actionPinning",
                    operations_components,
                    "Third-party actions are pinned to immutable revisions.",
                ),
                _component(
                    "permissionScope",
                    operations_components,
                    "Workflows avoid broad GitHub token scopes.",
                ),
                _component(
                    "untrustedCheckout",
                    operations_components,
                    "Privileged workflows do not check out untrusted pull request code.",
                ),
                _component(
                    "updateAutomation",
                    operations_components,
                    "Dependabot and lockfiles keep automation surfaces current.",
                ),
            ),
        ),
    )
    total = round_trust_score(
        (adapters[0].score + adapters[1].score + adapters[2].score * 0.75 + adapters[3].score * 0.75) / 3.5
    )
    return TrustDomainScore(
        domain="plugin",
        label=PLUGIN_TRUST_SPEC.label,
        spec_id=PLUGIN_TRUST_SPEC.spec_id,
        spec_version=PLUGIN_TRUST_SPEC.version,
        spec_path=PLUGIN_TRUST_SPEC.spec_path,
        derived_from=PLUGIN_TRUST_SPEC.derived_from,
        score=total,
        adapters=adapters,
    )
