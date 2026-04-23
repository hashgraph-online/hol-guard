"""HCS-28-aligned skill trust scoring."""

from __future__ import annotations

from pathlib import Path

from .checks.manifest import load_manifest
from .checks.skill_security import SkillSecurityContext
from .integrations.cisco_skill_scanner import CiscoIntegrationStatus
from .path_support import is_safe_relative_path, iter_safe_matching_files
from .trust_helpers import (
    build_adapter_score,
    build_domain_score,
    has_required_skill_frontmatter,
    hcs_28_upvote_score,
    parse_skill_frontmatter,
    round_trust_score,
    url_host,
)
from .trust_models import TrustDomainScore
from .trust_specs import SKILL_TRUST_SPEC


def _skill_files(plugin_dir: Path, manifest: dict[str, object] | None) -> tuple[Path, ...]:
    if manifest is None:
        return ()
    skills_root = manifest.get("skills")
    if not isinstance(skills_root, str) or not skills_root.strip():
        return ()
    if not is_safe_relative_path(plugin_dir, skills_root):
        return ()
    skills_dir = plugin_dir / skills_root
    if not skills_dir.is_dir():
        return ()
    return iter_safe_matching_files(plugin_dir, skills_dir, "**/SKILL.md")


def _normalized_skill_metadata(
    manifest: dict[str, object] | None,
    frontmatters: tuple[dict[str, object], ...],
) -> dict[str, object]:
    descriptions = [
        str(payload.get("description", "")).strip() for payload in frontmatters if payload.get("description")
    ]
    tags: set[str] = set()
    languages: set[str] = set()
    for payload in frontmatters:
        tag_value = payload.get("tags")
        if isinstance(tag_value, list):
            tags.update(str(item).strip() for item in tag_value if str(item).strip())
        elif isinstance(tag_value, str):
            tags.update(item.strip() for item in tag_value.split(",") if item.strip())
        language_value = payload.get("languages")
        if isinstance(language_value, list):
            languages.update(str(item).strip().lower() for item in language_value if str(item).strip())
        elif isinstance(language_value, str):
            languages.update(item.strip().lower() for item in language_value.split(",") if item.strip())
    repository = next(
        (
            str(payload.get("repo")).strip()
            for payload in frontmatters
            if isinstance(payload.get("repo"), str) and str(payload.get("repo")).strip()
        ),
        "",
    )
    homepage = next(
        (
            str(payload.get("homepage")).strip()
            for payload in frontmatters
            if isinstance(payload.get("homepage"), str) and str(payload.get("homepage")).strip()
        ),
        "",
    )
    commit = next(
        (
            str(payload.get("commit")).strip()
            for payload in frontmatters
            if isinstance(payload.get("commit"), str) and str(payload.get("commit")).strip()
        ),
        "",
    )
    if not repository and isinstance(manifest, dict) and isinstance(manifest.get("repository"), str):
        repository = str(manifest.get("repository")).strip()
    if not homepage and isinstance(manifest, dict) and isinstance(manifest.get("homepage"), str):
        homepage = str(manifest.get("homepage")).strip()
    if not commit and isinstance(manifest, dict) and isinstance(manifest.get("commit"), str):
        commit = str(manifest.get("commit")).strip()
    return {
        "descriptions": tuple(descriptions),
        "repository": repository,
        "homepage": homepage,
        "commit": commit,
        "tags": tuple(sorted(tags)),
        "languages": tuple(sorted(languages)),
    }


def _cisco_score(context: SkillSecurityContext) -> tuple[dict[str, float] | None, dict[str, str]]:
    if context.summary is None:
        return None, {
            "score": (
                "No Cisco scan result is available in read mode, so HCS-28 treats the universal safety adapter as 0."
            )
        }
    if context.summary.status != CiscoIntegrationStatus.ENABLED:
        return None, {"score": context.summary.message}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in context.summary.findings:
        severity = finding.severity.value
        if severity in counts:
            counts[severity] += 1
    raw_score = 100 - (30 * counts["critical"] + 12 * counts["high"] + 4 * counts["medium"] + counts["low"])
    return {"score": round_trust_score(raw_score)}, {"score": context.summary.message}


def build_skill_domain(
    plugin_dir: Path,
    context: SkillSecurityContext,
) -> TrustDomainScore | None:
    manifest = load_manifest(plugin_dir)
    skill_files = _skill_files(plugin_dir, manifest)
    if not skill_files:
        return None

    frontmatters = tuple(payload for payload in (parse_skill_frontmatter(path) for path in skill_files) if payload)
    normalized = _normalized_skill_metadata(manifest, frontmatters)
    has_author = (
        isinstance(manifest, dict)
        and isinstance(manifest.get("author"), dict)
        and isinstance(manifest["author"].get("name"), str)
        and bool(manifest["author"].get("name"))
    )
    all_frontmatter_valid = len(frontmatters) == len(skill_files) and all(
        has_required_skill_frontmatter(payload) for payload in frontmatters
    )
    repo_host = url_host(str(normalized["repository"]) or None)
    home_host = url_host(str(normalized["homepage"]) or None)
    description_length = (
        sum(len(description) for description in normalized["descriptions"]) / len(normalized["descriptions"])
        if normalized["descriptions"]
        else 0
    )
    tag_count = len(normalized["tags"])
    language_count = len(normalized["languages"])

    adapter_inputs: dict[str, tuple[dict[str, float] | None, dict[str, str], bool]] = {
        "verification.review-status": (
            {"score": 100.0} if isinstance(manifest, dict) and manifest.get("verified") is True else None,
            {
                "score": (
                    "The bundled skill package declares explicit version-scoped verification."
                    if isinstance(manifest, dict) and manifest.get("verified") is True
                    else (
                        "No explicit version-scoped verification record is present locally, "
                        "so the HCS-28 review-status adapter remains 0."
                    )
                )
            },
            True,
        ),
        "verification.publisher-bound": (
            {"score": 100.0} if has_author else None,
            {
                "score": (
                    "Local bundled-skill normalization maps publisher binding to the declared plugin author metadata."
                    if has_author
                    else "No plugin author metadata is present, so the local publisher-bound signal remains 0."
                )
            },
            True,
        ),
        "verification.repo-commit-integrity": (
            {"score": 100.0} if normalized["repository"] and normalized["commit"] else None,
            {
                "score": (
                    "The bundled skill metadata declares both a repository URL and an immutable commit reference."
                    if normalized["repository"] and normalized["commit"]
                    else (
                        "Repo-commit integrity requires both a repository URL and "
                        "a commit reference in local bundled-skill metadata."
                    )
                )
            },
            True,
        ),
        "verification.manifest-integrity": (
            {"score": 100.0} if all_frontmatter_valid else None,
            {
                "score": (
                    "Every bundled SKILL.md parsed successfully and includes the required frontmatter fields."
                    if all_frontmatter_valid
                    else "At least one bundled SKILL.md is missing required frontmatter or failed to parse."
                )
            },
            True,
        ),
        "verification.domain-proof": (
            {"score": 100.0} if repo_host and repo_host == home_host else None,
            {
                "score": (
                    "Homepage and repository hosts align, satisfying the local domain-proof mapping."
                    if repo_host and repo_host == home_host
                    else "Local domain-proof requires aligned homepage and repository hosts."
                )
            },
            True,
        ),
        "metadata.links": (
            {"score": 100.0}
            if normalized["homepage"] and normalized["repository"]
            else {"score": 60.0}
            if normalized["homepage"] or normalized["repository"]
            else None,
            {"score": "HCS-28 metadata.links awards 100 for homepage+repo, 60 for either one, and 0 otherwise."},
            True,
        ),
        "metadata.description": (
            {"score": 100.0}
            if description_length >= 160
            else {"score": 85.0}
            if description_length >= 80
            else {"score": 65.0}
            if description_length >= 30
            else {"score": 40.0}
            if description_length >= 10
            else None,
            {"score": "HCS-28 metadata.description uses the published description-length thresholds."},
            True,
        ),
        "metadata.taxonomy": (
            {
                "score": (
                    100.0
                    if tag_count >= 3 and language_count >= 1
                    else 85.0
                    if tag_count >= 1 and language_count >= 1
                    else 70.0
                    if tag_count >= 3
                    else 55.0
                    if tag_count >= 1
                    else 35.0
                    if language_count >= 1
                    else 0.0
                )
            },
            {"score": "HCS-28 metadata.taxonomy follows the published tag-count and language-count matrix."},
            True,
        ),
        "metadata.provenance": (
            {"score": 100.0}
            if normalized["repository"] and normalized["commit"]
            else {"score": 70.0}
            if normalized["repository"]
            else {"score": 40.0}
            if normalized["commit"]
            else None,
            {
                "score": (
                    "HCS-28 metadata.provenance awards 100 for repo+commit, 70 for repo only, and 40 for commit only."
                )
            },
            True,
        ),
        "upvotes": (
            {"score": hcs_28_upvote_score(int(manifest.get("upvotes", 0)))}
            if isinstance(manifest, dict) and isinstance(manifest.get("upvotes"), int)
            else None,
            {
                "score": (
                    "The HCS-28 upvotes adapter is conditional and only contributes "
                    "when a local upvote count is available."
                )
            },
            True,
        ),
        "safety.cisco-scan": (*_cisco_score(context), True),
        "repository.health": (
            None,
            {
                "score": (
                    "Repository health is conditional in HCS-28 and is omitted in local "
                    "read mode unless a persisted external score exists."
                )
            },
            bool(normalized["repository"]),
        ),
    }

    spec_by_id = {adapter.adapter_id: adapter for adapter in SKILL_TRUST_SPEC.adapters}
    adapters = tuple(
        build_adapter_score(
            spec_by_id[adapter_id],
            component_scores=component_scores,
            rationales=rationales,
            applicable=applicable,
        )
        for adapter_id, (component_scores, rationales, applicable) in adapter_inputs.items()
    )
    return build_domain_score(domain="skills", spec=SKILL_TRUST_SPEC, adapters=adapters)
