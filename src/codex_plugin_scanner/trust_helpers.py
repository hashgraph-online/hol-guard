"""Shared helpers for trust scoring."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from math import exp
from pathlib import Path
from urllib.parse import urlparse

from .models import CategoryResult
from .trust_models import (
    TrustAdapterScore,
    TrustAdapterSpec,
    TrustComponentScore,
    TrustDomainScore,
    TrustSpecDefinition,
)


@dataclass(frozen=True)
class McpPayloadState:
    payload: dict[str, object]
    parse_valid: bool


def round_trust_score(value: float) -> float:
    bounded = min(100.0, max(0.0, value))
    return float(Decimal(str(bounded)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def weighted_score(components: dict[str, float], weights: dict[str, float]) -> float:
    total_weight = sum(weight for weight in weights.values() if weight > 0)
    if total_weight <= 0:
        return 0.0
    return round_trust_score(sum(components[key] * weights[key] for key in weights) / total_weight)


def normalize_report_total(scores: tuple[float, ...]) -> float:
    if not scores:
        return 0.0
    return round_trust_score(sum(scores) / len(scores))


def build_adapter_score(
    spec: TrustAdapterSpec,
    *,
    component_scores: dict[str, float] | None,
    rationales: dict[str, str],
    evidence: dict[str, tuple[str, ...]] | None = None,
    applicable: bool = True,
) -> TrustAdapterScore:
    evidence_map = evidence or {}
    emitted = bool(component_scores)
    included_in_denominator = applicable and (emitted or spec.contribution_mode in {"universal", "scoped"})
    if not applicable:
        return TrustAdapterScore(
            adapter_id=spec.adapter_id,
            label=spec.label,
            weight=spec.weight,
            contribution_mode=spec.contribution_mode,
            applicable=False,
            emitted=False,
            included_in_denominator=False,
            score=0.0,
            components=(),
        )
    normalized_scores = component_scores or {}
    components = tuple(
        TrustComponentScore(
            key=key,
            score=round_trust_score(normalized_scores.get(key, 0.0)),
            rationale=rationales.get(key, "No score rationale recorded."),
            evidence=evidence_map.get(key, ()),
        )
        for key in spec.component_keys
    )
    score = round_trust_score(sum(component.score for component in components) / len(components)) if components else 0.0
    return TrustAdapterScore(
        adapter_id=spec.adapter_id,
        label=spec.label,
        weight=spec.weight,
        contribution_mode=spec.contribution_mode,
        applicable=True,
        emitted=emitted,
        included_in_denominator=included_in_denominator,
        score=score,
        components=components,
    )


def build_domain_score(
    *,
    domain: str,
    spec: TrustSpecDefinition,
    adapters: tuple[TrustAdapterScore, ...],
) -> TrustDomainScore:
    denominator = sum(adapter.weight for adapter in adapters if adapter.included_in_denominator)
    numerator = sum(adapter.weight * adapter.score for adapter in adapters if adapter.included_in_denominator)
    total = round_trust_score(numerator / denominator) if denominator > 0 else 0.0
    return TrustDomainScore(
        domain=domain,
        label=spec.label,
        spec_id=spec.spec_id,
        spec_version=spec.version,
        spec_path=spec.spec_path,
        derived_from=spec.derived_from,
        profile_id=spec.profile_id,
        profile_version=spec.profile_version,
        score=total,
        adapters=adapters,
    )


def category_checks(categories: tuple[CategoryResult, ...], name: str) -> dict[str, object]:
    for category in categories:
        if category.name == name:
            return {check.name: check for check in category.checks}
    return {}


def check_percent(checks: dict[str, object], name: str) -> float:
    check = checks.get(name)
    if check is None:
        return 0.0
    max_points = getattr(check, "max_points", 0)
    if max_points <= 0:
        return 0.0
    return round_trust_score(getattr(check, "points", 0) * 100 / max_points)


def is_https_url(value: str | None) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def url_host(value: str | None) -> str:
    if not value:
        return ""
    return (urlparse(value).hostname or "").lower()


def parse_skill_frontmatter(skill_file: Path) -> dict[str, object] | None:
    try:
        content = skill_file.read_text(encoding="utf-8")
    except OSError:
        return None
    if not content.startswith("---"):
        return None
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None
    payload: dict[str, object] = {}
    current_list_key: str | None = None
    for raw_line in parts[1].splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- ") and current_list_key:
            existing = payload.setdefault(current_list_key, [])
            if isinstance(existing, list):
                existing.append(stripped[2:].strip())
            continue
        current_list_key = None
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        normalized_key = key.strip()
        value = raw_value.strip()
        if value.startswith("[") and value.endswith("]"):
            payload[normalized_key] = [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
            continue
        if value:
            payload[normalized_key] = value.strip("'\"")
            continue
        payload[normalized_key] = []
        current_list_key = normalized_key
    return payload


def has_required_skill_frontmatter(payload: dict[str, object]) -> bool:
    for field in ("name", "description"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return False
    return True


def load_mcp_payload(plugin_dir: Path) -> McpPayloadState | None:
    path = plugin_dir / ".mcp.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return McpPayloadState(payload={}, parse_valid=False)
    if not isinstance(payload, dict):
        return McpPayloadState(payload={}, parse_valid=False)
    return McpPayloadState(payload=payload, parse_valid=True)


def hcs_28_upvote_score(upvotes: int) -> float:
    return round_trust_score(round(100 * (1 - exp(-max(0, upvotes) / 20))))
