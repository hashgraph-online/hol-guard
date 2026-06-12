from __future__ import annotations

import json
import re
from pathlib import Path

from .trust_helpers import build_adapter_score, build_domain_score
from .trust_models import TrustDomainScore
from .trust_specs import INSTRUCTION_TRUST_SPEC

_BOUNDARY_TERMS = (
    "must not",
    "never",
    "do not",
    "allowed",
    "forbidden",
    "required",
    "read-only",
    "write access",
    "network access",
)
_CAPABILITY_TERMS = (
    "shell",
    "command",
    "tool",
    "network",
    "write",
    "delete",
    "execute",
    "remote code",
)
_SECRET_TERMS = ("secret", "token", "password", "credential", "api key")
_SCOPE_TERMS = (
    "scope",
    "purpose",
    "overview",
    "requirements",
    "constraints",
    "responsibilities",
)
_GOVERNANCE_TERMS = (
    "review",
    "approval",
    "owner",
    "maintainer",
    "change control",
    "versioned",
    "reviewed by",
)
_PROVENANCE_TERMS = (
    "source",
    "repository",
    "repo",
    "commit",
    "homepage",
    "reference",
    "standard",
)
_OPERATIONAL_ROLES = frozenset(
    {
        "agents_md",
        "claude_md",
        "cursor_rules",
        "mcp_json",
        "policy_md",
        "security_md",
        "prompt_pack",
        "unknown_instruction",
    }
)


def build_instruction_domain(
    path: Path,
    *,
    role: str,
    item_kind: str,
) -> TrustDomainScore | None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None

    text = content.strip()
    if not text:
        return None

    lines = tuple(line.strip() for line in content.splitlines() if line.strip())
    text_lower = text.lower()
    headings = tuple(line for line in lines if line.startswith("#"))
    is_json = path.suffix.lower() == ".json"
    json_valid = _is_valid_json(text) if is_json else False

    structure_score = _structure_score(lines=lines, headings=headings, json_valid=json_valid)
    scope_terms = _matched_terms(text_lower, _SCOPE_TERMS)
    boundary_terms = _matched_terms(text_lower, _BOUNDARY_TERMS)
    capability_terms = _matched_terms(text_lower, _CAPABILITY_TERMS)
    secret_terms = _matched_terms(text_lower, _SECRET_TERMS)
    governance_terms = _matched_terms(text_lower, _GOVERNANCE_TERMS)
    provenance_terms = _matched_terms(text_lower, _PROVENANCE_TERMS)
    if "http://" in text_lower or "https://" in text_lower:
        provenance_terms = _append_unique(provenance_terms, "url")

    scope_score = _score_by_count(len(scope_terms), high=95.0, medium=75.0, low=55.0, zero=35.0)
    boundaries_score = _boundaries_score(
        boundary_terms=boundary_terms,
        capability_terms=capability_terms,
        secret_terms=secret_terms,
    )
    governance_score = _score_by_count(len(governance_terms), high=90.0, medium=70.0, low=55.0, zero=30.0)
    provenance_score = _score_by_count(len(provenance_terms), high=100.0, medium=75.0, low=55.0, zero=25.0)

    adapters = (
        build_adapter_score(
            INSTRUCTION_TRUST_SPEC.adapters[0],
            component_scores={"score": structure_score},
            rationales={
                "score": (
                    "Instruction content has enough structure to support deterministic local analysis."
                    if structure_score >= 80
                    else "Instruction content is sparse or weakly structured, which lowers baseline trust."
                )
            },
            evidence={"score": headings[:3] if headings else lines[:3]},
        ),
        build_adapter_score(
            INSTRUCTION_TRUST_SPEC.adapters[1],
            component_scores={"score": scope_score},
            rationales={
                "score": (
                    "Instruction content explicitly describes scope, purpose, or requirements."
                    if scope_terms
                    else "Instruction content does not clearly state scope or purpose."
                )
            },
            evidence={"score": tuple(scope_terms[:5])},
        ),
        build_adapter_score(
            INSTRUCTION_TRUST_SPEC.adapters[2],
            component_scores={"score": boundaries_score} if role in _OPERATIONAL_ROLES or item_kind == "prompt_pack" else None,
            rationales={
                "score": (
                    "Operational guidance includes capability boundaries and safety language."
                    if boundary_terms or capability_terms or secret_terms
                    else "Operational guidance lacks explicit capability boundaries or safety constraints."
                )
            },
            evidence={"score": tuple((boundary_terms + capability_terms + secret_terms)[:6])},
            applicable=role in _OPERATIONAL_ROLES or item_kind == "prompt_pack",
        ),
        build_adapter_score(
            INSTRUCTION_TRUST_SPEC.adapters[3],
            component_scores={"score": governance_score},
            rationales={
                "score": (
                    "Instruction content includes governance or change-control language."
                    if governance_terms
                    else "No review, ownership, or versioning language was found in the instruction content."
                )
            },
            evidence={"score": tuple(governance_terms[:5])},
        ),
        build_adapter_score(
            INSTRUCTION_TRUST_SPEC.adapters[4],
            component_scores={"score": provenance_score},
            rationales={
                "score": (
                    "Instruction content includes provenance or source references."
                    if provenance_terms
                    else "Instruction content does not reference an external source, repository, or standard."
                )
            },
            evidence={"score": tuple(provenance_terms[:5])},
        ),
    )

    return build_domain_score(domain="instructions", spec=INSTRUCTION_TRUST_SPEC, adapters=adapters)


def _is_valid_json(text: str) -> bool:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict)


def _matched_terms(text: str, terms: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for term in terms:
        if _term_matches(text, term):
            matches.append(term)
    return matches


def _term_matches(text: str, term: str) -> bool:
    if " " in term or "-" in term:
        return term in text
    pattern = rf"\b{re.escape(term)}\b"
    return re.search(pattern, text) is not None


def _append_unique(values: list[str], value: str) -> list[str]:
    if value in values:
        return values
    return [*values, value]


def _structure_score(
    *,
    lines: tuple[str, ...],
    headings: tuple[str, ...],
    json_valid: bool,
) -> float:
    if json_valid:
        return 95.0
    if len(lines) >= 6 and headings:
        return 92.0
    if len(lines) >= 4:
        return 78.0
    if len(lines) >= 2:
        return 60.0
    return 35.0


def _boundaries_score(
    *,
    boundary_terms: list[str],
    capability_terms: list[str],
    secret_terms: list[str],
) -> float:
    if boundary_terms and (capability_terms or secret_terms):
        return 95.0
    if boundary_terms:
        return 78.0
    if capability_terms or secret_terms:
        return 58.0
    return 35.0


def _score_by_count(
    count: int,
    *,
    high: float,
    medium: float,
    low: float,
    zero: float,
) -> float:
    if count >= 3:
        return high
    if count == 2:
        return medium
    if count == 1:
        return low
    return zero
