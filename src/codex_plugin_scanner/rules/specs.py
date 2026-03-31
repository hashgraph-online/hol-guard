"""Rule specification models used by lint and scan policy layers."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.models import Severity


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static metadata for a scanner rule."""

    rule_id: str
    category: str
    default_severity: Severity
    weight: int
    docs_slug: str
    description: str
    remediation: str
    docs_url: str
    fixable: bool = False
    profiles: tuple[str, ...] = ("default", "public-marketplace", "strict-security")


ALL_PROFILES: tuple[str, ...] = ("default", "public-marketplace", "strict-security")
