"""Compatibility facade for trust domain scoring."""

from __future__ import annotations

from pathlib import Path

from .checks.skill_security import SkillSecurityContext
from .models import CategoryResult
from .trust_mcp_scoring import build_mcp_domain
from .trust_models import TrustDomainScore
from .trust_plugin_scoring import build_plugin_domain
from .trust_skill_scoring import build_skill_domain

__all__ = [
    "CategoryResult",
    "Path",
    "SkillSecurityContext",
    "TrustDomainScore",
    "build_mcp_domain",
    "build_plugin_domain",
    "build_skill_domain",
]
