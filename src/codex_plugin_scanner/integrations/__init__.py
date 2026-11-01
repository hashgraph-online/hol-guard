"""Optional integrations for deeper plugin analysis."""

from .cisco_mcp_scanner import CiscoMcpScanSummary, run_cisco_mcp_scan
from .cisco_skill_scanner import CiscoIntegrationStatus, CiscoSkillScanSummary, run_cisco_skill_scan
from .gemma_verifier import (
    DEFAULT_GEMMA_MODEL,
    GEMMA_31B_MODEL,
    SUPPORTED_GEMMA_MODELS,
    GemmaFindingVerification,
    GemmaVerificationSummary,
    GemmaVerificationVerdict,
    is_gemma_available,
    verify_check_results_with_gemma,
    verify_finding_with_gemma,
)

__all__ = [
    "CiscoIntegrationStatus",
    "CiscoMcpScanSummary",
    "CiscoSkillScanSummary",
    "DEFAULT_GEMMA_MODEL",
    "GEMMA_31B_MODEL",
    "GemmaFindingVerification",
    "GemmaVerificationSummary",
    "GemmaVerificationVerdict",
    "SUPPORTED_GEMMA_MODELS",
    "is_gemma_available",
    "run_cisco_mcp_scan",
    "run_cisco_skill_scan",
    "verify_check_results_with_gemma",
    "verify_finding_with_gemma",
]
