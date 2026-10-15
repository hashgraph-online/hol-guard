"""Guard settings vocabularies that stay importable without loading Guard config."""

from __future__ import annotations

from .models import GUARD_ACTION_VALUES

VALID_GUARD_ACTIONS = frozenset(GUARD_ACTION_VALUES)
VALID_SECURITY_LEVELS = {"relaxed", "gentle", "balanced", "strict", "paranoid", "custom"}
VALID_RISK_ACTION_KEYS = {
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
}
