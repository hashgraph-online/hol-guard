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
    "package_unknown",
    "package_lockfile_drift",
    "package_direct_source",
    "package_custom_registry",
    "package_install",
    "low_trust_artifact",
    "runtime_known_vulnerable",
    "git_hook_bypass",
    "git_stage_all",
}
# The user's own git rules. Every preset leaves them at allow; a user who
# wants Guard to hold them sets them one by one.
USER_RULE_RISK_ACTION_KEYS = frozenset({"git_hook_bypass", "git_stage_all"})
