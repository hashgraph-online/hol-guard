"""Built-in rule registry for stable rule IDs and metadata."""

from __future__ import annotations

from codex_plugin_scanner.models import Severity
from codex_plugin_scanner.rules.specs import RuleSpec

# Preserved category weighting from the current scanner summary scoring model.
CATEGORY_WEIGHTS: dict[str, int] = {
    "manifest": 31,
    "security": 16,
    "operational-security": 18,
    "best-practices": 15,
    "marketplace": 11,
    "skill-security": 9,
    "code-quality": 10,
}

RULE_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec("README_MISSING", "best-practices", Severity.LOW, 3, "readme-missing", fixable=True),
    RuleSpec("SKILLS_DIR_MISSING", "best-practices", Severity.MEDIUM, 4, "skills-dir-missing"),
    RuleSpec("SKILL_FRONTMATTER_INVALID", "best-practices", Severity.MEDIUM, 4, "skill-frontmatter-invalid"),
    RuleSpec("ENV_FILE_COMMITTED", "best-practices", Severity.HIGH, 5, "env-file-committed"),
    RuleSpec("CODEXIGNORE_MISSING", "best-practices", Severity.LOW, 3, "codexignore-missing", fixable=True),
    RuleSpec("SECURITY_MD_MISSING", "security", Severity.MEDIUM, 3, "security-md-missing", fixable=True),
    RuleSpec("LICENSE_MISSING", "security", Severity.MEDIUM, 3, "license-missing", fixable=True),
    RuleSpec("HARDCODED_SECRET", "security", Severity.CRITICAL, 7, "hardcoded-secret"),
    RuleSpec("DANGEROUS_MCP_COMMAND", "security", Severity.HIGH, 4, "dangerous-mcp-command"),
    RuleSpec("MCP_CONFIG_INVALID_JSON", "security", Severity.HIGH, 4, "mcp-config-invalid-json"),
    RuleSpec("MCP_REMOTE_URL_INSECURE", "security", Severity.HIGH, 4, "mcp-remote-url-insecure"),
    RuleSpec("RISKY_APPROVAL_DEFAULT", "security", Severity.MEDIUM, 2, "risky-approval-default"),
    RuleSpec("MARKETPLACE_JSON_INVALID", "marketplace", Severity.HIGH, 5, "marketplace-json-invalid"),
    RuleSpec("MARKETPLACE_NAME_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-name-missing"),
    RuleSpec("MARKETPLACE_PLUGINS_MISSING", "marketplace", Severity.HIGH, 5, "marketplace-plugins-missing"),
    RuleSpec("MARKETPLACE_SOURCE_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-source-missing"),
    RuleSpec("MARKETPLACE_POLICY_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-policy-missing"),
    RuleSpec("MARKETPLACE_POLICY_FIELDS_MISSING", "marketplace", Severity.MEDIUM, 4, "marketplace-policy-fields-missing"),
    RuleSpec("MARKETPLACE_UNSAFE_SOURCE", "marketplace", Severity.HIGH, 3, "marketplace-unsafe-source"),
    RuleSpec("DANGEROUS_DYNAMIC_EXECUTION", "code-quality", Severity.HIGH, 5, "dangerous-dynamic-execution"),
    RuleSpec("SHELL_INJECTION_PATTERN", "code-quality", Severity.HIGH, 5, "shell-injection-pattern"),
    RuleSpec("GITHUB_ACTION_UNPINNED", "operational-security", Severity.HIGH, 5, "github-action-unpinned"),
    RuleSpec("GITHUB_ACTIONS_WRITE_ALL", "operational-security", Severity.HIGH, 5, "github-actions-write-all"),
    RuleSpec(
        "GITHUB_ACTIONS_UNTRUSTED_CHECKOUT",
        "operational-security",
        Severity.HIGH,
        4,
        "github-actions-untrusted-checkout",
    ),
    RuleSpec("DEPENDABOT_MISSING", "operational-security", Severity.LOW, 2, "dependabot-missing"),
    RuleSpec(
        "DEPENDABOT_GITHUB_ACTIONS_MISSING",
        "operational-security",
        Severity.LOW,
        2,
        "dependabot-github-actions-missing",
    ),
    RuleSpec("DEPENDENCY_LOCKFILE_MISSING", "operational-security", Severity.MEDIUM, 2, "dependency-lockfile-missing"),
    RuleSpec("CISCO-SCANNER-UNAVAILABLE", "skill-security", Severity.LOW, 3, "cisco-scanner-unavailable"),
)

_RULES_BY_ID: dict[str, RuleSpec] = {rule.rule_id: rule for rule in RULE_SPECS}


def list_rule_specs() -> tuple[RuleSpec, ...]:
    """Return all known rule specifications."""

    return RULE_SPECS


def get_rule_spec(rule_id: str) -> RuleSpec | None:
    """Resolve a rule spec by stable rule ID."""

    return _RULES_BY_ID.get(rule_id)


def has_rule_spec(rule_id: str) -> bool:
    """Check whether a rule ID is registered."""

    return rule_id in _RULES_BY_ID
