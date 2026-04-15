"""Built-in rule registry for stable rule IDs and metadata."""

from __future__ import annotations

from codex_plugin_scanner.models import Severity
from codex_plugin_scanner.rules.specs import RuleSpec

CATEGORY_WEIGHTS: dict[str, int] = {
    "manifest": 31,
    "security": 16,
    "operational-security": 18,
    "best-practices": 15,
    "marketplace": 11,
    "skill-security": 9,
    "code-quality": 10,
}

_DOC_ROOT = "https://github.com/hashgraph-online/ai-plugin-scanner/blob/main/docs/rules"


def _rule(
    rule_id: str,
    category: str,
    severity: Severity,
    weight: int,
    docs_slug: str,
    *,
    fixable: bool = False,
) -> RuleSpec:
    title = rule_id.replace("_", " ").replace("-", " ").title()
    return RuleSpec(
        rule_id=rule_id,
        category=category,
        default_severity=severity,
        weight=weight,
        docs_slug=docs_slug,
        description=f"{title} was detected.",
        remediation=f"Review and remediate {title.lower()}.",
        docs_url=f"{_DOC_ROOT}/{docs_slug}.md",
        fixable=fixable,
    )


RULE_SPECS: tuple[RuleSpec, ...] = (
    _rule("PLUGIN_JSON_MISSING", "manifest", Severity.HIGH, 5, "plugin-json-missing"),
    _rule("PLUGIN_JSON_INVALID", "manifest", Severity.HIGH, 5, "plugin-json-invalid"),
    _rule("README_MISSING", "best-practices", Severity.LOW, 3, "readme-missing", fixable=True),
    _rule("SKILLS_DIR_MISSING", "best-practices", Severity.MEDIUM, 4, "skills-dir-missing"),
    _rule("SKILL_FRONTMATTER_INVALID", "best-practices", Severity.MEDIUM, 4, "skill-frontmatter-invalid"),
    _rule("ENV_FILE_COMMITTED", "best-practices", Severity.HIGH, 5, "env-file-committed"),
    _rule("CODEXIGNORE_MISSING", "best-practices", Severity.LOW, 3, "codexignore-missing", fixable=True),
    _rule("SECURITY_MD_MISSING", "security", Severity.MEDIUM, 3, "security-md-missing", fixable=True),
    _rule("LICENSE_MISSING", "security", Severity.MEDIUM, 3, "license-missing", fixable=True),
    _rule("HARDCODED_SECRET", "security", Severity.CRITICAL, 7, "hardcoded-secret"),
    _rule("DANGEROUS_MCP_COMMAND", "security", Severity.HIGH, 4, "dangerous-mcp-command"),
    _rule("MCP_CONFIG_INVALID_JSON", "security", Severity.HIGH, 4, "mcp-config-invalid-json"),
    _rule("MCP_REMOTE_URL_INSECURE", "security", Severity.HIGH, 4, "mcp-remote-url-insecure"),
    _rule("RISKY_APPROVAL_DEFAULT", "security", Severity.MEDIUM, 2, "risky-approval-default"),
    _rule("MARKETPLACE_JSON_INVALID", "marketplace", Severity.HIGH, 5, "marketplace-json-invalid"),
    _rule("MARKETPLACE_NAME_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-name-missing"),
    _rule("MARKETPLACE_PLUGINS_MISSING", "marketplace", Severity.HIGH, 5, "marketplace-plugins-missing"),
    _rule("MARKETPLACE_SOURCE_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-source-missing"),
    _rule("MARKETPLACE_POLICY_MISSING", "marketplace", Severity.MEDIUM, 5, "marketplace-policy-missing"),
    _rule("MARKETPLACE_POLICY_FIELDS_MISSING", "marketplace", Severity.MEDIUM, 4, "marketplace-policy-fields-missing"),
    _rule("MARKETPLACE_UNSAFE_SOURCE", "marketplace", Severity.HIGH, 3, "marketplace-unsafe-source"),
    _rule("DANGEROUS_DYNAMIC_EXECUTION", "code-quality", Severity.HIGH, 5, "dangerous-dynamic-execution"),
    _rule("SHELL_INJECTION_PATTERN", "code-quality", Severity.HIGH, 5, "shell-injection-pattern"),
    _rule("GITHUB_ACTION_UNPINNED", "operational-security", Severity.HIGH, 5, "github-action-unpinned"),
    _rule("GITHUB_ACTIONS_WRITE_ALL", "operational-security", Severity.HIGH, 5, "github-actions-write-all"),
    _rule(
        "GITHUB_ACTIONS_UNTRUSTED_CHECKOUT",
        "operational-security",
        Severity.HIGH,
        4,
        "github-actions-untrusted-checkout",
    ),
    _rule("DEPENDABOT_MISSING", "operational-security", Severity.LOW, 2, "dependabot-missing"),
    _rule(
        "DEPENDABOT_GITHUB_ACTIONS_MISSING",
        "operational-security",
        Severity.LOW,
        2,
        "dependabot-github-actions-missing",
    ),
    _rule("DEPENDENCY_LOCKFILE_MISSING", "operational-security", Severity.MEDIUM, 2, "dependency-lockfile-missing"),
    _rule("CISCO-SCANNER-UNAVAILABLE", "skill-security", Severity.LOW, 3, "cisco-scanner-unavailable"),
)

_RULES_BY_ID: dict[str, RuleSpec] = {rule.rule_id: rule for rule in RULE_SPECS}


def list_rule_specs() -> tuple[RuleSpec, ...]:
    return RULE_SPECS


def get_rule_spec(rule_id: str) -> RuleSpec | None:
    return _RULES_BY_ID.get(rule_id)


def has_rule_spec(rule_id: str) -> bool:
    return rule_id in _RULES_BY_ID
