"""Marketplace validation checks (15 points)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from ..models import CheckResult, Finding, Severity


def _is_safe_source(plugin_dir: Path, source: str) -> bool:
    if not source.startswith("./"):
        return False
    if urlparse(source).scheme:
        return False
    candidate = Path(source)
    if candidate.is_absolute():
        return False
    resolved = (plugin_dir / candidate).resolve()
    try:
        resolved.relative_to(plugin_dir.resolve())
    except ValueError:
        return False
    return True


def check_marketplace_json(plugin_dir: Path) -> CheckResult:
    mp = plugin_dir / "marketplace.json"
    if not mp.exists():
        return CheckResult(
            name="marketplace.json valid",
            passed=True,
            points=0,
            max_points=0,
            message="No marketplace.json found, check not applicable",
            applicable=False,
        )
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message="marketplace.json is not valid JSON",
            findings=(
                Finding(
                    rule_id="MARKETPLACE_JSON_INVALID",
                    severity=Severity.MEDIUM,
                    category="marketplace",
                    title="marketplace.json is invalid JSON",
                    description="The marketplace manifest could not be parsed.",
                    remediation="Fix the JSON syntax in marketplace.json.",
                    file_path="marketplace.json",
                ),
            ),
        )

    if not data.get("name") or not isinstance(data.get("name"), str):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message='marketplace.json missing "name" field',
            findings=(
                Finding(
                    rule_id="MARKETPLACE_NAME_MISSING",
                    severity=Severity.LOW,
                    category="marketplace",
                    title='marketplace.json is missing "name"',
                    description='The marketplace manifest must define a "name" field.',
                    remediation='Add a string "name" field to marketplace.json.',
                    file_path="marketplace.json",
                ),
            ),
        )
    if not isinstance(data.get("plugins"), list):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message='marketplace.json missing "plugins" array',
            findings=(
                Finding(
                    rule_id="MARKETPLACE_PLUGINS_MISSING",
                    severity=Severity.MEDIUM,
                    category="marketplace",
                    title='marketplace.json is missing the "plugins" array',
                    description='The marketplace manifest must declare its plugin list in a "plugins" array.',
                    remediation='Add a "plugins" array to marketplace.json.',
                    file_path="marketplace.json",
                ),
            ),
        )
    for i, plugin in enumerate(data["plugins"]):
        if not isinstance(plugin, dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f"marketplace.json plugin[{i}] must be an object",
                findings=(
                    Finding(
                        rule_id="MARKETPLACE_ENTRY_INVALID",
                        severity=Severity.MEDIUM,
                        category="marketplace",
                        title="Marketplace plugin entry is invalid",
                        description=f"plugin[{i}] in marketplace.json must be an object.",
                        remediation="Ensure all entries in the plugins array are objects.",
                        file_path="marketplace.json",
                    ),
                ),
            )
        source = plugin.get("source")
        if not isinstance(source, dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'marketplace.json plugin[{i}] missing "source" object',
                findings=(
                    Finding(
                        rule_id="MARKETPLACE_SOURCE_MISSING",
                        severity=Severity.MEDIUM,
                        category="marketplace",
                        title="Marketplace plugin source is missing",
                        description=f'plugin[{i}] in marketplace.json is missing a "source" object.',
                        remediation='Add a "source" object with "source" and "path" fields for each marketplace entry.',
                        file_path="marketplace.json",
                    ),
                ),
            )
        if source.get("source") != "local" or not isinstance(source.get("path"), str):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'marketplace.json plugin[{i}] must declare source.source="local" and source.path',
                findings=(
                    Finding(
                        rule_id="MARKETPLACE_SOURCE_INVALID",
                        severity=Severity.MEDIUM,
                        category="marketplace",
                        title="Marketplace source shape is invalid",
                        description=(
                            f"plugin[{i}] in marketplace.json must declare "
                            '"source": {"source": "local", "path": "./plugins/..."}'
                        ),
                        remediation="Use the official repo marketplace shape with a local source object.",
                        file_path="marketplace.json",
                    ),
                ),
            )
        if not plugin.get("policy") or not isinstance(plugin.get("policy"), dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'marketplace.json plugin[{i}] missing "policy" field',
                findings=(
                    Finding(
                        rule_id="MARKETPLACE_POLICY_MISSING",
                        severity=Severity.MEDIUM,
                        category="marketplace",
                        title="Marketplace policy is missing",
                        description=f'plugin[{i}] in marketplace.json is missing a "policy" object.',
                        remediation='Add a "policy" object for each marketplace entry.',
                        file_path="marketplace.json",
                    ),
                ),
            )
    return CheckResult(
        name="marketplace.json valid", passed=True, points=5, max_points=5, message="marketplace.json is valid"
    )


def check_policy_fields(plugin_dir: Path) -> CheckResult:
    mp = plugin_dir / "marketplace.json"
    if not mp.exists():
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=0,
            max_points=0,
            message="No marketplace.json found, check not applicable",
            applicable=False,
        )
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=5,
            max_points=5,
            message="Cannot parse marketplace.json, skipping check",
        )

    plugins = data.get("plugins", [])
    if not plugins:
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=5,
            max_points=5,
            message="No plugins in marketplace.json, nothing to check",
        )

    issues: list[str] = []
    for i, plugin in enumerate(plugins):
        if not isinstance(plugin, dict):
            issues.append(f"plugin[{i}]: not an object")
            continue
        policy = plugin.get("policy") or {}
        if not policy.get("installation"):
            issues.append(f"plugin[{i}]: missing policy.installation")
        if not policy.get("authentication"):
            issues.append(f"plugin[{i}]: missing policy.authentication")
        if not plugin.get("category"):
            issues.append(f"plugin[{i}]: missing category")

    if not issues:
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=5,
            max_points=5,
            message="All plugins have required policy fields",
        )
    return CheckResult(
        name="Policy fields present",
        passed=False,
        points=0,
        max_points=5,
        message=f"Policy issues: {', '.join(issues[:3])}",
        findings=tuple(
            Finding(
                rule_id="MARKETPLACE_POLICY_FIELDS_MISSING",
                severity=Severity.MEDIUM,
                category="marketplace",
                title="Marketplace policy fields are incomplete",
                description=issue,
                remediation="Add policy.installation, policy.authentication, and category for each marketplace entry.",
                file_path="marketplace.json",
            )
            for issue in issues
        ),
    )


def check_sources_safe(plugin_dir: Path) -> CheckResult:
    mp = plugin_dir / "marketplace.json"
    if not mp.exists():
        return CheckResult(
            name="Marketplace sources are safe",
            passed=True,
            points=0,
            max_points=0,
            message="No marketplace.json found, check not applicable",
            applicable=False,
        )

    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CheckResult(
            name="Marketplace sources are safe",
            passed=True,
            points=0,
            max_points=0,
            message="Cannot parse marketplace.json, skipping source safety checks",
            applicable=False,
        )

    unsafe: list[str] = []
    for index, plugin in enumerate(data.get("plugins", [])):
        if not isinstance(plugin, dict):
            unsafe.append(f"plugin[{index}]=invalid-entry")
            continue
        source = plugin.get("source")
        if not isinstance(source, dict):
            continue
        source_mode = source.get("source")
        source_path = source.get("path")
        if source_mode != "local" or not isinstance(source_path, str):
            unsafe.append(f"plugin[{index}]=invalid-source")
            continue
        if not _is_safe_source(plugin_dir, source_path):
            unsafe.append(f"plugin[{index}]={source_path}")

    if not unsafe:
        return CheckResult(
            name="Marketplace sources are safe",
            passed=True,
            points=5,
            max_points=5,
            message="Marketplace sources are relative-safe local paths.",
        )

    return CheckResult(
        name="Marketplace sources are safe",
        passed=False,
        points=0,
        max_points=5,
        message=f"Unsafe marketplace sources detected: {', '.join(unsafe)}",
        findings=tuple(
            Finding(
                rule_id="MARKETPLACE_UNSAFE_SOURCE",
                severity=Severity.MEDIUM,
                category="marketplace",
                title="Marketplace source escapes the plugin directory",
                description=f'The marketplace source "{entry}" is absolute or resolves outside the plugin directory.',
                remediation="Use relative in-repo paths that stay within the plugin directory.",
                file_path="marketplace.json",
            )
            for entry in unsafe
        ),
    )


def run_marketplace_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_marketplace_json(plugin_dir),
        check_policy_fields(plugin_dir),
        check_sources_safe(plugin_dir),
    )
