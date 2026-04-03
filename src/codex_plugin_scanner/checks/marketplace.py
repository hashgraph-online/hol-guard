"""Marketplace validation checks."""

from __future__ import annotations

import json
from pathlib import Path

from ..marketplace_support import (
    extract_marketplace_source,
    find_marketplace_file,
    load_marketplace_context,
    marketplace_label,
    source_path_is_safe,
    source_reference_is_safe,
    validate_marketplace_path_requirements,
)
from ..models import CheckResult, Finding, Severity


def _marketplace_finding(rule_id: str, title: str, description: str, remediation: str, *, file_path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        category="marketplace",
        title=title,
        description=description,
        remediation=remediation,
        file_path=file_path,
    )


def _not_applicable_result(name: str, message: str) -> CheckResult:
    return CheckResult(
        name=name,
        passed=True,
        points=0,
        max_points=0,
        message=message,
        applicable=False,
    )


def _load_context(plugin_dir: Path) -> tuple[object | None, str | None]:
    marketplace_file = find_marketplace_file(plugin_dir)
    if marketplace_file is None:
        return None, None
    path, _legacy = marketplace_file
    try:
        return load_marketplace_context(plugin_dir), str(path.relative_to(plugin_dir))
    except json.JSONDecodeError:
        return False, str(path.relative_to(plugin_dir))
    except ValueError:
        return False, str(path.relative_to(plugin_dir))


def check_marketplace_json(plugin_dir: Path) -> CheckResult:
    context, relative_path = _load_context(plugin_dir)
    if context is None:
        return _not_applicable_result("marketplace.json valid", "No marketplace manifest found, check not applicable")
    if context is False:
        file_path = relative_path or "marketplace.json"
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message=f"{file_path} is not valid JSON",
            findings=(
                _marketplace_finding(
                    "MARKETPLACE_JSON_INVALID",
                    "Marketplace manifest is invalid JSON",
                    "The marketplace manifest could not be parsed.",
                    "Fix the JSON syntax in the marketplace manifest.",
                    file_path=file_path,
                ),
            ),
        )

    file_path = marketplace_label(context)
    payload = context.payload
    if not payload.get("name") or not isinstance(payload.get("name"), str):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message=f'{file_path} missing "name" field',
            findings=(
                _marketplace_finding(
                    "MARKETPLACE_NAME_MISSING",
                    "Marketplace name is missing",
                    'The marketplace manifest must define a "name" field.',
                    'Add a string "name" field to the marketplace manifest.',
                    file_path=file_path,
                ),
            ),
        )

    plugins = payload.get("plugins")
    if not isinstance(plugins, list):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message=f'{file_path} missing "plugins" array',
            findings=(
                _marketplace_finding(
                    "MARKETPLACE_PLUGINS_MISSING",
                    "Marketplace plugins array is missing",
                    'The marketplace manifest must declare its plugin list in a "plugins" array.',
                    'Add a "plugins" array to the marketplace manifest.',
                    file_path=file_path,
                ),
            ),
        )

    for index, plugin in enumerate(plugins):
        if not isinstance(plugin, dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f"{file_path} plugin[{index}] must be an object",
                findings=(
                    _marketplace_finding(
                        "MARKETPLACE_SOURCE_MISSING",
                        "Marketplace plugin entry is invalid",
                        f"plugin[{index}] in the marketplace manifest must be an object.",
                        "Replace the plugin entry with an object containing source, policy, and category fields.",
                        file_path=file_path,
                    ),
                ),
            )
        if context.legacy:
            source_ref, _source_path = extract_marketplace_source(plugin)
            if source_ref is None:
                return CheckResult(
                    name="marketplace.json valid",
                    passed=False,
                    points=0,
                    max_points=5,
                    message=f'{file_path} plugin[{index}] missing "source" field',
                    findings=(
                        _marketplace_finding(
                            "MARKETPLACE_SOURCE_MISSING",
                            "Marketplace plugin source is missing",
                            f'plugin[{index}] in the marketplace manifest is missing a "source" field.',
                            'Add a "source" field for each marketplace entry.',
                            file_path=file_path,
                        ),
                    ),
                )
        else:
            issue = validate_marketplace_path_requirements(context, plugin)
            if issue is not None:
                return CheckResult(
                    name="marketplace.json valid",
                    passed=False,
                    points=0,
                    max_points=5,
                    message=f"{file_path} plugin[{index}] {issue}",
                    findings=(
                        _marketplace_finding(
                            "MARKETPLACE_SOURCE_MISSING",
                            "Marketplace source object is incomplete",
                            f"plugin[{index}] in the marketplace manifest has an invalid source object: {issue}.",
                            'Add a source object with both "source" and "./"-prefixed "path" fields.',
                            file_path=file_path,
                        ),
                    ),
                )
        if not plugin.get("policy") or not isinstance(plugin.get("policy"), dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'{file_path} plugin[{index}] missing "policy" field',
                findings=(
                    _marketplace_finding(
                        "MARKETPLACE_POLICY_MISSING",
                        "Marketplace policy is missing",
                        f'plugin[{index}] in the marketplace manifest is missing a "policy" object.',
                        'Add a "policy" object for each marketplace entry.',
                        file_path=file_path,
                    ),
                ),
            )

    compatibility = " in compatibility mode" if context.legacy else ""
    return CheckResult(
        name="marketplace.json valid",
        passed=True,
        points=5,
        max_points=5,
        message=f"{file_path} is valid{compatibility}",
    )


def check_policy_fields(plugin_dir: Path) -> CheckResult:
    context, relative_path = _load_context(plugin_dir)
    if context is None:
        return _not_applicable_result("Policy fields present", "No marketplace manifest found, check not applicable")
    if context is False:
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=5,
            max_points=5,
            message=f"Cannot parse {relative_path or 'marketplace.json'}, skipping check",
        )

    issues: list[str] = []
    for index, plugin in enumerate(context.payload.get("plugins", [])):
        if not isinstance(plugin, dict):
            issues.append(f"plugin[{index}] must be an object")
            continue
        policy = plugin.get("policy") or {}
        if not isinstance(policy, dict):
            issues.append(f"plugin[{index}] missing policy object")
            continue
        if not isinstance(policy.get("installation"), str) or not policy.get("installation"):
            issues.append(f"plugin[{index}] missing policy.installation")
        if not isinstance(policy.get("authentication"), str) or not policy.get("authentication"):
            issues.append(f"plugin[{index}] missing policy.authentication")
        if not isinstance(plugin.get("category"), str) or not plugin.get("category"):
            issues.append(f"plugin[{index}] missing category")

    if not issues:
        compatibility = " in compatibility mode" if context.legacy else ""
        return CheckResult(
            name="Policy fields present",
            passed=True,
            points=5,
            max_points=5,
            message=f"All marketplace policy fields are present{compatibility}",
        )

    file_path = marketplace_label(context)
    return CheckResult(
        name="Policy fields present",
        passed=False,
        points=0,
        max_points=5,
        message=f"Policy issues: {', '.join(issues[:3])}",
        findings=tuple(
            _marketplace_finding(
                "MARKETPLACE_POLICY_FIELDS_MISSING",
                "Marketplace policy fields are incomplete",
                issue,
                "Add policy.installation, policy.authentication, and category for each marketplace entry.",
                file_path=file_path,
            )
            for issue in issues
        ),
    )


def check_sources_safe(plugin_dir: Path) -> CheckResult:
    context, _relative_path = _load_context(plugin_dir)
    if context is None:
        return _not_applicable_result(
            "Marketplace sources are safe",
            "No marketplace manifest found, check not applicable",
        )
    if context is False:
        return _not_applicable_result(
            "Marketplace sources are safe",
            "Cannot parse marketplace manifest, skipping source safety checks",
        )

    unsafe: list[str] = []
    for index, plugin in enumerate(context.payload.get("plugins", [])):
        if not isinstance(plugin, dict):
            unsafe.append(f"plugin[{index}]=invalid-entry")
            continue
        source_ref, source_path = extract_marketplace_source(plugin)
        if context.legacy:
            if source_ref is not None and not source_reference_is_safe(context, source_ref):
                unsafe.append(f"plugin[{index}]={source_ref}")
            continue
        if source_ref is None or not source_reference_is_safe(context, source_ref):
            unsafe.append(f"plugin[{index}].source.source={source_ref or 'missing'}")
        if source_path is None:
            unsafe.append(f"plugin[{index}].source.path=missing")
        elif not source_path.startswith("./"):
            unsafe.append(f'plugin[{index}].source.path must start with "./": {source_path}')
        elif not source_path_is_safe(context, source_path):
            unsafe.append(f"plugin[{index}].source.path escapes root: {source_path}")

    if not unsafe:
        compatibility = " in compatibility mode" if context.legacy else ""
        return CheckResult(
            name="Marketplace sources are safe",
            passed=True,
            points=5,
            max_points=5,
            message=f"Marketplace sources are safe{compatibility}.",
        )

    file_path = marketplace_label(context)
    return CheckResult(
        name="Marketplace sources are safe",
        passed=False,
        points=0,
        max_points=5,
        message=f"Unsafe marketplace sources detected: {', '.join(unsafe)}",
        findings=tuple(
            _marketplace_finding(
                "MARKETPLACE_UNSAFE_SOURCE",
                "Marketplace source is unsafe",
                entry,
                'Use remote HTTPS sources or "./"-prefixed in-repo paths that stay within the marketplace root.',
                file_path=file_path,
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
