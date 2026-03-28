"""Marketplace validation checks (10 points)."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import CheckResult


def check_marketplace_json(plugin_dir: Path) -> CheckResult:
    mp = plugin_dir / "marketplace.json"
    if not mp.exists():
        return CheckResult(
            name="marketplace.json valid",
            passed=True,
            points=5,
            max_points=5,
            message="No marketplace.json found, check not applicable",
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
        )

    if not data.get("name") or not isinstance(data.get("name"), str):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message='marketplace.json missing "name" field',
        )
    if not isinstance(data.get("plugins"), list):
        return CheckResult(
            name="marketplace.json valid",
            passed=False,
            points=0,
            max_points=5,
            message='marketplace.json missing "plugins" array',
        )
    for i, plugin in enumerate(data["plugins"]):
        if not plugin.get("source") or not isinstance(plugin.get("source"), str):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'marketplace.json plugin[{i}] missing "source" field',
            )
        if not plugin.get("policy") or not isinstance(plugin.get("policy"), dict):
            return CheckResult(
                name="marketplace.json valid",
                passed=False,
                points=0,
                max_points=5,
                message=f'marketplace.json plugin[{i}] missing "policy" field',
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
            points=5,
            max_points=5,
            message="No marketplace.json found, check not applicable",
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
        policy = plugin.get("policy") or {}
        if not policy.get("installation"):
            issues.append(f"plugin[{i}]: missing policy.installation")
        if not policy.get("authentication"):
            issues.append(f"plugin[{i}]: missing policy.authentication")

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
    )


def run_marketplace_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_marketplace_json(plugin_dir),
        check_policy_fields(plugin_dir),
    )
