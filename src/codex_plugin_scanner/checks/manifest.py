"""Manifest validation checks (25 points)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import CheckResult

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+")
KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def load_manifest(plugin_dir: Path) -> dict | None:
    p = plugin_dir / ".codex-plugin" / "plugin.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def check_plugin_json_exists(plugin_dir: Path) -> CheckResult:
    p = plugin_dir / ".codex-plugin" / "plugin.json"
    exists = p.exists()
    return CheckResult(
        name="plugin.json exists",
        passed=exists,
        points=5 if exists else 0,
        max_points=5,
        message="plugin.json found" if exists else "plugin.json not found at .codex-plugin/plugin.json",
    )


def check_valid_json(plugin_dir: Path) -> CheckResult:
    p = plugin_dir / ".codex-plugin" / "plugin.json"
    try:
        content = p.read_text(encoding="utf-8")
        json.loads(content)
        return CheckResult(name="Valid JSON", passed=True, points=5, max_points=5, message="plugin.json is valid JSON")
    except Exception:
        return CheckResult(
            name="Valid JSON", passed=False, points=0, max_points=5, message="plugin.json is not valid JSON"
        )


def check_required_fields(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Required fields present", passed=False, points=0, max_points=8, message="Cannot parse plugin.json"
        )
    required = ["name", "version", "description"]
    missing = [f for f in required if not manifest.get(f) or not isinstance(manifest.get(f), str)]
    if not missing:
        return CheckResult(
            name="Required fields present",
            passed=True,
            points=8,
            max_points=8,
            message="All required fields (name, version, description) present",
        )
    return CheckResult(
        name="Required fields present",
        passed=False,
        points=0,
        max_points=8,
        message=f"Missing required fields: {', '.join(missing)}",
    )


def check_semver(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Version follows semver", passed=False, points=0, max_points=4, message="Cannot parse plugin.json"
        )
    version = manifest.get("version", "")
    if version and SEMVER_RE.match(str(version)):
        return CheckResult(
            name="Version follows semver",
            passed=True,
            points=4,
            max_points=4,
            message=f'Version "{version}" follows semver',
        )
    return CheckResult(
        name="Version follows semver",
        passed=False,
        points=0,
        max_points=4,
        message=f'Version "{version}" does not follow semver (expected X.Y.Z)',
    )


def check_kebab_case(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Name is kebab-case", passed=False, points=0, max_points=3, message="Cannot parse plugin.json"
        )
    name = manifest.get("name", "")
    if name and KEBAB_RE.match(str(name)):
        return CheckResult(
            name="Name is kebab-case", passed=True, points=3, max_points=3, message=f'Name "{name}" is kebab-case'
        )
    return CheckResult(
        name="Name is kebab-case", passed=False, points=0, max_points=3, message=f'Name "{name}" should be kebab-case'
    )


def run_manifest_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_plugin_json_exists(plugin_dir),
        check_valid_json(plugin_dir),
        check_required_fields(plugin_dir),
        check_semver(plugin_dir),
        check_kebab_case(plugin_dir),
    )
