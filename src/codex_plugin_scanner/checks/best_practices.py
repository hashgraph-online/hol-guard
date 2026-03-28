"""Best practice checks (25 points)."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import CheckResult

ENV_FILES = {".env", ".env.local", ".env.production"}


def check_readme(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / "README.md").exists()
    return CheckResult(
        name="README.md found",
        passed=exists,
        points=5 if exists else 0,
        max_points=5,
        message="README.md found" if exists else "README.md not found",
    )


def check_skills_directory(plugin_dir: Path) -> CheckResult:
    manifest_path = plugin_dir / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return CheckResult(name="Skills directory exists if declared", passed=True, points=5, max_points=5, message="Cannot parse manifest, skipping check")
    skills = manifest.get("skills")
    if not skills:
        return CheckResult(name="Skills directory exists if declared", passed=True, points=5, max_points=5, message="No skills field declared, check not applicable")
    skills_path = plugin_dir / skills
    if skills_path.is_dir():
        return CheckResult(name="Skills directory exists if declared", passed=True, points=5, max_points=5, message=f'Skills directory "{skills}" exists')
    return CheckResult(name="Skills directory exists if declared", passed=False, points=0, max_points=5, message=f'Skills directory "{skills}" declared but not found')


def check_skill_frontmatter(plugin_dir: Path) -> CheckResult:
    manifest_path = plugin_dir / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return CheckResult(name="SKILL.md frontmatter", passed=True, points=5, max_points=5, message="Cannot parse manifest, skipping check")
    skills = manifest.get("skills")
    if not skills:
        return CheckResult(name="SKILL.md frontmatter", passed=True, points=5, max_points=5, message="No skills field declared, check not applicable")
    skills_path = plugin_dir / skills
    if not skills_path.is_dir():
        return CheckResult(name="SKILL.md frontmatter", passed=True, points=5, max_points=5, message="Skills directory not found, skipping check")

    skill_files = list(skills_path.glob("*/SKILL.md"))
    if not skill_files:
        return CheckResult(name="SKILL.md frontmatter", passed=True, points=5, max_points=5, message="No SKILL.md files found, nothing to check")

    issues: list[str] = []
    for sf in skill_files:
        try:
            content = sf.read_text(encoding="utf-8")
        except OSError:
            continue
        if "---" not in content:
            issues.append(str(sf.relative_to(plugin_dir)))
            continue
        # Extract frontmatter between first two ---
        parts = content.split("---", 2)
        if len(parts) < 3:
            issues.append(str(sf.relative_to(plugin_dir)))
            continue
        fm = parts[1]
        if "name:" not in fm or "description:" not in fm:
            issues.append(str(sf.relative_to(plugin_dir)))

    if not issues:
        return CheckResult(name="SKILL.md frontmatter", passed=True, points=5, max_points=5, message="All SKILL.md files have valid frontmatter")
    return CheckResult(
        name="SKILL.md frontmatter",
        passed=False,
        points=0,
        max_points=5,
        message=f"SKILL.md missing valid frontmatter in: {', '.join(issues)}",
    )


def check_no_env_files(plugin_dir: Path) -> CheckResult:
    found = [f for f in ENV_FILES if (plugin_dir / f).exists()]
    if not found:
        return CheckResult(name="No .env files committed", passed=True, points=5, max_points=5, message="No .env files found")
    return CheckResult(name="No .env files committed", passed=False, points=0, max_points=5, message=f".env files found: {', '.join(found)}")


def check_codexignore(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / ".codexignore").exists()
    return CheckResult(
        name=".codexignore found",
        passed=exists,
        points=5 if exists else 0,
        max_points=5,
        message=".codexignore found" if exists else ".codexignore not found",
    )


def run_best_practice_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_readme(plugin_dir),
        check_skills_directory(plugin_dir),
        check_skill_frontmatter(plugin_dir),
        check_no_env_files(plugin_dir),
        check_codexignore(plugin_dir),
    )
