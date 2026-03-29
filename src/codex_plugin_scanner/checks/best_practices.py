"""Best practice checks (15 points)."""

from __future__ import annotations

from pathlib import Path

from ..models import CheckResult, Finding, Severity
from .manifest import load_manifest

ENV_FILES = {".env", ".env.local", ".env.production"}


def check_readme(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / "README.md").exists()
    return CheckResult(
        name="README.md found",
        passed=exists,
        points=3 if exists else 0,
        max_points=3,
        message="README.md found" if exists else "README.md not found",
        findings=()
        if exists
        else (
            Finding(
                rule_id="README_MISSING",
                severity=Severity.LOW,
                category="best-practices",
                title="README.md is missing",
                description="Plugins should document installation, usage, and security expectations in README.md.",
                remediation="Add a README.md that explains setup, usage, and operational constraints.",
                file_path="README.md",
            ),
        ),
    )


def check_skills_directory(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Skills directory exists if declared",
            passed=True,
            points=0,
            max_points=0,
            message="Cannot parse manifest, skipping check",
            applicable=False,
        )
    skills = manifest.get("skills")
    if not skills:
        return CheckResult(
            name="Skills directory exists if declared",
            passed=True,
            points=0,
            max_points=0,
            message="No skills field declared, check not applicable",
            applicable=False,
        )
    skills_path = plugin_dir / skills
    if skills_path.is_dir():
        return CheckResult(
            name="Skills directory exists if declared",
            passed=True,
            points=3,
            max_points=3,
            message=f'Skills directory "{skills}" exists',
        )
    return CheckResult(
        name="Skills directory exists if declared",
        passed=False,
        points=0,
        max_points=3,
        message=f'Skills directory "{skills}" declared but not found',
        findings=(
            Finding(
                rule_id="SKILLS_DIR_MISSING",
                severity=Severity.MEDIUM,
                category="best-practices",
                title="Declared skills directory is missing",
                description=f'The manifest declares "{skills}" as the skills directory, but it does not exist.',
                remediation="Create the skills directory or correct the manifest path.",
                file_path=".codex-plugin/plugin.json",
            ),
        ),
    )


def check_skill_frontmatter(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="SKILL.md frontmatter",
            passed=True,
            points=0,
            max_points=0,
            message="Cannot parse manifest, skipping check",
            applicable=False,
        )
    skills = manifest.get("skills")
    if not skills:
        return CheckResult(
            name="SKILL.md frontmatter",
            passed=True,
            points=0,
            max_points=0,
            message="No skills field declared, check not applicable",
            applicable=False,
        )
    skills_path = plugin_dir / skills
    if not skills_path.is_dir():
        return CheckResult(
            name="SKILL.md frontmatter",
            passed=True,
            points=0,
            max_points=0,
            message="Skills directory not found, skipping check",
            applicable=False,
        )

    skill_files = list(skills_path.glob("*/SKILL.md"))
    if not skill_files:
        return CheckResult(
            name="SKILL.md frontmatter",
            passed=True,
            points=0,
            max_points=0,
            message="No SKILL.md files found, nothing to check",
            applicable=False,
        )

    issues: list[str] = []
    for sf in skill_files:
        try:
            content = sf.read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            continue
        if "---" not in content:
            issues.append(str(sf.relative_to(plugin_dir)))
            continue
        parts = content.split("---", 2)
        if len(parts) < 3:
            issues.append(str(sf.relative_to(plugin_dir)))
            continue
        fm = parts[1]
        if "name:" not in fm or "description:" not in fm:
            issues.append(str(sf.relative_to(plugin_dir)))

    if not issues:
        return CheckResult(
            name="SKILL.md frontmatter",
            passed=True,
            points=3,
            max_points=3,
            message="All SKILL.md files have valid frontmatter",
        )
    return CheckResult(
        name="SKILL.md frontmatter",
        passed=False,
        points=0,
        max_points=3,
        message=f"SKILL.md missing valid frontmatter in: {', '.join(issues)}",
        findings=tuple(
            Finding(
                rule_id="SKILL_FRONTMATTER_INVALID",
                severity=Severity.MEDIUM,
                category="best-practices",
                title="Skill frontmatter is invalid",
                description=f"{path} is missing valid skill frontmatter.",
                remediation="Add YAML frontmatter with at least name and description fields.",
                file_path=path,
            )
            for path in issues
        ),
    )


def check_no_env_files(plugin_dir: Path) -> CheckResult:
    found = [f for f in ENV_FILES if (plugin_dir / f).exists()]
    if not found:
        return CheckResult(
            name="No .env files committed",
            passed=True,
            points=3,
            max_points=3,
            message="No .env files found",
        )
    return CheckResult(
        name="No .env files committed",
        passed=False,
        points=0,
        max_points=3,
        message=f".env files found: {', '.join(found)}",
        findings=tuple(
            Finding(
                rule_id="ENV_FILE_COMMITTED",
                severity=Severity.HIGH,
                category="best-practices",
                title="Environment file is committed",
                description=f'The file "{path}" is present in the plugin directory.',
                remediation="Remove committed environment files and rely on local, ignored configuration.",
                file_path=path,
            )
            for path in found
        ),
    )


def check_codexignore(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / ".codexignore").exists()
    return CheckResult(
        name=".codexignore found",
        passed=exists,
        points=3 if exists else 0,
        max_points=3,
        message=".codexignore found" if exists else ".codexignore not found",
        findings=()
        if exists
        else (
            Finding(
                rule_id="CODEXIGNORE_MISSING",
                severity=Severity.INFO,
                category="best-practices",
                title=".codexignore is missing",
                description="A .codexignore file helps prevent accidental inclusion of local artifacts and secrets.",
                remediation="Add a .codexignore file with generated assets, local state, and secret paths.",
                file_path=".codexignore",
            ),
        ),
    )


def run_best_practice_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_readme(plugin_dir),
        check_skills_directory(plugin_dir),
        check_skill_frontmatter(plugin_dir),
        check_no_env_files(plugin_dir),
        check_codexignore(plugin_dir),
    )
