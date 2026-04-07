"""Claude ecosystem checks."""

from __future__ import annotations

import json

from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity
from .ecosystem_common import SEMVER_RE, has_frontmatter


def _finding(
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    file_path: str,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="claude",
        title=title,
        description=description,
        remediation=remediation,
        file_path=file_path,
    )


def check_manifest_exists(package: NormalizedPackage) -> CheckResult:
    exists = package.manifest_path is not None and package.manifest_path.exists()
    file_path = (
        ".claude-plugin/plugin.json" if package.package_kind == "single-plugin" else ".claude-plugin/marketplace.json"
    )
    return CheckResult(
        name="Claude manifest exists",
        passed=exists,
        points=4 if exists else 0,
        max_points=4,
        message="Claude manifest found" if exists else "Claude manifest missing",
        findings=()
        if exists
        else (
            _finding(
                "CLAUDE_MANIFEST_MISSING",
                "Claude manifest is missing",
                "Claude plugin packages require a .claude-plugin manifest.",
                "Add .claude-plugin/plugin.json or .claude-plugin/marketplace.json.",
                file_path=file_path,
            ),
        ),
    )


def check_required_fields(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    name = manifest.get("name")
    version = manifest.get("version")
    missing: list[str] = []
    if not isinstance(name, str) or not name.strip():
        missing.append("name")
    if package.package_kind == "single-plugin":
        if not isinstance(version, str) or not version.strip():
            missing.append("version")
        elif not SEMVER_RE.match(version):
            return CheckResult(
                name="Claude required fields and semver",
                passed=False,
                points=0,
                max_points=5,
                message=f'Claude plugin version "{version}" is not semver.',
                findings=(
                    _finding(
                        "CLAUDE_VERSION_BAD_SEMVER",
                        "Claude plugin version is not semver",
                        f'The version "{version}" does not match X.Y.Z.',
                        "Use semver in .claude-plugin/plugin.json.",
                        file_path=".claude-plugin/plugin.json",
                        severity=Severity.LOW,
                    ),
                ),
            )
    if not missing:
        return CheckResult(
            name="Claude required fields and semver",
            passed=True,
            points=5,
            max_points=5,
            message="Claude required fields are present.",
        )
    return CheckResult(
        name="Claude required fields and semver",
        passed=False,
        points=0,
        max_points=5,
        message=f"Missing required Claude fields: {', '.join(missing)}",
        findings=tuple(
            _finding(
                f"CLAUDE_FIELD_MISSING_{field.upper()}",
                f'Claude field "{field}" is missing',
                f'The Claude manifest requires a non-empty "{field}" string.',
                f'Add "{field}" to the Claude manifest.',
                file_path=(
                    ".claude-plugin/plugin.json"
                    if package.package_kind == "single-plugin"
                    else ".claude-plugin/marketplace.json"
                ),
            )
            for field in missing
        ),
    )


def check_marketplace_structure(package: NormalizedPackage) -> CheckResult:
    if package.package_kind != "marketplace":
        return CheckResult(
            name="Claude marketplace structure",
            passed=True,
            points=0,
            max_points=0,
            message="Not a Claude marketplace package.",
            applicable=False,
        )
    plugins = package.raw_manifest.get("plugins")
    strict = package.raw_manifest.get("strict")
    if not isinstance(plugins, list):
        return CheckResult(
            name="Claude marketplace structure",
            passed=False,
            points=0,
            max_points=4,
            message='Claude marketplace must include a "plugins" array.',
            findings=(
                _finding(
                    "CLAUDE_MARKETPLACE_PLUGINS_MISSING",
                    "Claude marketplace plugins array missing",
                    'The Claude marketplace manifest must include a top-level "plugins" array.',
                    'Add "plugins": [] to .claude-plugin/marketplace.json.',
                    file_path=".claude-plugin/marketplace.json",
                ),
            ),
        )
    if not isinstance(strict, bool):
        return CheckResult(
            name="Claude marketplace structure",
            passed=False,
            points=0,
            max_points=4,
            message='Claude marketplace must define boolean "strict".',
            findings=(
                _finding(
                    "CLAUDE_MARKETPLACE_STRICT_INVALID",
                    "Claude marketplace strict mode missing",
                    'The Claude marketplace manifest should declare a boolean "strict" mode.',
                    'Set "strict": true or false in .claude-plugin/marketplace.json.',
                    file_path=".claude-plugin/marketplace.json",
                ),
            ),
        )
    return CheckResult(
        name="Claude marketplace structure",
        passed=True,
        points=4,
        max_points=4,
        message="Claude marketplace shape is valid.",
    )


def check_relative_paths(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    invalid_paths: list[str] = []
    path_fields = ("path", "pluginPath", "directory")

    def walk(value: object, breadcrumb: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{breadcrumb}.{key}" if breadcrumb else str(key)
                if key in path_fields and isinstance(item, str) and item and not item.startswith("./"):
                    invalid_paths.append(f"{child}={item}")
                walk(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{breadcrumb}[{index}]")

    walk(manifest)

    if not invalid_paths:
        return CheckResult(
            name="Claude custom paths are relative",
            passed=True,
            points=4,
            max_points=4,
            message="Claude custom paths use ./ relative form.",
        )

    return CheckResult(
        name="Claude custom paths are relative",
        passed=False,
        points=0,
        max_points=4,
        message=f"Non-relative Claude paths found: {', '.join(invalid_paths[:3])}",
        findings=tuple(
            _finding(
                "CLAUDE_PATH_NOT_RELATIVE",
                "Claude path is not relative",
                f'The path "{entry}" does not start with "./".',
                'Use "./" relative paths for Claude plugin components.',
                file_path=(
                    ".claude-plugin/marketplace.json"
                    if package.package_kind == "marketplace"
                    else ".claude-plugin/plugin.json"
                ),
                severity=Severity.LOW,
            )
            for entry in invalid_paths
        ),
    )


def check_hooks_and_skills(package: NormalizedPackage) -> CheckResult:
    root = package.root_path
    issues: list[Finding] = []
    hooks_file = root / "hooks" / "hooks.json"
    if hooks_file.exists():
        try:
            payload = json.loads(hooks_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("hooks payload is not an object")
        except (json.JSONDecodeError, OSError, ValueError):
            issues.append(
                _finding(
                    "CLAUDE_HOOKS_INVALID",
                    "Claude hooks file is invalid JSON",
                    "hooks/hooks.json must be valid JSON object structure.",
                    "Fix JSON syntax and hooks schema shape.",
                    file_path=str(hooks_file.relative_to(root)),
                )
            )

    for skill_path in (root / "skills").rglob("SKILL.md") if (root / "skills").is_dir() else []:
        try:
            content = skill_path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not has_frontmatter(content):
            issues.append(
                _finding(
                    "CLAUDE_SKILL_FRONTMATTER_INVALID",
                    "Claude SKILL.md frontmatter is invalid",
                    f"{skill_path.relative_to(root)} is missing name/description frontmatter.",
                    "Add YAML frontmatter with at least name and description.",
                    file_path=str(skill_path.relative_to(root)),
                    severity=Severity.LOW,
                )
            )

    if not issues:
        return CheckResult(
            name="Claude hooks and skills are parseable",
            passed=True,
            points=5,
            max_points=5,
            message="Claude hooks and skills passed parse checks.",
        )
    return CheckResult(
        name="Claude hooks and skills are parseable",
        passed=False,
        points=0,
        max_points=5,
        message=f"Claude hooks/skills issues detected: {len(issues)}",
        findings=tuple(issues),
    )


def run_claude_checks(package: NormalizedPackage) -> tuple[CheckResult, ...]:
    """Run Claude ecosystem checks."""

    return (
        check_manifest_exists(package),
        check_required_fields(package),
        check_marketplace_structure(package),
        check_relative_paths(package),
        check_hooks_and_skills(package),
    )
