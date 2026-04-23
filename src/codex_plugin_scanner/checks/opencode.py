"""OpenCode ecosystem checks."""

from __future__ import annotations

from pathlib import Path

from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity
from ..path_support import is_safe_relative_path
from .ecosystem_common import has_frontmatter


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
        category="opencode",
        title=title,
        description=description,
        remediation=remediation,
        file_path=file_path,
    )


def check_opencode_config(package: NormalizedPackage) -> CheckResult:
    if package.manifest_path is None:
        return CheckResult(
            name="OpenCode config discovered",
            passed=True,
            points=2,
            max_points=2,
            message="OpenCode workspace detected via .opencode directory.",
        )
    if package.manifest_parse_error:
        reason = package.manifest_parse_error_reason or "invalid-json"
        reason_messages = {
            "file-not-found": f"{package.manifest_path.name} was not found while scanning.",
            "permission-denied": f"{package.manifest_path.name} could not be read due to permissions.",
            "read-error": f"{package.manifest_path.name} could not be read.",
            "not-object": f"{package.manifest_path.name} must contain a top-level JSON object.",
            "invalid-json": f"{package.manifest_path.name} is not valid JSON/JSONC.",
        }
        return CheckResult(
            name="OpenCode config discovered",
            passed=False,
            points=0,
            max_points=2,
            message=reason_messages.get(reason, f"{package.manifest_path.name} could not be parsed."),
            findings=(
                _finding(
                    "OPENCODE_CONFIG_INVALID",
                    "OpenCode config is invalid",
                    reason_messages.get(reason, f"{package.manifest_path.name} is not valid JSON/JSONC."),
                    "Fix opencode.json/opencode.jsonc syntax.",
                    file_path=package.manifest_path.name,
                ),
            ),
        )
    return CheckResult(
        name="OpenCode config discovered",
        passed=True,
        points=2,
        max_points=2,
        message=f"{package.manifest_path.name} parsed successfully.",
    )


def check_opencode_plugins(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    root = package.root_path
    configured_plugins = manifest.get("plugins")
    if configured_plugins is None:
        return CheckResult(
            name="OpenCode plugin references resolve",
            passed=True,
            points=0,
            max_points=0,
            message="No plugin references declared in OpenCode config.",
            applicable=False,
        )
    values: list[str] = []
    if isinstance(configured_plugins, list):
        for item in configured_plugins:
            if isinstance(item, str):
                values.append(item)
    elif isinstance(configured_plugins, dict):
        for item in configured_plugins.values():
            if isinstance(item, str):
                values.append(item)

    unsafe: list[str] = []
    missing: list[str] = []
    for value in values:
        if not value.startswith((".", "/")):
            continue
        if not is_safe_relative_path(root, value):
            unsafe.append(value)
            continue
        if not (root / Path(value)).exists():
            missing.append(value)

    if not unsafe and not missing:
        return CheckResult(
            name="OpenCode plugin references resolve",
            passed=True,
            points=4,
            max_points=4,
            message="OpenCode plugin references resolve locally.",
        )
    findings = [
        _finding(
            "OPENCODE_PLUGIN_PATH_UNSAFE",
            "OpenCode plugin path escapes the repository",
            f'The plugin reference "{path}" resolves outside the repository root.',
            "Use only relative in-repository plugin paths.",
            file_path=package.manifest_path.name if package.manifest_path else "opencode.json",
        )
        for path in unsafe
    ]
    findings.extend(
        _finding(
            "OPENCODE_PLUGIN_PATH_MISSING",
            "OpenCode plugin path is missing",
            f'The plugin reference "{path}" does not exist.',
            "Fix plugin path references in opencode config.",
            file_path=package.manifest_path.name if package.manifest_path else "opencode.json",
        )
        for path in missing
    )
    return CheckResult(
        name="OpenCode plugin references resolve",
        passed=False,
        points=0,
        max_points=4,
        message=f"OpenCode plugin path issues: {', '.join([*unsafe, *missing][:3])}",
        findings=tuple(findings),
    )


def check_opencode_commands(package: NormalizedPackage) -> CheckResult:
    root = package.root_path
    command_paths = package.components.get("commands", ())
    if not command_paths:
        return CheckResult(
            name="OpenCode command markdown structure",
            passed=True,
            points=0,
            max_points=0,
            message="No OpenCode command markdown files detected.",
            applicable=False,
        )

    issues: list[Finding] = []
    for relative_path in command_paths:
        path = root / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not has_frontmatter(content):
            issues.append(
                _finding(
                    "OPENCODE_COMMAND_FRONTMATTER_INVALID",
                    "OpenCode command markdown is missing frontmatter",
                    f"{relative_path} should include frontmatter with name/description.",
                    "Add frontmatter at the top of the command markdown file.",
                    file_path=relative_path,
                    severity=Severity.LOW,
                )
            )

    if not issues:
        return CheckResult(
            name="OpenCode command markdown structure",
            passed=True,
            points=4,
            max_points=4,
            message="OpenCode command markdown files include frontmatter.",
        )
    return CheckResult(
        name="OpenCode command markdown structure",
        passed=False,
        points=0,
        max_points=4,
        message=f"OpenCode command markdown issues: {len(issues)}",
        findings=tuple(issues),
    )


def check_opencode_mcp_shape(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    mcp = manifest.get("mcp")
    if mcp is None:
        return CheckResult(
            name="OpenCode MCP shape",
            passed=True,
            points=0,
            max_points=0,
            message="No OpenCode mcp configuration declared.",
            applicable=False,
        )
    if isinstance(mcp, dict):
        return CheckResult(
            name="OpenCode MCP shape",
            passed=True,
            points=3,
            max_points=3,
            message="OpenCode mcp configuration is object-shaped.",
        )
    return CheckResult(
        name="OpenCode MCP shape",
        passed=False,
        points=0,
        max_points=3,
        message="OpenCode mcp configuration must be an object.",
        findings=(
            _finding(
                "OPENCODE_MCP_INVALID",
                "OpenCode mcp configuration is invalid",
                "The mcp field in opencode config must be an object.",
                "Update mcp to an object in opencode.json/opencode.jsonc.",
                file_path=package.manifest_path.name if package.manifest_path else "opencode.json",
            ),
        ),
    )


def run_opencode_checks(package: NormalizedPackage) -> tuple[CheckResult, ...]:
    """Run OpenCode ecosystem checks."""

    return (
        check_opencode_config(package),
        check_opencode_plugins(package),
        check_opencode_commands(package),
        check_opencode_mcp_shape(package),
    )
