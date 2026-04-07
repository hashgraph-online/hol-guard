"""Gemini ecosystem checks."""

from __future__ import annotations

from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity
from .ecosystem_common import SEMVER_RE

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


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
        category="gemini",
        title=title,
        description=description,
        remediation=remediation,
        file_path=file_path,
    )


def check_manifest_required_fields(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    missing: list[str] = []
    for field in ("name", "version"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            missing.append(field)
    version = manifest.get("version")
    if isinstance(version, str) and version.strip() and not SEMVER_RE.match(version):
        missing.append("version-semver")
    if not missing:
        return CheckResult(
            name="Gemini manifest required fields",
            passed=True,
            points=5,
            max_points=5,
            message="Gemini manifest has required fields.",
        )
    findings: list[Finding] = []
    for missing_field in missing:
        if missing_field == "version-semver":
            findings.append(
                _finding(
                    "GEMINI_VERSION_BAD_SEMVER",
                    "Gemini extension version is not semver",
                    f'Gemini extension version "{version}" should match X.Y.Z.',
                    "Update gemini-extension.json version to semver.",
                    file_path="gemini-extension.json",
                    severity=Severity.LOW,
                )
            )
            continue
        findings.append(
            _finding(
                f"GEMINI_FIELD_MISSING_{missing_field.upper()}",
                f'Gemini field "{missing_field}" missing',
                f'Gemini extension manifest requires a "{missing_field}" string.',
                f'Add "{missing_field}" to gemini-extension.json.',
                file_path="gemini-extension.json",
            )
        )
    return CheckResult(
        name="Gemini manifest required fields",
        passed=False,
        points=0,
        max_points=5,
        message=f"Gemini manifest issues: {', '.join(missing)}",
        findings=tuple(findings),
    )


def check_commands_toml(package: NormalizedPackage) -> CheckResult:
    root = package.root_path
    command_paths = package.components.get("commands", ())
    if not command_paths:
        return CheckResult(
            name="Gemini command TOML files parse",
            passed=True,
            points=0,
            max_points=0,
            message="No Gemini command TOML files detected.",
            applicable=False,
        )
    issues: list[Finding] = []
    for relative_path in command_paths:
        path = root / relative_path
        try:
            tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            issues.append(
                _finding(
                    "GEMINI_COMMAND_TOML_INVALID",
                    "Gemini command TOML is invalid",
                    f"{relative_path} is not valid TOML.",
                    "Fix TOML syntax in the command file.",
                    file_path=relative_path,
                )
            )
    if not issues:
        return CheckResult(
            name="Gemini command TOML files parse",
            passed=True,
            points=5,
            max_points=5,
            message="Gemini command TOML files parse successfully.",
        )
    return CheckResult(
        name="Gemini command TOML files parse",
        passed=False,
        points=0,
        max_points=5,
        message=f"Invalid Gemini command TOML files: {', '.join(f.file_path or '' for f in issues[:3])}",
        findings=tuple(issues),
    )


def check_context_and_mcp(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    root = package.root_path
    findings: list[Finding] = []
    context_file = manifest.get("contextFileName")
    if isinstance(context_file, str) and context_file.strip() and not (root / context_file).exists():
        findings.append(
            _finding(
                "GEMINI_CONTEXT_FILE_MISSING",
                "Gemini context file is missing",
                f'contextFileName points to "{context_file}", but that file is missing.',
                "Add the context file or remove contextFileName.",
                file_path="gemini-extension.json",
                severity=Severity.LOW,
            )
        )
    mcp_servers = manifest.get("mcpServers")
    if mcp_servers is not None and not isinstance(mcp_servers, dict):
        findings.append(
            _finding(
                "GEMINI_MCP_SERVERS_INVALID",
                "Gemini mcpServers must be an object",
                "The mcpServers field should be a JSON object keyed by server name.",
                "Update mcpServers to an object in gemini-extension.json.",
                file_path="gemini-extension.json",
            )
        )
    exclude_tools = manifest.get("excludeTools")
    if exclude_tools is not None and (
        not isinstance(exclude_tools, list) or not all(isinstance(item, str) for item in exclude_tools)
    ):
        findings.append(
            _finding(
                "GEMINI_EXCLUDE_TOOLS_INVALID",
                "Gemini excludeTools must be an array of strings",
                "excludeTools should list command names as string values.",
                "Fix excludeTools in gemini-extension.json.",
                file_path="gemini-extension.json",
                severity=Severity.LOW,
            )
        )
    if not findings:
        return CheckResult(
            name="Gemini context and MCP shape",
            passed=True,
            points=5,
            max_points=5,
            message="Gemini context and MCP fields are valid.",
        )
    return CheckResult(
        name="Gemini context and MCP shape",
        passed=False,
        points=0,
        max_points=5,
        message=f"Gemini manifest context/MCP issues: {len(findings)}",
        findings=tuple(findings),
    )


def run_gemini_checks(package: NormalizedPackage) -> tuple[CheckResult, ...]:
    """Run Gemini ecosystem checks."""

    return (
        check_manifest_required_fields(package),
        check_commands_toml(package),
        check_context_and_mcp(package),
    )
