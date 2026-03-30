"""Security checks (20 points)."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from ..models import CheckResult, Finding, Severity

# Patterns for hardcoded secrets
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}", re.I),
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"password\s*[=:]\s*[\"'][^\s\"']{8,}", re.I),
    re.compile(r"secret\s*[=:]\s*[\"'][^\s\"']{8,}", re.I),
    re.compile(r"token\s*[=:]\s*[\"'][^\s\"']{8,}", re.I),
    re.compile(r"api_?key\s*[=:]\s*[\"'][^\s\"']{8,}", re.I),
    re.compile(r"API_KEY\s*[=:]\s*[\"'][^\s\"']{8,}"),
    re.compile(r"PRIVATE_KEY\s*[=:]\s*[\"'][^\s\"']{8,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9]{36}"),  # GitHub OAuth
    re.compile(r"ghu_[A-Za-z0-9]{36}"),  # GitHub user token
    re.compile(r"ghs_[A-Za-z0-9]{36}"),  # GitHub app token
    re.compile(r"glpat-[A-Za-z0-9\-]{20}"),  # GitLab PAT
    re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}"),  # Slack tokens
    re.compile(r"sk-[A-Za-z0-9]{48}"),  # OpenAI key
]

EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__pycache__", ".venv", "venv"}

BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".lock",
    ".wasm",
    ".pyc",
    ".so",
    ".dylib",
}

DANGEROUS_MCP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"rm\s+-rf"),
    re.compile(r"\bsudo\b"),
    re.compile(r"curl\b.*\|\s*(ba)?sh"),
    re.compile(r"wget\b.*\|\s*(ba)?sh"),
    re.compile(r"bash\s+-c"),
    re.compile(r"\beval\b"),
    re.compile(r"\bexec\b"),
    re.compile(r"powershell\s+-c", re.I),
    re.compile(r"cmd\s*/c", re.I),
]

RISKY_APPROVAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"danger-full-access"),
    re.compile(r'approval[_ -]?policy["\']?\s*[:=]\s*["\']never["\']', re.I),
    re.compile(r'approvalMode["\']?\s*[:=]\s*["\']bypass["\']', re.I),
]


def _scan_all_files(plugin_dir: Path) -> list[Path]:
    """Recursively find all files, skipping excluded dirs."""
    files = []
    for p in plugin_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in BINARY_EXTS:
            continue
        files.append(p)
    return files


def check_security_md(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / "SECURITY.md").exists()
    return CheckResult(
        name="SECURITY.md found",
        passed=exists,
        points=3 if exists else 0,
        max_points=3,
        message="SECURITY.md found" if exists else "SECURITY.md not found",
        findings=()
        if exists
        else (
            Finding(
                rule_id="SECURITY_MD_MISSING",
                severity=Severity.LOW,
                category="security",
                title="SECURITY.md is missing",
                description=(
                    "Plugins should publish a SECURITY.md file for responsible disclosure and support guidance."
                ),
                remediation="Add a SECURITY.md file with reporting guidance and supported versions.",
                file_path="SECURITY.md",
            ),
        ),
    )


def check_license(plugin_dir: Path) -> CheckResult:
    lp = plugin_dir / "LICENSE"
    if not lp.exists():
        return CheckResult(
            name="LICENSE found",
            passed=False,
            points=0,
            max_points=3,
            message="LICENSE file not found",
            findings=(
                Finding(
                    rule_id="LICENSE_MISSING",
                    severity=Severity.LOW,
                    category="security",
                    title="LICENSE file is missing",
                    description="Plugins should ship a LICENSE file so consumers can review usage rights.",
                    remediation="Add a LICENSE file that matches the manifest license metadata.",
                    file_path="LICENSE",
                ),
            ),
        )
    try:
        content = lp.read_text(encoding="utf-8", errors="ignore")
        if "Apache" in content and ("2.0" in content or "www.apache.org" in content):
            return CheckResult(
                name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (Apache-2.0)"
            )
        if "MIT" in content and "Permission is hereby granted" in content:
            return CheckResult(name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (MIT)")
        return CheckResult(name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found")
    except OSError:
        return CheckResult(
            name="LICENSE found", passed=False, points=0, max_points=3, message="LICENSE exists but could not be read"
        )


def check_no_hardcoded_secrets(plugin_dir: Path) -> CheckResult:
    findings: list[str] = []
    for fpath in _scan_all_files(plugin_dir):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(content):
                findings.append(str(fpath.relative_to(plugin_dir)))
                break
    if not findings:
        return CheckResult(
            name="No hardcoded secrets", passed=True, points=7, max_points=7, message="No hardcoded secrets detected"
        )
    shown = findings[:5]
    suffix = f" and {len(findings) - 5} more" if len(findings) > 5 else ""
    return CheckResult(
        name="No hardcoded secrets",
        passed=False,
        points=0,
        max_points=7,
        message=f"Hardcoded secrets found in: {', '.join(shown)}{suffix}",
        findings=tuple(
            Finding(
                rule_id="HARDCODED_SECRET",
                severity=Severity.HIGH,
                category="security",
                title="Hardcoded secret detected",
                description=f"Potential secret material was detected in {path}.",
                remediation="Remove the secret from source control and load it securely at runtime.",
                file_path=path,
            )
            for path in findings
        ),
    )


def check_no_dangerous_mcp(plugin_dir: Path) -> CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not mcp_path.exists():
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping check",
            applicable=False,
        )
    try:
        content = mcp_path.read_text(encoding="utf-8")
    except OSError:
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=0,
            max_points=0,
            message="Could not read .mcp.json",
            applicable=False,
        )
    found: list[str] = []
    for pattern in DANGEROUS_MCP_PATTERNS:
        if pattern.search(content):
            found.append(pattern.pattern)
    if not found:
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=4,
            max_points=4,
            message="No dangerous commands found in .mcp.json",
        )
    return CheckResult(
        name="No dangerous MCP commands",
        passed=False,
        points=0,
        max_points=4,
        message=f"Dangerous patterns in .mcp.json: {', '.join(found)}",
        findings=tuple(
            Finding(
                rule_id="DANGEROUS_MCP_COMMAND",
                severity=Severity.HIGH,
                category="security",
                title="Dangerous MCP command pattern detected",
                description=f'The MCP configuration matches the risky pattern "{pattern}".',
                remediation="Remove destructive commands and require explicit user approval before high-risk actions.",
                file_path=".mcp.json",
            )
            for pattern in found
        ),
    )


IGNORED_MCP_URL_CONTEXT = {"metadata", "description", "homepage", "website", "docs", "documentation"}
MCP_URL_KEYS = {"url", "endpoint", "server_url"}


def _collect_mcp_urls(node: object, urls: list[str], path: tuple[str, ...] = ()) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered_key = key.lower()
            next_path = (*path, lowered_key)
            if lowered_key in IGNORED_MCP_URL_CONTEXT:
                continue
            if isinstance(value, str) and lowered_key in MCP_URL_KEYS:
                urls.append(value)
                continue
            if isinstance(value, (dict, list)):
                _collect_mcp_urls(value, urls, next_path)
        return
    if isinstance(node, list):
        for item in node:
            _collect_mcp_urls(item, urls, path)


def _extract_mcp_urls(payload: object) -> list[str]:
    urls: list[str] = []
    if isinstance(payload, dict):
        targeted = False
        for key in ("mcpServers", "servers"):
            value = payload.get(key)
            if isinstance(value, (dict, list)):
                targeted = True
                _collect_mcp_urls(value, urls, (key.lower(),))
        if targeted:
            return urls
    _collect_mcp_urls(payload, urls)
    return urls


def _is_loopback_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def check_mcp_transport_security(plugin_dir: Path) -> CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not mcp_path.exists():
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping transport hardening checks.",
            applicable=False,
        )

    try:
        payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    except Exception:
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=False,
            points=0,
            max_points=4,
            message="Could not parse .mcp.json for transport URLs.",
            findings=(
                Finding(
                    rule_id="MCP_CONFIG_INVALID_JSON",
                    severity=Severity.MEDIUM,
                    category="security",
                    title="MCP configuration is not valid JSON",
                    description="The .mcp.json file exists but could not be parsed.",
                    remediation="Fix the .mcp.json syntax so transport settings can be validated.",
                    file_path=".mcp.json",
                ),
            ),
        )

    urls = _extract_mcp_urls(payload)
    if not urls:
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No remote MCP URLs declared; stdio-only configuration is not applicable here.",
            applicable=False,
        )

    issues = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            continue
        if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
            continue
        issues.append(url)

    if not issues:
        return CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=4,
            max_points=4,
            message="Remote MCP URLs use hardened transports or stay on loopback for local development.",
        )

    return CheckResult(
        name="MCP remote transports are hardened",
        passed=False,
        points=0,
        max_points=4,
        message=f"Insecure MCP remote URLs detected: {', '.join(issues)}",
        findings=tuple(
            Finding(
                rule_id="MCP_REMOTE_URL_INSECURE",
                severity=Severity.HIGH,
                category="security",
                title="MCP remote transport uses an insecure URL",
                description=f'The remote MCP endpoint "{url}" is not HTTPS or loopback-only HTTP.',
                remediation="Use HTTPS for remote MCP servers and reserve plain HTTP for localhost development only.",
                file_path=".mcp.json",
            )
            for url in issues
        ),
    )


def check_no_approval_bypass_defaults(plugin_dir: Path) -> CheckResult:
    findings: list[str] = []
    for file_path in _scan_all_files(plugin_dir):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not file_path.name.endswith((".json", ".md", ".yaml", ".yml", ".toml")):
            continue
        if any(pattern.search(content) for pattern in RISKY_APPROVAL_PATTERNS):
            findings.append(str(file_path.relative_to(plugin_dir)))

    if not findings:
        return CheckResult(
            name="No approval bypass defaults",
            passed=True,
            points=3,
            max_points=3,
            message="No risky approval or sandbox defaults detected.",
        )

    return CheckResult(
        name="No approval bypass defaults",
        passed=False,
        points=0,
        max_points=3,
        message=f"Risky approval defaults found in: {', '.join(findings)}",
        findings=tuple(
            Finding(
                rule_id="RISKY_APPROVAL_DEFAULT",
                severity=Severity.MEDIUM,
                category="security",
                title="Risky approval or sandbox default detected",
                description=f"{path} contains a dangerous approval or sandbox default.",
                remediation=(
                    "Avoid shipping configurations that default to bypassed approvals or unrestricted sandboxes."
                ),
                file_path=path,
            )
            for path in findings
        ),
    )


def run_security_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_security_md(plugin_dir),
        check_license(plugin_dir),
        check_no_hardcoded_secrets(plugin_dir),
        check_no_dangerous_mcp(plugin_dir),
        check_mcp_transport_security(plugin_dir),
        check_no_approval_bypass_defaults(plugin_dir),
    )
