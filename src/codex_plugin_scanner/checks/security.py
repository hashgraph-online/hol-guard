"""Security checks (30 points)."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CheckResult

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
        points=5 if exists else 0,
        max_points=5,
        message="SECURITY.md found" if exists else "SECURITY.md not found",
    )


def check_license(plugin_dir: Path) -> CheckResult:
    lp = plugin_dir / "LICENSE"
    if not lp.exists():
        return CheckResult(name="LICENSE found", passed=False, points=0, max_points=5, message="LICENSE file not found")
    try:
        content = lp.read_text(encoding="utf-8", errors="ignore")
        if "Apache" in content and ("2.0" in content or "www.apache.org" in content):
            return CheckResult(
                name="LICENSE found", passed=True, points=5, max_points=5, message="LICENSE found (Apache-2.0)"
            )
        if "MIT" in content and "Permission is hereby granted" in content:
            return CheckResult(name="LICENSE found", passed=True, points=5, max_points=5, message="LICENSE found (MIT)")
        return CheckResult(
            name="LICENSE found", passed=True, points=5, max_points=5, message="LICENSE found (not Apache-2.0 or MIT)"
        )
    except OSError:
        return CheckResult(
            name="LICENSE found", passed=False, points=0, max_points=5, message="LICENSE exists but could not be read"
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
            name="No hardcoded secrets", passed=True, points=10, max_points=10, message="No hardcoded secrets detected"
        )
    shown = findings[:5]
    suffix = f" and {len(findings) - 5} more" if len(findings) > 5 else ""
    return CheckResult(
        name="No hardcoded secrets",
        passed=False,
        points=0,
        max_points=10,
        message=f"Hardcoded secrets found in: {', '.join(shown)}{suffix}",
    )


def check_no_dangerous_mcp(plugin_dir: Path) -> CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not mcp_path.exists():
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=10,
            max_points=10,
            message="No .mcp.json found, skipping check",
        )
    try:
        content = mcp_path.read_text(encoding="utf-8")
    except OSError:
        return CheckResult(
            name="No dangerous MCP commands", passed=True, points=10, max_points=10, message="Could not read .mcp.json"
        )
    found: list[str] = []
    for pattern in DANGEROUS_MCP_PATTERNS:
        if pattern.search(content):
            found.append(pattern.pattern)
    if not found:
        return CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=10,
            max_points=10,
            message="No dangerous commands found in .mcp.json",
        )
    return CheckResult(
        name="No dangerous MCP commands",
        passed=False,
        points=0,
        max_points=10,
        message=f"Dangerous patterns in .mcp.json: {', '.join(found)}",
    )


def run_security_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_security_md(plugin_dir),
        check_license(plugin_dir),
        check_no_hardcoded_secrets(plugin_dir),
        check_no_dangerous_mcp(plugin_dir),
    )
