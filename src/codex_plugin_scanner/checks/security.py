"""Security checks (20 points)."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from urllib.parse import urlparse

from ..models import CheckResult, Finding, Severity
from ..path_support import resolves_within_root


@dataclass(frozen=True, slots=True)
class SecretPattern:
    pattern: re.Pattern[str]
    kind: str = "provider"
    value_group: int = 0


# Patterns for hardcoded secrets
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern(re.compile(r"aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", re.I), value_group=1),
    SecretPattern(
        re.compile(
            r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----"
            r"[\s\S]{32,}?"
            r"-----END (?P=label)-----"
        ),
        kind="private_key",
    ),
    SecretPattern(re.compile(r"password\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"secret\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"token\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"api_?key\s*[=:]\s*[\"']([^\s\"']{8,})", re.I), kind="generic", value_group=1),
    SecretPattern(re.compile(r"API_KEY\s*[=:]\s*[\"']([^\s\"']{8,})"), kind="generic", value_group=1),
    SecretPattern(re.compile(r"PRIVATE_KEY\s*[=:]\s*[\"']([^\s\"']{8,})"), kind="generic", value_group=1),
    SecretPattern(re.compile(r"ghp_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"gho_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"ghu_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"ghs_[A-Za-z0-9]{36}")),
    SecretPattern(re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    SecretPattern(re.compile(r"glpat-[A-Za-z0-9\-]{20}")),
    SecretPattern(re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xoxe-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xoxr-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"xapp-[A-Za-z0-9\-]{10,}")),
    SecretPattern(re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
)

EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__pycache__", ".venv", "venv"}

DOCUMENTATION_EXTS = {".md", ".mdx", ".markdown", ".rst", ".adoc", ".asciidoc"}
EXAMPLE_PATH_HINTS = {
    "docs",
    "doc",
    "skills",
    "skill",
    "prompts",
    "prompt",
    "instructions",
    "instruction",
    "examples",
    "example",
    "samples",
    "sample",
    "guides",
    "guide",
    "tutorials",
    "tutorial",
    "rules",
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "fixture",
}
TEST_FILE_RE = re.compile(r"(^test_.*|.*(?:\.test|\.spec)\.[^.]+$|.*_test\.[^.]+$)", re.I)
PLACEHOLDER_MARKERS = (
    "redacted",
    "changeme",
    "set-at-runtime",
    "set_at_runtime",
)
EXAMPLE_GENERIC_VALUES = {
    "admin123",
    "adminpass123",
    "mypassword123",
    "password123",
    "secret-value",
    "secure123",
    "securep@ss1",
    "testpass123",
}
ILLUSTRATIVE_PATH_HINTS = {"commands", "examples", "prompts", "rules", "skills"}
ILLUSTRATIVE_CONTEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:assert|fixture|mock|pytest|test\(|writeandstage|detectsecrets)\b", re.I),
    re.compile(r"\b(?:example|sample|demo|bad|wrong|good|correct|never|always)\b", re.I),
    re.compile(r"hardcoded secret|in source code|environment variable|env var|set via|\.env", re.I),
)
PROVIDER_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"^AKIA(?P<payload>[0-9A-Z]+)$"), 16),
    (re.compile(r"^(?:ghp_|gho_|ghu_|ghs_)(?P<payload>[A-Za-z0-9]+)$"), 36),
    (re.compile(r"^github_pat_(?P<payload>[A-Za-z0-9_]+)$"), 20),
    (re.compile(r"^glpat-(?P<payload>[A-Za-z0-9\-]+)$"), 20),
    (re.compile(r"^(?:xox[bpas]-|xoxe-|xoxr-|xapp-)(?P<payload>[A-Za-z0-9\-]+)$"), 10),
    (re.compile(r"^sk-(?:proj-|ant-)?(?P<payload>[A-Za-z0-9_-]+)$"), 20),
)
PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----")
PRIVATE_KEY_FOOTER_TEMPLATE = "-----END {label}-----"

BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
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

APACHE_LICENSE_VERSION_RE = re.compile(r"apache\s+license\s*,?\s*version\s+2\.0", re.I)
LICENSE_URL_RE = re.compile(r"https?://[^\s<>()\"']+")


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
        if not resolves_within_root(plugin_dir, p, require_exists=True):
            continue
        files.append(p)
    return files


def _is_example_surface(relative_path: Path) -> bool:
    path_parts = {part.lower() for part in relative_path.parts}
    return (
        relative_path.suffix.lower() in DOCUMENTATION_EXTS
        or bool(path_parts & EXAMPLE_PATH_HINTS)
        or bool(TEST_FILE_RE.search(relative_path.name))
    )


def _extract_secret_candidate(detector: SecretPattern, match: re.Match[str]) -> str:
    return match.group(detector.value_group).strip()


def _normalize_secret_candidate(value: str) -> str:
    normalized = value.strip().strip("\"'`")
    if normalized.lower().startswith("bearer "):
        normalized = normalized[7:].strip()
    return normalized


def _looks_like_placeholder_secret(value: str) -> bool:
    normalized = _normalize_secret_candidate(value)
    lowered = normalized.lower()
    if not normalized:
        return True
    if normalized.startswith(("${", "{{", "<", "[")):
        return True
    if "..." in normalized or "…" in normalized:
        return True
    if lowered.startswith(("your-", "your_", "your", "example-", "sample-", "demo-")):
        return True
    if lowered.endswith(("-here", "_here", "example", "sample")):
        return True
    if lowered in PLACEHOLDER_MARKERS:
        return True
    return bool(re.search(r"(?i)(?:^|[-_])(x{4,}|\*{3,})(?:[-_]|$)", normalized))


def _normalized_alnum(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _normalize_secret_candidate(value).lower())


def _ascending_run_stats(value: str) -> tuple[int, int]:
    if not value:
        return 0, 0
    longest = 1
    current = 1
    coverage = 0
    for previous, token in pairwise(value):
        if ord(token) == ord(previous) + 1:
            current += 1
            longest = max(longest, current)
        else:
            if current >= 4:
                coverage += current
            current = 1
    if current >= 4:
        coverage += current
    return longest, coverage


def _provider_payload(value: str) -> tuple[str, int] | None:
    normalized = _normalize_secret_candidate(value)
    for pattern, minimum_length in PROVIDER_PREFIX_PATTERNS:
        match = pattern.fullmatch(normalized)
        if match:
            return match.group("payload"), minimum_length
    return None


def _looks_like_synthetic_provider_candidate(value: str) -> bool:
    provider_payload = _provider_payload(value)
    if provider_payload is None:
        return False
    payload, _minimum_length = provider_payload
    normalized = _normalized_alnum(payload)
    if len(normalized) < 8:
        return False
    longest_run, coverage = _ascending_run_stats(normalized)
    return longest_run >= 8 and coverage / len(normalized) >= 0.6


def _looks_like_incomplete_provider_candidate(value: str) -> bool:
    provider_payload = _provider_payload(value)
    if provider_payload is None:
        return False
    payload, minimum_length = provider_payload
    normalized = _normalized_alnum(payload)
    return len(normalized) < minimum_length


def _looks_like_example_generic_secret(value: str) -> bool:
    normalized = _normalize_secret_candidate(value).lower()
    return normalized in EXAMPLE_GENERIC_VALUES


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _has_illustrative_context(relative_path: Path, content: str, offset: int) -> bool:
    if {part.lower() for part in relative_path.parts} & ILLUSTRATIVE_PATH_HINTS:
        return True
    lines = content.splitlines()
    line_number = _line_number_for_offset(content, offset)
    start = max(0, line_number - 3)
    end = min(len(lines), line_number + 2)
    context = "\n".join(lines[start:end])
    return any(pattern.search(context) for pattern in ILLUSTRATIVE_CONTEXT_PATTERNS)


def _private_key_looks_like_placeholder(body_lines: list[str]) -> bool:
    body_text = "\n".join(body_lines)
    if _looks_like_placeholder_secret(body_text):
        return True
    placeholder_lines = {"mii...", "[redacted]", "redacted", "secret-key-material"}
    lowered_lines = [line.lower() for line in body_lines]
    return any(line in placeholder_lines or "redacted" in line for line in lowered_lines)


def _extract_inline_private_key_body(line: str, header: str) -> list[str]:
    header_index = line.find(header)
    if header_index == -1:
        return []
    tail = line[header_index + len(header) :]
    if "\\n" not in tail:
        return []
    body_lines: list[str] = []
    for fragment in tail.split("\\n")[1:]:
        cleaned = fragment.strip().strip("\"'`),;}]")
        if cleaned:
            body_lines.append(cleaned)
    return body_lines


def _first_private_key_line(relative_path: Path, content: str) -> int | None:
    lines = content.splitlines()
    example_surface = _is_example_surface(relative_path)
    for match in PRIVATE_KEY_HEADER_RE.finditer(content):
        line_number = _line_number_for_offset(content, match.start())
        label = match.group("label")
        footer = PRIVATE_KEY_FOOTER_TEMPLATE.format(label=label)
        header = match.group(0)
        body_lines = _extract_inline_private_key_body(lines[line_number - 1], header)
        has_footer = False
        for candidate_line in lines[line_number:]:
            stripped = candidate_line.strip()
            if not stripped:
                if body_lines:
                    break
                continue
            if stripped == footer:
                has_footer = True
                break
            if stripped.startswith("-----END ") or stripped.startswith("-----BEGIN ") or stripped == "```":
                break
            body_lines.append(stripped)
        if not body_lines:
            continue
        body_text = "".join(body_lines)
        if example_surface and _private_key_looks_like_placeholder(body_lines):
            continue
        if len(body_text) >= 32:
            return line_number
        if has_footer:
            return line_number
    return None


def _should_skip_secret_match(relative_path: Path, content: str, detector: SecretPattern, match: re.Match[str]) -> bool:
    candidate = _extract_secret_candidate(detector, match)
    if not _is_example_surface(relative_path):
        return False
    if _looks_like_placeholder_secret(candidate):
        return True
    effective_kind = detector.kind
    if effective_kind == "generic" and _provider_payload(candidate) is not None:
        effective_kind = "provider"
    if effective_kind == "generic":
        return _looks_like_example_generic_secret(candidate)
    if effective_kind == "provider":
        if not _has_illustrative_context(relative_path, content, match.start()):
            return False
        return _looks_like_synthetic_provider_candidate(candidate) or _looks_like_incomplete_provider_candidate(
            candidate
        )
    return False


def _first_hardcoded_secret_line(relative_path: Path, content: str) -> int | None:
    first_line = _first_private_key_line(relative_path, content)
    for detector in SECRET_PATTERNS:
        if detector.kind == "private_key":
            continue
        for match in detector.pattern.finditer(content):
            if _should_skip_secret_match(relative_path, content, detector, match):
                continue
            line_number = _line_number_for_offset(content, match.start())
            if first_line is None or line_number < first_line:
                first_line = line_number
    return first_line


def _has_canonical_apache_license_reference(content: str) -> bool:
    for candidate in LICENSE_URL_RE.findall(content):
        parsed = urlparse(candidate.rstrip(".,;:"))
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        if hostname == "www.apache.org" and path == "/licenses/LICENSE-2.0":
            return True
    return False


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
        if "apache" in content.lower() and (
            APACHE_LICENSE_VERSION_RE.search(content) or _has_canonical_apache_license_reference(content)
        ):
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
    findings: list[tuple[str, int]] = []
    for fpath in _scan_all_files(plugin_dir):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative_path = fpath.relative_to(plugin_dir)
        line_number = _first_hardcoded_secret_line(relative_path, content)
        if line_number is not None:
            findings.append((relative_path.as_posix(), line_number))
    if not findings:
        return CheckResult(
            name="No hardcoded secrets", passed=True, points=7, max_points=7, message="No hardcoded secrets detected"
        )
    shown = [path for path, _line_number in findings[:5]]
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
                line_number=line_number,
            )
            for path, line_number in findings
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
