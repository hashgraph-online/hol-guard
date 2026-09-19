"""MCP command and remote transport security checks."""

from __future__ import annotations


def check_no_dangerous_mcp(plugin_dir: _security.Path) -> _security.CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not _security.path_entry_exists(mcp_path):
        return _security.CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping check",
            applicable=False,
        )
    try:
        content = _security.read_text_file_within_root(
            plugin_dir.resolve(strict=True),
            mcp_path,
            max_bytes=_security.MAX_SCAN_FILE_BYTES,
        )
    except (OSError, UnicodeError):
        return _security.CheckResult(
            name="No dangerous MCP commands",
            passed=False,
            points=0,
            max_points=4,
            message="Could not safely read .mcp.json",
            findings=(
                _security.Finding(
                    rule_id="MCP_CONFIG_UNREADABLE",
                    severity=_security.Severity.MEDIUM,
                    category="security",
                    title="MCP configuration could not be safely read",
                    description="The MCP configuration is not a bounded regular file inside the plugin.",
                    remediation="Replace links or special files with a regular, repository-contained .mcp.json file.",
                    file_path=".mcp.json",
                ),
            ),
        )
    found: list[str] = []
    for pattern in _security.DANGEROUS_MCP_PATTERNS:
        if pattern.search(content):
            found.append(pattern.pattern)
    if not found:
        return _security.CheckResult(
            name="No dangerous MCP commands",
            passed=True,
            points=4,
            max_points=4,
            message="No dangerous commands found in .mcp.json",
        )
    return _security.CheckResult(
        name="No dangerous MCP commands",
        passed=False,
        points=0,
        max_points=4,
        message=f"Dangerous patterns in .mcp.json: {', '.join(found)}",
        findings=tuple(
            _security.Finding(
                rule_id="DANGEROUS_MCP_COMMAND",
                severity=_security.Severity.HIGH,
                category="security",
                title="Dangerous MCP command pattern detected",
                description=f'The MCP configuration matches the risky pattern "{pattern}".',
                remediation="Remove destructive commands and require explicit user approval before high-risk actions.",
                file_path=".mcp.json",
            )
            for pattern in found
        ),
    )


def _collect_mcp_urls(node: object, urls: list[str], path: tuple[str, ...] = ()) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered_key = key.lower()
            next_path = (*path, lowered_key)
            if lowered_key in _security.IGNORED_MCP_URL_CONTEXT:
                continue
            if isinstance(value, str) and lowered_key in _security.MCP_URL_KEYS:
                urls.append(value)
                continue
            if isinstance(value, (dict, list)):
                _security._collect_mcp_urls(value, urls, next_path)
        return
    if isinstance(node, list):
        for item in node:
            _security._collect_mcp_urls(item, urls, path)


def _extract_mcp_urls(payload: object) -> list[str]:
    urls: list[str] = []
    if isinstance(payload, dict):
        targeted = False
        for key in ("mcpServers", "servers"):
            value = payload.get(key)
            if isinstance(value, (dict, list)):
                targeted = True
                _security._collect_mcp_urls(value, urls, (key.lower(),))
        if targeted:
            return urls
    _security._collect_mcp_urls(payload, urls)
    return urls


def _is_loopback_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname == "localhost":
        return True
    try:
        return _security.ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def check_mcp_transport_security(plugin_dir: _security.Path) -> _security.CheckResult:
    mcp_path = plugin_dir / ".mcp.json"
    if not _security.path_entry_exists(mcp_path):
        return _security.CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No .mcp.json found, skipping transport hardening checks.",
            applicable=False,
        )

    try:
        payload = _security.json.loads(
            _security.read_text_file_within_root(
                plugin_dir.resolve(strict=True),
                mcp_path,
                max_bytes=_security.MAX_SCAN_FILE_BYTES,
            )
        )
    except (_security.json.JSONDecodeError, OSError, UnicodeError, ValueError):
        return _security.CheckResult(
            name="MCP remote transports are hardened",
            passed=False,
            points=0,
            max_points=4,
            message="Could not parse .mcp.json for transport URLs.",
            findings=(
                _security.Finding(
                    rule_id="MCP_CONFIG_INVALID_JSON",
                    severity=_security.Severity.MEDIUM,
                    category="security",
                    title="MCP configuration is not valid JSON",
                    description="The .mcp.json file exists but could not be parsed.",
                    remediation="Fix the .mcp.json syntax so transport settings can be validated.",
                    file_path=".mcp.json",
                ),
            ),
        )

    urls = _security._extract_mcp_urls(payload)
    if not urls:
        return _security.CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=0,
            max_points=0,
            message="No remote MCP URLs declared; stdio-only configuration is not applicable here.",
            applicable=False,
        )

    issues = []
    for url in urls:
        parsed = _security.urlparse(url)
        if parsed.scheme == "https":
            continue
        if parsed.scheme == "http" and _security._is_loopback_host(parsed.hostname):
            continue
        issues.append(url)

    if not issues:
        return _security.CheckResult(
            name="MCP remote transports are hardened",
            passed=True,
            points=4,
            max_points=4,
            message="Remote MCP URLs use hardened transports or stay on loopback for local development.",
        )

    return _security.CheckResult(
        name="MCP remote transports are hardened",
        passed=False,
        points=0,
        max_points=4,
        message=f"Insecure MCP remote URLs detected: {', '.join(issues)}",
        findings=tuple(
            _security.Finding(
                rule_id="MCP_REMOTE_URL_INSECURE",
                severity=_security.Severity.HIGH,
                category="security",
                title="MCP remote transport uses an insecure URL",
                description=f'The remote MCP endpoint "{url}" is not HTTPS or loopback-only HTTP.',
                remediation="Use HTTPS for remote MCP servers and reserve plain HTTP for localhost development only.",
                file_path=".mcp.json",
            )
            for url in issues
        ),
    )


# Bind after definitions so either the facade or this helper can be imported first.
from . import security as _security  # noqa: E402
