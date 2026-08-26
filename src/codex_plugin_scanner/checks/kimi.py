"""Kimi Code plugin manifest and declared-bundle checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity
from ..path_support import is_safe_relative_path
from .code_quality import check_no_eval, check_no_shell_injection
from .kimi_support import looks_like_path, manifest_label, object_sequence
from .security import (
    DANGEROUS_MCP_PATTERNS,
    check_license,
    check_no_approval_bypass_defaults,
    check_no_hardcoded_secrets,
    check_security_md,
)

KIMI_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
KIMI_SEMVER_RE = re.compile(
    "".join(
        (
            r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)",
            r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?",
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
        )
    )
)
SHELL_INTERPRETERS = frozenset({"bash", "cmd", "dash", "fish", "ksh", "powershell", "pwsh", "sh", "zsh"})
KIMI_MANIFEST_PATHS = ("skills", "agents", "commands")
UNSUPPORTED_RUNTIME_FIELDS = ("tools", "apps", "inject", "configFile")


def _finding(
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    package: NormalizedPackage,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="kimi",
        title=title,
        description=description,
        remediation=remediation,
        file_path=manifest_label(package),
    )


def _path_values(value: object) -> tuple[str, ...] | None:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        items = cast(list[object], value)
        if all(isinstance(item, str) for item in items):
            return tuple(cast(str, item) for item in items)
    return None


def _string_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return {cast(str, key): item for key, item in mapping.items()}


def check_kimi_manifest(package: NormalizedPackage) -> CheckResult:
    if package.manifest_parse_error:
        reason = package.manifest_parse_error_reason or "invalid-json"
        return CheckResult(
            name="Kimi manifest parses",
            passed=False,
            points=0,
            max_points=5,
            message=f"Kimi manifest could not be parsed: {reason}.",
            findings=(
                _finding(
                    "KIMI_MANIFEST_INVALID",
                    "Kimi plugin manifest is invalid",
                    f"The Kimi manifest could not be parsed: {reason}.",
                    "Provide a readable JSON object in kimi.plugin.json or .kimi-plugin/plugin.json.",
                    package,
                ),
            ),
        )
    name = package.raw_manifest.get("name")
    version = package.raw_manifest.get("version")
    findings: list[Finding] = []
    if not isinstance(name, str) or not KIMI_NAME_RE.fullmatch(name):
        findings.append(
            _finding(
                "KIMI_NAME_INVALID",
                "Kimi plugin name is invalid",
                "Kimi plugin names must match [a-z0-9][a-z0-9_-]{0,63}.",
                "Set name to a valid Kimi plugin id.",
                package,
            )
        )
    if version is not None and (not isinstance(version, str) or not KIMI_SEMVER_RE.fullmatch(version)):
        findings.append(
            _finding(
                "KIMI_VERSION_INVALID",
                "Kimi plugin version is invalid",
                "When present, the Kimi plugin version must use X.Y.Z semantic versioning.",
                "Set version to a semantic version or remove it.",
                package,
                Severity.LOW,
            )
        )
    if not findings:
        return CheckResult("Kimi manifest parses", True, 5, 5, "Kimi manifest and plugin identity are valid.")
    return CheckResult("Kimi manifest parses", False, 0, 5, f"Kimi manifest issues: {len(findings)}", tuple(findings))


def check_kimi_declared_paths(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    findings: list[Finding] = []
    for field in KIMI_MANIFEST_PATHS:
        value = manifest.get(field)
        if value is None:
            continue
        paths = _path_values(value)
        if paths is None:
            findings.append(
                _finding(
                    "KIMI_PATHS_INVALID",
                    f"Kimi {field} paths are invalid",
                    f"{field} must be a ./ path or an array of ./ paths.",
                    f"Update {field} to use in-plugin paths.",
                    package,
                )
            )
            continue
        for value_path in paths:
            if not is_safe_relative_path(package.root_path, value_path, require_prefix=True, require_exists=True):
                findings.append(
                    _finding(
                        "KIMI_PATH_UNSAFE_OR_MISSING",
                        f"Kimi {field} path is unsafe or missing",
                        f'{field} path "{value_path}" must resolve inside the plugin and exist.',
                        f"Use an existing ./ path within the plugin for {field}.",
                        package,
                    )
                )
                continue
            target = package.root_path / value_path
            if target.is_symlink():
                findings.append(
                    _finding(
                        "KIMI_PATH_SYMLINK_UNSUPPORTED",
                        f"Kimi {field} path is a symlink",
                        f'{field} path "{value_path}" must not be a symlink.',
                        f"Use a regular in-plugin path for {field}.",
                        package,
                    )
                )
                continue
            if field in {"agents", "commands"} and target.is_file() and target.suffix.lower() != ".md":
                findings.append(
                    _finding(
                        "KIMI_MARKDOWN_PATH_INVALID",
                        f"Kimi {field} file is not Markdown",
                        f'{field} path "{value_path}" must be a directory or .md file.',
                        f"Point {field} to a directory or Markdown file.",
                        package,
                        Severity.LOW,
                    )
                )
    system_prompt_path = manifest.get("systemPromptPath")
    system_prompt_target = package.root_path / system_prompt_path if isinstance(system_prompt_path, str) else None
    system_prompt_is_safe = isinstance(system_prompt_path, str) and is_safe_relative_path(
        package.root_path, system_prompt_path, require_prefix=True, require_exists=True
    )
    if system_prompt_path is not None and (
        system_prompt_target is None
        or not system_prompt_is_safe
        or not system_prompt_target.is_file()
        or system_prompt_target.is_symlink()
    ):
        findings.append(
            _finding(
                "KIMI_SYSTEM_PROMPT_PATH_INVALID",
                "Kimi system prompt path is invalid",
                "systemPromptPath must reference an existing ./ file inside the plugin.",
                "Use an existing in-plugin UTF-8 text file.",
                package,
            )
        )
    if not findings:
        return CheckResult("Kimi declared paths resolve", True, 5, 5, "Kimi bundle paths stay inside the plugin.")
    return CheckResult(
        "Kimi declared paths resolve", False, 0, 5, f"Kimi path issues: {len(findings)}", tuple(findings)
    )


def check_kimi_manifest_shapes(package: NormalizedPackage) -> CheckResult:
    manifest = package.raw_manifest
    findings: list[Finding] = []
    interface = manifest.get("interface")
    interface_mapping = _string_mapping(interface)
    if interface is not None and (
        interface_mapping is None or not all(isinstance(value, str) for value in interface_mapping.values())
    ):
        findings.append(
            _finding(
                "KIMI_INTERFACE_INVALID",
                "Kimi interface metadata is invalid",
                "interface must be an object containing string display metadata.",
                "Use string values for Kimi interface metadata.",
                package,
                Severity.LOW,
            )
        )
    session_start = manifest.get("sessionStart")
    session_start_mapping = _string_mapping(session_start)
    if session_start is not None and (
        session_start_mapping is None or not isinstance(session_start_mapping.get("skill"), str)
    ):
        findings.append(
            _finding(
                "KIMI_SESSION_START_INVALID",
                "Kimi sessionStart is invalid",
                "sessionStart must be an object with a string skill field.",
                "Reference a declared plugin skill by name.",
                package,
                Severity.LOW,
            )
        )
    system_prompt = manifest.get("systemPrompt")
    if system_prompt is not None and (
        not isinstance(system_prompt, str) or len(system_prompt.encode("utf-8")) > 32 * 1024
    ):
        findings.append(
            _finding(
                "KIMI_SYSTEM_PROMPT_INVALID",
                "Kimi system prompt is invalid",
                "systemPrompt must be a UTF-8 string no larger than 32 KiB.",
                "Shorten or remove the inline system prompt.",
                package,
                Severity.LOW,
            )
        )
    unsupported = [field for field in UNSUPPORTED_RUNTIME_FIELDS if field in manifest]
    if unsupported:
        findings.append(
            _finding(
                "KIMI_UNSUPPORTED_RUNTIME_FIELDS",
                "Kimi manifest contains unsupported runtime fields",
                f"Kimi ignores these runtime fields: {', '.join(unsupported)}.",
                "Remove fields that Kimi Code ignores.",
                package,
                Severity.LOW,
            )
        )
    if not findings:
        return CheckResult("Kimi manifest field shapes", True, 4, 4, "Kimi manifest field shapes are valid.")
    return CheckResult(
        "Kimi manifest field shapes", False, 0, 4, f"Kimi field-shape issues: {len(findings)}", tuple(findings)
    )


def check_kimi_mcp_servers(package: NormalizedPackage) -> CheckResult:
    raw_servers = package.raw_manifest.get("mcpServers")
    if raw_servers is None:
        return CheckResult("Kimi MCP servers", True, 0, 0, "No Kimi MCP servers declared.", applicable=False)
    servers = _string_mapping(raw_servers)
    if servers is None:
        finding = _finding(
            "KIMI_MCP_SERVERS_INVALID",
            "Kimi MCP servers are invalid",
            "mcpServers must be an object keyed by server name.",
            "Use an object for Kimi MCP server declarations.",
            package,
        )
        return CheckResult("Kimi MCP servers", False, 0, 5, finding.description, (finding,))

    findings: list[Finding] = []
    for name, server_value in servers.items():
        server = _string_mapping(server_value)
        if server is None:
            findings.append(
                _finding(
                    "KIMI_MCP_SERVER_INVALID",
                    "Kimi MCP server entry is invalid",
                    "Each mcpServers entry must have a string name and object value.",
                    "Use an object-shaped MCP server declaration.",
                    package,
                )
            )
            continue
        command = server.get("command")
        url = server.get("url")
        if (isinstance(command, str)) == (isinstance(url, str)):
            findings.append(
                _finding(
                    "KIMI_MCP_TRANSPORT_INVALID",
                    "Kimi MCP transport is ambiguous",
                    f'MCP server "{name}" must declare exactly one of command or url.',
                    "Choose one supported MCP transport.",
                    package,
                )
            )
            continue
        if isinstance(command, str):
            raw_args = object_sequence(server.get("args")) or []
            joined = " ".join([command, *[item for item in raw_args if isinstance(item, str)]])
            command_name = Path(command).name.lower()
            launches_shell_code = command_name in SHELL_INTERPRETERS and any(
                item.lower() in {"-c", "/c", "-command"} for item in raw_args if isinstance(item, str)
            )
            if launches_shell_code or any(pattern.search(joined) for pattern in DANGEROUS_MCP_PATTERNS):
                findings.append(
                    _finding(
                        "KIMI_MCP_COMMAND_DANGEROUS",
                        "Kimi MCP command is dangerous",
                        f'MCP server "{name}" uses a dangerous shell command pattern.',
                        "Use a structured executable and argument list without shell indirection.",
                        package,
                        Severity.HIGH,
                    )
                )
            command_is_path = looks_like_path(command)
            if command_is_path and not command.startswith("./"):
                findings.append(
                    _finding(
                        "KIMI_MCP_COMMAND_PATH_INVALID",
                        "Kimi MCP command path is invalid",
                        f'MCP server "{name}" path-like command must use an in-plugin ./ path.',
                        "Use a bare executable name or existing in-plugin executable path.",
                        package,
                    )
                )
            elif command.startswith("./") and not is_safe_relative_path(
                package.root_path, command, require_prefix=True, require_exists=True
            ):
                findings.append(
                    _finding(
                        "KIMI_MCP_COMMAND_PATH_INVALID",
                        "Kimi MCP command path is invalid",
                        f'MCP server "{name}" command must remain inside the plugin.',
                        "Use an existing in-plugin executable path.",
                        package,
                    )
                )
            elif command.startswith("./") and (package.root_path / command).is_symlink():
                findings.append(
                    _finding(
                        "KIMI_MCP_COMMAND_SYMLINK_UNSUPPORTED",
                        "Kimi MCP command path is a symlink",
                        f'MCP server "{name}" command must not be a symlink.',
                        "Use a regular in-plugin executable file.",
                        package,
                    )
                )
            elif command.startswith("./") and not (package.root_path / command).is_file():
                findings.append(
                    _finding(
                        "KIMI_MCP_COMMAND_NOT_FILE",
                        "Kimi MCP command is not a file",
                        f'MCP server "{name}" command must reference an executable file.',
                        "Point command to an in-plugin executable file.",
                        package,
                    )
                )
        if isinstance(url, str):
            parsed = urlparse(url)
            loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            secure_remote = parsed.scheme == "https" and parsed.hostname is not None
            secure_loopback = parsed.scheme == "http" and loopback
            has_credentials = parsed.username is not None or parsed.password is not None
            if not (secure_remote or secure_loopback) or has_credentials or bool(parsed.fragment):
                findings.append(
                    _finding(
                        "KIMI_MCP_URL_INSECURE",
                        "Kimi MCP URL is insecure",
                        f'MCP server "{name}" must use HTTPS unless it is loopback-only.',
                        "Use HTTPS for remote MCP servers.",
                        package,
                        Severity.HIGH,
                    )
                )
        args = server.get("args")
        env = server.get("env")
        args_sequence = object_sequence(args)
        if args is not None and (args_sequence is None or not all(isinstance(item, str) for item in args_sequence)):
            findings.append(
                _finding(
                    "KIMI_MCP_ARGS_INVALID",
                    "Kimi MCP args are invalid",
                    f'MCP server "{name}" args must be an array of strings.',
                    "Use string arguments.",
                    package,
                )
            )
        if args_sequence is not None:
            for arg in args_sequence:
                if not isinstance(arg, str) or not looks_like_path(arg):
                    continue
                if not arg.startswith("./"):
                    findings.append(
                        _finding(
                            "KIMI_MCP_ARG_PATH_INVALID",
                            "Kimi MCP argument path is unsafe",
                            f'MCP server "{name}" path-like argument "{arg}" must use an in-plugin ./ path.',
                            "Use an existing regular in-plugin path for local MCP arguments.",
                            package,
                        )
                    )
                    continue
                arg_target = package.root_path / arg
                if (
                    not is_safe_relative_path(package.root_path, arg, require_prefix=True, require_exists=True)
                    or arg_target.is_symlink()
                ):
                    detail = f'MCP server "{name}" local argument "{arg}" must exist inside the plugin '
                    detail += "and not be a symlink."
                    findings.append(
                        _finding(
                            "KIMI_MCP_ARG_PATH_INVALID",
                            "Kimi MCP argument path is unsafe",
                            detail,
                            "Use a regular in-plugin path for local MCP arguments.",
                            package,
                        )
                    )
        env_mapping = _string_mapping(env)
        if env is not None and (
            env_mapping is None or not all(isinstance(value, str) for value in env_mapping.values())
        ):
            findings.append(
                _finding(
                    "KIMI_MCP_ENV_INVALID",
                    "Kimi MCP environment is invalid",
                    f'MCP server "{name}" env must map string names to string values.',
                    "Use string environment values.",
                    package,
                )
            )
        cwd = server.get("cwd")
        cwd_target = package.root_path / cwd if isinstance(cwd, str) else None
        cwd_is_safe = isinstance(cwd, str) and is_safe_relative_path(
            package.root_path, cwd, require_prefix=True, require_exists=True
        )
        if cwd is not None and (
            cwd_target is None or not cwd_is_safe or cwd_target.is_symlink() or not cwd_target.is_dir()
        ):
            findings.append(
                _finding(
                    "KIMI_MCP_CWD_INVALID",
                    "Kimi MCP working directory is invalid",
                    f'MCP server "{name}" cwd must be an existing ./ path inside the plugin.',
                    "Use an in-plugin working directory.",
                    package,
                )
            )

    if not findings:
        return CheckResult("Kimi MCP servers", True, 5, 5, "Kimi MCP server declarations are valid.")
    return CheckResult("Kimi MCP servers", False, 0, 5, f"Kimi MCP issues: {len(findings)}", tuple(findings))


def _bundle_files(package: NormalizedPackage) -> tuple[Path, ...]:
    relative_files = {
        relative
        for component, values in package.components.items()
        if component != "mcp_servers"
        for relative in values
    }
    if package.manifest_path is not None:
        relative_files.add(package.manifest_path.relative_to(package.root_path).as_posix())
    return tuple(sorted((package.root_path / relative for relative in relative_files), key=str))


def run_kimi_checks(package: NormalizedPackage) -> tuple[CheckResult, ...]:
    """Run Kimi schema, path, MCP, and declared-content checks."""

    files = _bundle_files(package)
    return (
        check_kimi_manifest(package),
        check_kimi_declared_paths(package),
        check_kimi_manifest_shapes(package),
        check_kimi_mcp_servers(package),
        check_security_md(package.root_path),
        check_license(package.root_path),
        check_no_hardcoded_secrets(package.root_path, files),
        check_no_approval_bypass_defaults(package.root_path, files),
        check_no_eval(package.root_path, files),
        check_no_shell_injection(package.root_path, files),
    )
