"""Install command parsers through the live Protect facade."""

from __future__ import annotations


def parse_protect_command(command: list[str]) -> _protect.ProtectRequest:
    """Parse a package install or harness registration command."""

    executable = _protect.Path(command[0]).name.lower()
    handlers = {
        "npm": _protect._parse_npm_request,
        "pnpm": _protect._parse_pnpm_request,
        "yarn": _protect._parse_yarn_request,
        "pip": _protect._parse_pip_request,
        "pip3": _protect._parse_pip_request,
        "uv": _protect._parse_uv_request,
        "go": _protect._parse_go_request,
        "claude": _protect._parse_claude_request,
        "codex": _protect._parse_codex_request,
        "cursor": _protect._parse_cursor_request,
        "antigravity": _protect._parse_antigravity_request,
        "gemini": _protect._parse_gemini_request,
        "opencode": _protect._parse_opencode_request,
    }
    handler = handlers.get(executable, _protect._parse_custom_request)
    return handler(command)


def _parse_npm_request(command: list[str]) -> _protect.ProtectRequest:
    normalized_command = list(_protect.strip_package_manager_global_options(command))
    specs = (
        _protect._collect_package_specs(normalized_command[2:])
        if len(normalized_command) > 1 and normalized_command[1] in {"install", "add", "i"}
        else ()
    )
    return _protect._package_manager_request(command, "npm", specs)


def _parse_pnpm_request(command: list[str]) -> _protect.ProtectRequest:
    normalized_command = list(_protect.strip_package_manager_global_options(command))
    specs = (
        _protect._collect_package_specs(normalized_command[2:])
        if len(normalized_command) > 1 and normalized_command[1] in {"add", "install"}
        else ()
    )
    return _protect._package_manager_request(command, "pnpm", specs)


def _parse_yarn_request(command: list[str]) -> _protect.ProtectRequest:
    normalized_command = tuple(_protect.strip_package_manager_global_options(command))
    working_command = normalized_command
    if len(normalized_command) >= 4 and normalized_command[1] == "workspace":
        working_command = (normalized_command[0], *normalized_command[3:])
    specs = (
        _protect._collect_package_specs(list(working_command[2:]))
        if len(working_command) > 1 and working_command[1] == "add"
        else ()
    )
    return _protect._package_manager_request(command, "yarn", specs)


def _parse_pip_request(command: list[str]) -> _protect.ProtectRequest:
    normalized_command = list(_protect.strip_package_manager_global_options(command))
    specs = (
        _protect._collect_package_specs(normalized_command[2:])
        if len(normalized_command) > 1 and normalized_command[1] == "install"
        else ()
    )
    return _protect._package_manager_request(command, "pip", specs)


def _parse_uv_request(command: list[str]) -> _protect.ProtectRequest:
    normalized_command = list(_protect.strip_package_manager_global_options(command))
    specs = _protect._collect_uv_specs(normalized_command)
    return _protect._package_manager_request(command, "uv", specs)


def _parse_go_request(command: list[str]) -> _protect.ProtectRequest:
    specs = (
        _protect._collect_package_specs(command[2:]) if len(command) > 1 and command[1] in {"get", "install"} else ()
    )
    return _protect._package_manager_request(command, "go", specs)


def _parse_codex_request(command: list[str]) -> _protect.ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        target = _protect.ProtectTarget(
            artifact_id=f"install:codex:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="codex",
            package_name=name,
            package_url=None,
            raw_spec=name,
            version=None,
            source_url=_protect._option_value(command, "--url"),
            harness="codex",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "codex", None, "codex", (target,))
    return _protect._parse_custom_request(command)


def _parse_claude_request(command: list[str]) -> _protect.ProtectRequest:
    if len(command) >= 5 and command[1:3] == ["mcp", "add"]:
        positional = _protect._remaining_positionals(command[3:])
        if len(positional) < 2:
            return _protect._parse_custom_request(command)
        name = positional[0]
        command_or_url = positional[1]
        target = _protect.ProtectTarget(
            artifact_id=f"install:claude-code:mcp:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="claude-code",
            package_name=name,
            package_url=None,
            raw_spec=command_or_url,
            version=None,
            source_url=command_or_url if command_or_url.startswith(("http://", "https://")) else None,
            harness="claude-code",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "claude", None, "claude-code", (target,))
    if len(command) >= 5 and command[1:3] == ["mcp", "add-json"]:
        positional = _protect._remaining_positionals(command[3:])
        if len(positional) < 2:
            return _protect._parse_custom_request(command)
        name = positional[0]
        target = _protect._parse_claude_mcp_target(name, positional[1])
        return _protect.ProtectRequest(tuple(command), "harness_registration", "claude", None, "claude-code", (target,))
    return _protect._parse_custom_request(command)


def _parse_cursor_request(command: list[str]) -> _protect.ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        target = _protect.ProtectTarget(
            artifact_id=f"install:cursor:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="cursor",
            package_name=name,
            package_url=None,
            raw_spec=name,
            version=None,
            source_url=_protect._option_value(command, "--url"),
            harness="cursor",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "cursor", None, "cursor", (target,))
    return _protect._parse_custom_request(command)


def _parse_gemini_request(command: list[str]) -> _protect.ProtectRequest:
    if len(command) >= 4 and command[1:3] == ["extensions", "install"]:
        name = command[3]
        target = _protect.ProtectTarget(
            artifact_id=f"install:gemini:{name}",
            artifact_name=name,
            artifact_type="extension",
            ecosystem="gemini",
            package_name=name,
            package_url=None,
            raw_spec=name,
            version=None,
            source_url=_protect._option_value(command, "--url"),
            harness="gemini",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    if len(command) >= 4 and tuple(command[1:3]) in {
        ("extensions", "link"),
        ("skills", "install"),
        ("skills", "link"),
    }:
        spec = command[3]
        name = _protect._target_name_from_spec(spec)
        artifact_type = "extension" if command[1] == "extensions" else "skill"
        target = _protect.ProtectTarget(
            artifact_id=f"install:gemini:{artifact_type}:{name}",
            artifact_name=name,
            artifact_type=artifact_type,
            ecosystem="gemini",
            package_name=name if artifact_type == "extension" else None,
            package_url=_protect.build_package_url("gemini", name if artifact_type == "extension" else None, None),
            raw_spec=spec,
            version=None,
            source_url=_protect._spec_url(spec),
            harness="gemini",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    if len(command) >= 5 and command[1:3] == ["mcp", "add"]:
        name = command[3]
        command_or_url = command[4]
        transport = _protect._option_value(command, "--transport") or _protect._option_value(command, "--type")
        source_url = command_or_url if _protect._is_remote_transport(command_or_url, transport) else None
        target = _protect.ProtectTarget(
            artifact_id=f"install:gemini:mcp:{name}",
            artifact_name=name,
            artifact_type="mcp_server",
            ecosystem="gemini",
            package_name=name,
            package_url=None,
            raw_spec=command_or_url,
            version=None,
            source_url=source_url,
            harness="gemini",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "gemini", None, "gemini", (target,))
    return _protect._parse_custom_request(command)


def _parse_antigravity_request(command: list[str]) -> _protect.ProtectRequest:
    extension_name = _protect._option_value(command, "--install-extension")
    if extension_name is not None:
        target = _protect.ProtectTarget(
            artifact_id=f"install:antigravity:extension:{extension_name}",
            artifact_name=extension_name,
            artifact_type="extension",
            ecosystem="antigravity",
            package_name=extension_name,
            package_url=_protect.build_package_url("antigravity", extension_name, None),
            raw_spec=extension_name,
            version=None,
            source_url=_protect._spec_url(extension_name),
            harness="antigravity",
        )
        return _protect.ProtectRequest(
            tuple(command), "harness_registration", "antigravity", None, "antigravity", (target,)
        )
    raw_mcp_payload = _protect._option_value(command, "--add-mcp")
    if raw_mcp_payload is not None:
        target = _protect._parse_antigravity_mcp_target(raw_mcp_payload)
        return _protect.ProtectRequest(
            tuple(command), "harness_registration", "antigravity", None, "antigravity", (target,)
        )
    return _protect._parse_custom_request(command)


def _parse_opencode_request(command: list[str]) -> _protect.ProtectRequest:
    if len(command) >= 4 and command[1] in {"plugin", "skill"} and command[2] in {"add", "install"}:
        name = command[3]
        target = _protect.ProtectTarget(
            artifact_id=f"install:opencode:{name}",
            artifact_name=name,
            artifact_type="plugin" if command[1] == "plugin" else "skill",
            ecosystem="opencode",
            package_name=name,
            package_url=None,
            raw_spec=name,
            version=None,
            source_url=_protect._option_value(command, "--url"),
            harness="opencode",
        )
        return _protect.ProtectRequest(tuple(command), "harness_registration", "opencode", None, "opencode", (target,))
    return _protect._parse_custom_request(command)


def _parse_custom_request(command: list[str]) -> _protect.ProtectRequest:
    executable = _protect.Path(command[0]).name
    target = _protect.ProtectTarget(
        artifact_id=f"install:custom:{_protect._command_fingerprint(command)[:16]}",
        artifact_name=executable,
        artifact_type="custom_command",
        ecosystem="custom",
        package_name=None,
        package_url=None,
        raw_spec=_protect.shlex.join(command),
        version=None,
        source_url=_protect._first_url(command),
        harness=None,
    )
    return _protect.ProtectRequest(tuple(command), "custom", executable, None, None, (target,))


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import protect as _protect  # noqa: E402
