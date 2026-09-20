"""Install target and option parsers through the live Protect facade."""

from __future__ import annotations


def _package_manager_request(command: list[str], ecosystem: str, specs: tuple[str, ...]) -> _protect.ProtectRequest:
    targets = tuple(_protect._package_target(ecosystem, spec) for spec in specs)
    if len(targets) == 0:
        targets = (
            _protect.ProtectTarget(
                artifact_id=f"install:{ecosystem}:{_protect._command_fingerprint(command)[:16]}",
                artifact_name=ecosystem,
                artifact_type="package_request",
                ecosystem=ecosystem,
                package_name=None,
                package_url=None,
                raw_spec=_protect.shlex.join(command),
                version=None,
                source_url=_protect._first_url(command),
                harness=None,
            ),
        )
    return _protect.ProtectRequest(tuple(command), "package_install", ecosystem, ecosystem, None, targets)


def _package_target(ecosystem: str, spec: str) -> _protect.ProtectTarget:
    package_name, version = _protect._parse_package_identity(ecosystem, spec)
    if package_name is not None:
        package_name = package_name.strip()
    if version is not None:
        version = version.strip()
    source_url = _protect._spec_url(spec)
    if source_url is None and version is not None:
        source_url = _protect._spec_url(version)
    identity = package_name or spec
    return _protect.ProtectTarget(
        artifact_id=f"install:{ecosystem}:{identity}",
        artifact_name=identity,
        artifact_type=f"{ecosystem}_package",
        ecosystem=ecosystem,
        package_name=package_name,
        package_url=_protect.build_package_url(ecosystem, package_name, version),
        raw_spec=spec,
        version=version,
        source_url=source_url,
        harness=None,
    )


def _collect_package_specs(values: list[str]) -> tuple[str, ...]:
    specs: list[str] = []
    skip_next = False
    value_options = {
        "-r",
        "--extra-index-url",
        "--index-url",
        "--prefix",
        "--registry",
        "--requirement",
    }
    for index, value in enumerate(values):
        if skip_next:
            skip_next = False
            continue
        if value.startswith("-"):
            if value in value_options:
                skip_next = True
            continue
        if index > 0 and values[index - 1] in {"-r", "--requirement"}:
            continue
        specs.append(value)
    return tuple(specs)


def _collect_uv_specs(command: list[str]) -> tuple[str, ...]:
    if len(command) >= 3 and command[1:3] == ["pip", "install"]:
        return _protect._collect_package_specs(command[3:])
    if len(command) >= 2 and command[1] == "add":
        return _protect._collect_package_specs(command[2:])
    return ()


def _parse_package_identity(ecosystem: str, spec: str) -> tuple[str | None, str | None]:
    if ecosystem in {"pip", "uv"} and "==" in spec:
        name, version = spec.split("==", 1)
        return (name, version)
    if ecosystem == "go" and "@" in spec:
        name, version = spec.rsplit("@", 1)
        return (name, version)
    if spec.startswith("@"):
        if spec.count("@") >= 2:
            name, version = spec.rsplit("@", 1)
            return (name, version)
        return (spec, None)
    if "@" in spec and not spec.startswith(("http://", "https://", "git+", "file:")):
        name, version = spec.rsplit("@", 1)
        return (name, version)
    return (_protect._spec_name(spec), None)


def _spec_name(spec: str) -> str | None:
    if spec.startswith(("http://", "https://", "git+", "file:")):
        parsed = _protect.urlparse(spec)
        candidate = _protect.Path(parsed.path or spec).name
        return candidate or spec
    if spec.startswith(("./", "../", "/")):
        return _protect.Path(spec).name or spec
    return spec or None


def _spec_url(spec: str) -> str | None:
    if spec.startswith(("http://", "https://", "git+", "file:")):
        return spec
    return None


def _target_name_from_spec(spec: str) -> str:
    parsed_name = _protect._spec_name(spec)
    if parsed_name is None:
        return spec
    return parsed_name.removesuffix(".git")


def _option_value(command: list[str], option: str) -> str | None:
    for index, value in enumerate(command):
        if value == option and index + 1 < len(command):
            return command[index + 1]
    return None


def _remaining_positionals(args: list[str]) -> list[str]:
    positionals: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(args[index + 1 :])
            break
        if token.startswith("--"):
            if "=" not in token and index + 1 < len(args) and not args[index + 1].startswith("-"):
                index += 2
                continue
            index += 1
            continue
        if token.startswith("-") and token != "-":
            if len(token) == 2 and index + 1 < len(args) and not args[index + 1].startswith("-"):
                index += 2
                continue
            index += 1
            continue
        positionals.append(token)
        index += 1
    return positionals


def _first_url(command: list[str]) -> str | None:
    for value in command:
        if value.startswith(("http://", "https://", "git+", "file:")):
            return value
    return None


def _parse_antigravity_mcp_target(raw_payload: str) -> _protect.ProtectTarget:
    try:
        payload = _protect.json.loads(raw_payload)
    except _protect.json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    target_name = payload.get("name")
    name = target_name if isinstance(target_name, str) else "antigravity-mcp"
    command_or_url = payload.get("url") if isinstance(payload.get("url"), str) else None
    if command_or_url is None and isinstance(payload.get("command"), str):
        command_or_url = payload["command"]
    source_url = (
        command_or_url
        if isinstance(command_or_url, str) and _protect._is_remote_transport(command_or_url, None)
        else None
    )
    return _protect.ProtectTarget(
        artifact_id=f"install:antigravity:mcp:{name}",
        artifact_name=name,
        artifact_type="mcp_server",
        ecosystem="antigravity",
        package_name=name,
        package_url=None,
        raw_spec=raw_payload,
        version=None,
        source_url=source_url,
        harness="antigravity",
    )


def _parse_claude_mcp_target(name: str, raw_payload: str) -> _protect.ProtectTarget:
    try:
        payload = _protect.json.loads(raw_payload)
    except _protect.json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    transport = payload.get("transport") if isinstance(payload.get("transport"), str) else None
    command_or_url = payload.get("url") if isinstance(payload.get("url"), str) else None
    if command_or_url is None and isinstance(payload.get("command"), str):
        command_or_url = payload["command"]
    source_url = (
        command_or_url
        if isinstance(command_or_url, str) and _protect._is_remote_transport(command_or_url, transport)
        else None
    )
    return _protect.ProtectTarget(
        artifact_id=f"install:claude-code:mcp:{name}",
        artifact_name=name,
        artifact_type="mcp_server",
        ecosystem="claude-code",
        package_name=name,
        package_url=None,
        raw_spec=raw_payload,
        version=None,
        source_url=source_url,
        harness="claude-code",
    )


def _is_remote_transport(command_or_url: str, transport: str | None) -> bool:
    if transport == "stdio":
        return False
    if transport in {"http", "sse"}:
        return command_or_url.startswith(("http://", "https://"))
    return command_or_url.startswith(("http://", "https://"))


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import protect as _protect  # noqa: E402
