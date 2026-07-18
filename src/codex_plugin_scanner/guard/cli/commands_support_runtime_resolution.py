"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_hook_payload import _action_envelope_json, _coalesce_string
    from .commands_support_runtime_artifacts import _CODEX_PROMPT_SECRET_KEY_MARKERS


from ._commands_shared import *
from .commands_parser_helpers import *
from ..runtime.approval_context import build_runtime_launch_identity
from ..runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from ..synced_policy import synced_policy_payload as _synced_policy_payload

def _redact_codex_prompt_secret_assignments(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        equals_index = value.find("=", index)
        if equals_index == -1:
            output.append(value[index:])
            break
        key_start = equals_index - 1
        while key_start >= index and value[key_start] not in {" ", "\t", "\n", "\r", ",", ";"}:
            key_start -= 1
        key_start += 1
        key = value[key_start:equals_index].strip()
        key_upper = key.upper()
        if key and any(marker in key_upper for marker in _CODEX_PROMPT_SECRET_KEY_MARKERS):
            value_start = equals_index + 1
            while value_start < len(value) and value[value_start].isspace():
                value_start += 1
            value_end = value_start
            while value_end < len(value) and value[value_end] not in {" ", "\t", "\n", "\r", ",", ";"}:
                value_end += 1
            output.append(value[index:value_start])
            output.append("[redacted]")
            index = value_end
            continue
        output.append(value[index : equals_index + 1])
        index = equals_index + 1
    return "".join(output)

def _truncate_codex_display_text(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 1].rstrip()}…"

def _resolve_prompt_scan_path(requested_path: str, *, cwd: Path | None) -> Path | None:
    stripped = requested_path.strip().strip("'\"")
    if not stripped:
        return None
    exact_path = _expand_prompt_scan_path(stripped, cwd=cwd)
    if _prompt_scan_path_exists(exact_path):
        return exact_path
    normalized = stripped.rstrip(".,;:!?)]}")
    if not normalized or normalized == stripped:
        return exact_path
    return _expand_prompt_scan_path(normalized, cwd=cwd)

def _expand_prompt_scan_path(requested_path: str, *, cwd: Path | None) -> Path:
    try:
        expanded = Path(requested_path).expanduser()
    except RuntimeError:
        return Path(requested_path)
    if not expanded.is_absolute():
        expanded = (cwd or Path.cwd()) / expanded
    with suppress(OSError):
        return expanded.resolve(strict=False)
    return expanded

def _prompt_scan_path_exists(path: Path) -> bool:
    with suppress(OSError):
        return path.is_file()
    return False

def _legacy_claude_alias_runtime_artifact(
    *,
    artifact: GuardArtifact,
    requested_harness: str,
    home_dir: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    if requested_harness == artifact.harness:
        return None
    if requested_harness != "claude" or artifact.harness != "claude-code":
        return None
    legacy_prefix = "claude-code:"
    if not artifact.artifact_id.startswith(legacy_prefix):
        return None
    return replace(
        artifact,
        artifact_id=f"claude:{artifact.artifact_id[len(legacy_prefix) :]}",
        harness="claude",
        config_path=str(_runtime_policy_path("claude", home_dir, workspace)),
    )

def _is_copilot_permission_request(payload: dict[str, object]) -> bool:
    for key in ("hook_name", "hook_event_name", "hookEventName"):
        hook_name = payload.get(key)
        if isinstance(hook_name, str) and hook_name == "permissionRequest":
            return True
    return False

def _copilot_hook_stage(payload: dict[str, object]) -> str | None:
    for key in ("hook_name", "hook_event_name", "hookEventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None

@dataclass(frozen=True, slots=True)
class _CopilotMcpRuntimeServer:
    server_name: str
    source_scope: str
    config_path: str
    server_config: object

@dataclass(frozen=True, slots=True)
class _CopilotMcpRuntimeTool:
    server: _CopilotMcpRuntimeServer
    tool_name: str

def _copilot_runtime_tool_call(
    *,
    payload: dict[str, object],
    home_dir: Path,
    workspace: Path | None,
    config: GuardConfig | None = None,
    preferred_workspace_config: str | None = None,
) -> tuple[GuardArtifact, str, object] | None:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    resolution: _CopilotMcpRuntimeTool | None = None
    if "/" in tool_name:
        server_name, runtime_tool_name = tool_name.split("/", 1)
        if server_name.strip() and runtime_tool_name.strip():
            runtime_server = _resolve_copilot_mcp_runtime_server(
                server_name=server_name.strip(),
                home_dir=home_dir,
                workspace=workspace,
                preferred_workspace_config=preferred_workspace_config,
            )
            if runtime_server is None:
                runtime_server = _CopilotMcpRuntimeServer(
                    server_name=server_name.strip(),
                    source_scope=_coalesce_string(
                        payload.get("source_scope"),
                        "project" if workspace is not None else "global",
                    ),
                    config_path=str(_runtime_policy_path("copilot", home_dir, workspace)),
                    server_config=None,
                )
            resolution = _CopilotMcpRuntimeTool(
                server=runtime_server,
                tool_name=runtime_tool_name.strip(),
            )
    elif tool_name.startswith("mcp_"):
        resolution = _resolve_copilot_mcp_runtime_tool(
            tool_name=tool_name,
            home_dir=home_dir,
            workspace=workspace,
            preferred_workspace_config=preferred_workspace_config,
        )
    if resolution is None:
        return None
    launch_cwd = workspace or Path.cwd()
    server_identity, server_fingerprint, transport = _copilot_runtime_server_identity(
        resolution.server,
        launch_cwd=launch_cwd,
    )
    tool_schema, tool_description = _copilot_runtime_tool_metadata(
        payload,
        server_config=resolution.server.server_config,
        requested_tool_name=tool_name,
        runtime_tool_name=resolution.tool_name,
    )
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name=resolution.server.server_name,
        tool_name=resolution.tool_name,
        source_scope=resolution.server.source_scope,
        config_path=resolution.server.config_path,
        transport=transport,
        server_fingerprint=server_fingerprint,
        server_identity=server_identity,
        tool_schema=tool_schema,
        tool_description=tool_description,
    )
    arguments = payload.get("tool_input", payload.get("arguments"))
    artifact_hash = build_tool_call_hash(
        artifact,
        arguments,
        workspace=workspace or Path.cwd(),
        config=config,
    )
    return artifact, artifact_hash, arguments

def _resolve_copilot_mcp_runtime_tool(
    *,
    tool_name: str,
    home_dir: Path,
    workspace: Path | None,
    preferred_workspace_config: str | None = None,
) -> _CopilotMcpRuntimeTool | None:
    if not tool_name.startswith("mcp_"):
        return None
    suffix = tool_name[len("mcp_") :]
    if not suffix:
        return None
    matches: list[tuple[int, int, _CopilotMcpRuntimeServer, str]] = []
    for server in _copilot_runtime_server_entries(home_dir, workspace):
        server_token = _copilot_mcp_tool_token(server.server_name)
        if suffix.startswith(f"{server_token}_"):
            runtime_tool_name = suffix[len(server_token) + 1 :]
            if runtime_tool_name:
                matches.append(
                    (
                        len(server_token),
                        _copilot_runtime_match_priority(
                            config_path=server.config_path,
                            preferred_workspace_config=preferred_workspace_config,
                        ),
                        server,
                        runtime_tool_name,
                    )
                )
    if matches:
        _length, _priority, server, runtime_tool_name = max(
            matches,
            key=lambda item: (item[0], item[1], item[2].config_path),
        )
        return _CopilotMcpRuntimeTool(server=server, tool_name=runtime_tool_name)
    return None

def _resolve_copilot_mcp_runtime_server(
    *,
    server_name: str,
    home_dir: Path,
    workspace: Path | None,
    preferred_workspace_config: str | None,
) -> _CopilotMcpRuntimeServer | None:
    matches = [
        entry
        for entry in _copilot_runtime_server_entries(home_dir, workspace)
        if entry.server_name == server_name
    ]
    if not matches:
        return None
    return max(
        matches,
        key=lambda entry: (
            _copilot_runtime_match_priority(
                config_path=entry.config_path,
                preferred_workspace_config=preferred_workspace_config,
            ),
            entry.config_path,
        ),
    )

def _copilot_runtime_server_entries(home_dir: Path, workspace: Path | None) -> list[_CopilotMcpRuntimeServer]:
    entries: list[_CopilotMcpRuntimeServer] = []
    if workspace is not None:
        for path in (workspace / ".vscode" / "mcp.json", workspace / ".mcp.json"):
            entries.extend(_mcp_server_entries_from_path(path, source_scope="project"))
    entries.extend(_mcp_server_entries_from_path(home_dir / ".copilot" / "mcp-config.json", source_scope="global"))
    return entries

def _copilot_runtime_match_priority(*, config_path: str, preferred_workspace_config: str | None) -> int:
    path = Path(config_path)
    is_cli_workspace_config = path.name == ".mcp.json"
    is_ide_workspace_config = path.name == "mcp.json" and path.parent.name == ".vscode"
    if preferred_workspace_config == "cli":
        if is_cli_workspace_config:
            return 2
        if is_ide_workspace_config:
            return 1
        return 0
    if preferred_workspace_config == "ide":
        if is_ide_workspace_config:
            return 2
        if is_cli_workspace_config:
            return 1
        return 0
    return 0

def _resolve_copilot_workspace_root(workspace: Path | None) -> Path | None:
    if workspace is None:
        return None
    candidates = [workspace, *workspace.parents]
    for candidate in candidates:
        if (candidate / ".mcp.json").is_file() or (candidate / ".vscode" / "mcp.json").is_file():
            return candidate
    return workspace

def _mcp_server_entries_from_path(path: Path, *, source_scope: str) -> list[_CopilotMcpRuntimeServer]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    servers = _mcp_servers_payload(payload)
    if not isinstance(servers, dict):
        return []
    return [
        _CopilotMcpRuntimeServer(
            server_name=server_name.strip(),
            source_scope=source_scope,
            config_path=str(path),
            server_config=server_config,
        )
        for server_name, server_config in servers.items()
        if isinstance(server_name, str) and server_name.strip()
    ]

def _mcp_servers_payload(payload: dict[str, object]) -> dict[str, object] | None:
    servers = payload.get("servers")
    if isinstance(servers, dict):
        return servers
    mcp_servers = payload.get("mcpServers")
    if isinstance(mcp_servers, dict):
        return mcp_servers
    return None

def _copilot_runtime_server_identity(
    server: _CopilotMcpRuntimeServer,
    *,
    launch_cwd: Path,
) -> tuple[McpServerIdentity, dict[str, object], str]:
    """Build a non-secret, content-bound identity for a Copilot MCP server."""

    server_config = (
        cast(Mapping[str, object], server.server_config)
        if isinstance(server.server_config, Mapping)
        else None
    )
    command, launch_args = _copilot_runtime_server_command(server_config)
    transport = _copilot_runtime_server_transport(server_config)
    config_sha256 = _copilot_runtime_server_config_digest(server.server_config)
    configured_env, env_keys = _copilot_runtime_server_environment(server_config)
    launch_env = dict(os.environ)
    launch_env.update(configured_env)
    launch_identity = build_runtime_launch_identity(
        command,
        args=launch_args,
        structured_command=True,
        search_path=launch_env.get("PATH"),
        cwd=launch_cwd,
        launch_env=launch_env,
    )
    launch_identity["launch_args_sha256"] = hashlib.sha256(
        json.dumps(list(launch_args), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    launch_identity["server_config_sha256"] = config_sha256
    launch_identity["transport"] = transport
    remote_url = server_config.get("url") if server_config is not None else None
    has_remote_url = isinstance(remote_url, str) and bool(remote_url.strip())
    if server_config is None or (command is None and not has_remote_url) or config_sha256 is None:
        launch_identity["reuse_nonce"] = secrets.token_hex(16)
        launch_identity["status"] = (
            "server_config_unresolved"
            if server_config is None
            else "server_command_unresolved"
            if command is None and not has_remote_url
            else "server_config_unhashable"
        )
    elif command is None:
        launch_identity["status"] = "remote_transport"

    server_identity = build_mcp_server_identity(
        config_path=server.config_path,
        command=command or ("<remote>" if has_remote_url else "<unresolved>"),
        args=launch_args,
        transport=transport,
        env=configured_env,
        env_keys=env_keys,
    )
    server_fingerprint: dict[str, object] = {
        "config_sha256": config_sha256,
        "launch_args_sha256": launch_identity["launch_args_sha256"],
        # ``build_tool_call_hash`` carries this full mapping into the v1
        # approval identity.  It therefore binds the selected server config
        # as well as executable and interpreted-entrypoint bytes without
        # persisting config secrets.
        "resolved_executable": launch_identity,
        "transport": transport,
    }
    return server_identity, server_fingerprint, transport

def _copilot_runtime_server_environment(
    server_config: Mapping[str, object] | None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if server_config is None:
        return {}, ()
    env_config = server_config.get("env")
    if not isinstance(env_config, Mapping):
        return {}, ()
    env_keys = tuple(sorted(str(key) for key in env_config if str(key).strip()))
    configured_env = {
        str(key): value
        for key, value in env_config.items()
        if str(key).strip() and isinstance(value, str)
    }
    return configured_env, env_keys

def _copilot_runtime_server_command(
    server_config: Mapping[str, object] | None,
) -> tuple[str | None, tuple[str, ...]]:
    if server_config is None:
        return None, ()
    command_value = server_config.get("command")
    command: str | None = None
    launch_args: list[str] = []
    if isinstance(command_value, str) and command_value.strip():
        command = command_value.strip()
    elif isinstance(command_value, list):
        command_parts = [item for item in command_value if isinstance(item, str) and item]
        if command_parts:
            command = command_parts[0]
            launch_args.extend(command_parts[1:])
    args_value = server_config.get("args")
    if isinstance(args_value, list):
        launch_args.extend(item for item in args_value if isinstance(item, str))
    return command, tuple(launch_args)

def _copilot_runtime_server_transport(server_config: Mapping[str, object] | None) -> str:
    if server_config is None:
        return "stdio"
    raw_transport = server_config.get("transport", server_config.get("type"))
    if isinstance(raw_transport, str) and raw_transport.strip():
        normalized = raw_transport.strip().lower().replace("_", "-")
        if normalized in {"local", "stdio"}:
            return "stdio"
        if normalized in {"http", "https", "remote", "streamable-http"}:
            return "http"
        return normalized
    if isinstance(server_config.get("url"), str) and str(server_config["url"]).strip():
        return "http"
    return "stdio"

def _copilot_runtime_server_config_digest(server_config: object) -> str | None:
    try:
        encoded = json.dumps(
            server_config,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()

_COPILOT_TOOL_METADATA_MISSING = object()

def _copilot_runtime_tool_metadata(
    payload: Mapping[str, object],
    *,
    server_config: object,
    requested_tool_name: str,
    runtime_tool_name: str,
) -> tuple[object | None, str | None]:
    schema: object = _COPILOT_TOOL_METADATA_MISSING
    description: str | None = None
    candidates: list[Mapping[str, object]] = [payload]
    for key in ("tool", "tool_definition", "toolDefinition"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            candidates.append(value)
    tool_calls = payload.get("toolCalls")
    if isinstance(tool_calls, list):
        for item in tool_calls:
            if not isinstance(item, Mapping):
                continue
            candidate_name = item.get("name")
            if candidate_name in {requested_tool_name, runtime_tool_name}:
                candidates.append(item)
    config_tool = _copilot_runtime_config_tool_definition(server_config, runtime_tool_name)
    if config_tool is not None:
        candidates.append(config_tool)

    for candidate in candidates:
        if schema is _COPILOT_TOOL_METADATA_MISSING:
            for key in ("tool_schema", "toolSchema", "input_schema", "inputSchema", "schema"):
                if key in candidate:
                    schema = candidate[key]
                    break
        if description is None:
            for key in ("tool_description", "toolDescription", "description"):
                value = candidate.get(key)
                if isinstance(value, str) and value.strip():
                    description = value.strip()
                    break
        if schema is not _COPILOT_TOOL_METADATA_MISSING and description is not None:
            break
    return (None if schema is _COPILOT_TOOL_METADATA_MISSING else schema), description

def _copilot_runtime_config_tool_definition(
    server_config: object,
    runtime_tool_name: str,
) -> Mapping[str, object] | None:
    if not isinstance(server_config, Mapping):
        return None
    tools = server_config.get("tools")
    if isinstance(tools, Mapping):
        definition = tools.get(runtime_tool_name)
        return definition if isinstance(definition, Mapping) else None
    if isinstance(tools, list):
        for item in tools:
            if isinstance(item, Mapping) and item.get("name") == runtime_tool_name:
                return item
    return None

def _copilot_mcp_tool_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return token.strip("_")


def _validated_pi_runtime_policy_override(
    home_dir: Path,
    workspace: Path | None,
    payload: dict[str, object] | None,
) -> Path | None:
    raw_config_path = payload.get("config_path") if isinstance(payload, dict) else None
    if not isinstance(raw_config_path, str) or not raw_config_path.strip():
        return None
    candidate = Path(raw_config_path).expanduser()
    allowed_paths = {
        home_dir / ".pi" / "agent" / "settings.json",
        home_dir / ".omp" / "agent" / "settings.json",
    }
    if workspace is not None:
        allowed_paths.update(
            {
                workspace / ".pi" / "settings.json",
                workspace / ".omp" / "settings.json",
            }
        )
    return candidate if candidate in allowed_paths else None


def _runtime_policy_path(
    harness: str,
    home_dir: Path,
    workspace: Path | None,
    *,
    payload: dict[str, object] | None = None,
) -> Path:
    if harness == "hermes":
        return home_dir / ".hermes" / "config.yaml"
    if harness == "cursor":
        if workspace is not None:
            return workspace / ".cursor" / "mcp.json"
        return home_dir / ".cursor" / "mcp.json"
    if harness == "claude-code":
        if workspace is not None:
            return workspace / ".claude" / "settings.local.json"
        return home_dir / ".claude" / "settings.json"
    if harness == "codex":
        if workspace is not None:
            return workspace / ".codex" / "config.toml"
        return home_dir / ".codex" / "config.toml"
    if harness == "pi":
        override_path = _validated_pi_runtime_policy_override(home_dir, workspace, payload)
        if override_path is not None:
            return override_path
        if workspace is not None:
            return workspace / ".pi" / "settings.json"
        return home_dir / ".pi" / "agent" / "settings.json"
    if harness == "copilot":
        if workspace is not None:
            return workspace / ".github" / "hooks" / "hol-guard-copilot.json"
        return home_dir / ".copilot" / "config.json"
    if workspace is not None:
        return workspace / ".mcp.json"
    return home_dir / ".mcp.json"

def _runtime_detection(harness: str, artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )

def _queue_claude_native_approval_gate_fallback(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_digest: str,
    approval_center_url: str,
    action_envelope: GuardActionEnvelope | None = None,
    redaction_level: str = "full",
) -> list[dict[str, object]]:
    now = _now()
    queued = queue_blocked_approvals(
        detection=_runtime_detection(harness, artifact),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": artifact_digest,
                    "artifact_type": artifact.artifact_type,
                    "policy_action": "require-reapproval",
                    "changed_fields": [artifact.artifact_type, "claude-native-approval-gate"],
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "risk_summary": "Native Claude approval requires the HOL Guard approval password.",
                    "risk_signals": ["approval_gate_required", "claude_native_approval"],
                    "action_envelope_json": _action_envelope_json(action_envelope),
                }
            ]
        },
        store=store,
        approval_center_url=approval_center_url,
        now=now,
        redaction_level=redaction_level,
    )
    store.add_event(
        "approval_gate/native_fallback_queued",
        {
            "harness": harness,
            "artifact_id": artifact.artifact_id,
            "queued_count": len(queued),
        },
        now,
    )
    return queued

def _runtime_capabilities_summary(artifact: GuardArtifact) -> str:
    if artifact.artifact_type == "package_request":
        package_manager = artifact.metadata.get("package_manager")
        if isinstance(package_manager, str) and package_manager:
            return f"package request • {package_manager}"
        return "package request"
    tool_name = artifact.metadata.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        if artifact.artifact_type == "tool_action_request":
            return f"tool action request • {tool_name}"
        return f"file read request • {tool_name}"
    return "file read request"

def _runtime_request_summary(artifact: GuardArtifact) -> str | None:
    summary = artifact.metadata.get("request_summary")
    if isinstance(summary, str) and summary:
        return summary
    return None

def _runtime_requested_path(artifact: GuardArtifact) -> str | None:
    normalized_path = artifact.metadata.get("normalized_path")
    if isinstance(normalized_path, str) and normalized_path:
        return normalized_path
    return None

def _canonical_harness_name(harness: str) -> str:
    try:
        return get_adapter(harness).harness
    except ValueError:
        return harness

def _managed_install_for(store: GuardStore, harness: str) -> dict[str, object] | None:
    managed_install = store.get_managed_install(_canonical_harness_name(harness))
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    return managed_install

def _managed_manifest_server(
    managed_install: dict[str, object],
    server_name: str,
) -> dict[str, object] | None:
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        return None
    servers = manifest.get("servers")
    if not isinstance(servers, dict):
        return None
    server = servers.get(server_name)
    if not isinstance(server, dict):
        return None
    return server

def _server_headers(server: dict[str, object]) -> dict[str, str]:
    headers = server.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {str(key): value for key, value in headers.items() if isinstance(key, str) and isinstance(value, str)}

def _server_env(server: dict[str, object]) -> dict[str, str]:
    env = server.get("env")
    if not isinstance(env, dict):
        return {}
    return {str(key): value for key, value in env.items() if isinstance(key, str) and isinstance(value, str)}

def _run_hermes_mcp_proxy(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
) -> int:
    managed_install = _managed_install_for(store, "hermes")
    if managed_install is None:
        print("Guard is not managing Hermes in this Guard home.", file=sys.stderr)
        return 2
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        print("Hermes managed install manifest is missing.", file=sys.stderr)
        return 2
    if not isinstance(manifest.get("servers"), dict):
        print("Hermes managed install has no MCP server manifest.", file=sys.stderr)
        return 2
    server = _managed_manifest_server(managed_install, str(args.server))
    if server is None:
        print(f"Unknown Hermes MCP server: {args.server}", file=sys.stderr)
        return 2
    transport = str(server.get("transport") or "stdio")
    if transport == "http":
        base_url = server.get("url")
        if not isinstance(base_url, str) or not base_url:
            print(f"Hermes MCP server {args.server} is missing a remote URL.", file=sys.stderr)
            return 2
        proxy = RemoteGuardProxy(base_url=base_url, allow_insecure_localhost=True)
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Guard Hermes MCP proxy received invalid JSON: {exc}", file=sys.stderr)
                return 2
            expect_response = message.get("id") is not None
            response = proxy.forward(
                "",
                message,
                headers=_server_headers(server),
                expect_response=expect_response,
            )
            if response is not None:
                print(json.dumps(response, separators=(",", ":")), flush=True)
        return 0
    approval_center_url = ensure_guard_daemon(context.guard_home)
    command = _server_command(server)
    if len(command) == 0:
        print(f"Hermes MCP server {args.server} is missing a launch command.", file=sys.stderr)
        return 2

    def current_stdio_config() -> GuardConfig:
        local_config = load_guard_config(context.guard_home, workspace=context.workspace_dir)
        return overlay_synced_guard_policy(local_config, _synced_policy_payload(store))

    proxy = StdioGuardProxy(
        command=command,
        cwd=context.workspace_dir,
        guard_store=store,
        guard_config=config,
        approval_center_url=approval_center_url,
        harness="hermes",
        env=_server_env(server),
        current_config_provider=current_stdio_config,
    )
    return proxy.run_stream(
        input_stream=sys.stdin,
        output_stream=sys.stdout,
        error_stream=sys.stderr,
    )

def _server_command(server: dict[str, object]) -> list[str]:
    command = server.get("command")
    args = server.get("args")
    command_parts: list[str] = []
    if isinstance(command, str) and command:
        command_parts.append(command)
    if isinstance(args, list):
        command_parts.extend(str(value) for value in args if isinstance(value, str) and value)
    return command_parts

__all__ = [
    "_canonical_harness_name", "_copilot_hook_stage", "_copilot_mcp_tool_token",
    "_copilot_runtime_match_priority", "_copilot_runtime_server_entries", "_copilot_runtime_tool_call",
    "_expand_prompt_scan_path", "_is_copilot_permission_request", "_legacy_claude_alias_runtime_artifact",
    "_managed_install_for", "_managed_manifest_server", "_mcp_server_entries_from_path", "_mcp_servers_payload",
    "_prompt_scan_path_exists", "_queue_claude_native_approval_gate_fallback",
    "_redact_codex_prompt_secret_assignments", "_resolve_copilot_mcp_runtime_tool",
    "_resolve_copilot_workspace_root", "_resolve_prompt_scan_path", "_run_hermes_mcp_proxy",
    "_runtime_capabilities_summary", "_runtime_detection", "_runtime_policy_path", "_runtime_request_summary",
    "_runtime_requested_path", "_server_command", "_server_env", "_server_headers",
    "_truncate_codex_display_text",
]
