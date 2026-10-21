"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import os
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore
    from ._commands_shared import _now
    from .commands_support_hook_payload import _action_envelope_json
    from .commands_support_runtime_artifacts import _CODEX_PROMPT_SECRET_KEY_MARKERS


from ._commands_shared import *
from .commands_parser_helpers import *
from ..runtime.composio_contract import composio_names_a_wrapper
from ..runtime.mcp_protection import McpServerIdentity
from ..synced_policy import synced_policy_payload as _synced_policy_payload
from ..native_cli_runtime_support import cli_runtime_support as _native_cli_support

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
    from ..daemon.hook_availability_policy import hook_event_is_permission_request as _perm
    return any(
        isinstance(payload.get(key), str) and _perm(str(payload.get(key)))
        for key in ("hook_name", "hook_event_name", "hookEventName")
    )

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

def _copilot_identity_dto(value: dict[str, Any]) -> McpServerIdentity:
    fields: dict[str, Any] = dict(value)
    fields["env_keys"] = tuple(fields["env_keys"])
    return McpServerIdentity(**fields)


def _copilot_runtime_tool_call(
    *, payload: dict[str, object], home_dir: Path, workspace: Path | None,
    config: GuardConfig | None = None, preferred_workspace_config: str | None = None,
    store: GuardStore | None = None,
) -> tuple[GuardArtifact, str, object] | None:
    tool_name = payload.get("tool_name")
    if (
        not isinstance(tool_name, str) or not tool_name.strip()
        or ("/" not in tool_name and not tool_name.startswith("mcp_"))
    ):
        return None
    fields = ("tool_schema", "toolSchema", "input_schema", "inputSchema", "schema",
              "tool_description", "toolDescription", "description")
    projection = {key: payload[key] for key in (*fields, "tool_name", "source_scope") if key in payload}
    for key in ("tool", "tool_definition", "toolDefinition"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            projection[key] = {name: value[name] for name in fields if name in value}
    calls = payload.get("toolCalls")
    if isinstance(calls, list):
        projection["toolCalls"] = [
            {name: item[name] for name in (*fields, "name") if name in item}
            for item in calls if isinstance(item, Mapping)
        ]
    result = _native_cli_support("resolve_tool", {
        "payload": projection, "home_dir": str(home_dir),
        "workspace": str(workspace) if workspace is not None else None,
        "preferred": preferred_workspace_config, "launch_cwd": str(workspace or Path.cwd()),
        "environment": dict(os.environ),
        "caller_cwd": str(Path.cwd()),
    }, guard_home=store.guard_home if store is not None else None)
    if result is None:
        return None
    server, identity, metadata = result["server"], result["identity"], result["metadata"]
    runtime_name = result["tool_name"]
    server_identity = identity["server_identity"]
    artifact = build_tool_call_artifact(
        harness="copilot", server_name=server["server_name"], tool_name=runtime_name,
        source_scope=server["source_scope"], config_path=server["config_path"], transport=identity["transport"],
        server_identity=_copilot_identity_dto(server_identity),
        server_fingerprint=identity["fingerprint"], tool_schema=metadata["schema"],
        tool_description=metadata["description"],
        provider_catalog_hash=(
            store.read_mcp_provider_authority_hash()
            if store is not None and composio_names_a_wrapper(runtime_name)
            else None
        ),
    )
    arguments = payload.get("tool_input", payload.get("arguments"))
    artifact_hash = build_tool_call_hash(artifact, arguments, workspace=workspace or Path.cwd(), config=config)
    return artifact, artifact_hash, arguments





def _resolve_copilot_workspace_root(workspace: Path | None) -> Path | None:
    if workspace is None:
        return None
    result = _native_cli_support("workspace_root", {
        "workspace": str(workspace),
        "caller_cwd": str(Path.cwd()),
    })
    return Path(result) if result is not None else None



def _copilot_runtime_server_identity(
    server: _CopilotMcpRuntimeServer, *, launch_cwd: Path,
) -> tuple[McpServerIdentity, dict[str, object], str]:
    environment = server.server_config.get("env") if isinstance(server.server_config, Mapping) else None
    result = _native_cli_support("server_identity", {
        "server": {"server_name": server.server_name, "source_scope": server.source_scope,
                   "config_path": server.config_path, "server_config": server.server_config,
                   "environment_keys": list(environment) if isinstance(environment, Mapping) else []},
        "launch_cwd": str(launch_cwd), "environment": dict(os.environ),
    })
    identity = result["server_identity"]
    server_identity = _copilot_identity_dto(identity)
    return server_identity, result["fingerprint"], result["transport"]










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
    if harness in {"pi", "omp"}:
        override_path = _validated_pi_runtime_policy_override(home_dir, workspace, payload)
        if override_path is not None:
            return override_path
        if workspace is not None:
            return workspace / (".omp" if harness == "omp" else ".pi") / "settings.json"
        return home_dir / (".omp" if harness == "omp" else ".pi") / "agent" / "settings.json"
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
    approval_center_url = schedule_guard_daemon_ensure(
        context.guard_home,
        home_dir=context.home_dir,
    )
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
    "_canonical_harness_name", "_copilot_hook_stage",
    "_copilot_runtime_tool_call",
    "_expand_prompt_scan_path", "_is_copilot_permission_request", "_legacy_claude_alias_runtime_artifact",
    "_managed_install_for", "_managed_manifest_server",
    "_prompt_scan_path_exists", "_queue_claude_native_approval_gate_fallback",
    "_redact_codex_prompt_secret_assignments",
    "_resolve_copilot_workspace_root", "_resolve_prompt_scan_path", "_run_hermes_mcp_proxy",
    "_runtime_capabilities_summary", "_runtime_detection", "_runtime_policy_path", "_runtime_request_summary",
    "_runtime_requested_path", "_server_command", "_server_env", "_server_headers",
    "_truncate_codex_display_text",
]
