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
from ..adapters.mcp_servers import ManagedMcpServer, proxy_process_env, stable_mcp_server_identifier
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

def _is_copilot_permission_request(payload: dict[str, object]) -> bool:
    from ..daemon.hook_availability_policy import hook_event_is_permission_request as _perm
    return any(
        isinstance(payload.get(key), str) and _perm(str(payload.get(key)))
        for key in ("hook_name", "hook_event_name", "hookEventName")
    )

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

def _runtime_request_summary(artifact: GuardArtifact) -> str | None:
    summary = artifact.metadata.get("request_summary")
    if isinstance(summary, str) and summary:
        return summary
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

def _serve_hermes_stdio_proxy(
    *,
    context: HarnessContext,
    store: GuardStore,
    config,
    server_name: str,
    command: list[str],
    source_scope: str,
    config_path: str,
    server_id: str | None,
    server_env_keys: tuple[str, ...],
) -> int:
    def current_config() -> GuardConfig:
        local_config = load_guard_config(context.guard_home, workspace=context.workspace_dir)
        return overlay_synced_guard_policy(local_config, _synced_policy_payload(store))

    # The relay prompts inline for any client that declares elicitation, as this proxy does.
    proxy = ElicitationMcpGuardProxy(
        harness="hermes",
        server_name=server_name,
        command=command,
        context=context,
        store=store,
        config=config,
        source_scope=source_scope,
        config_path=config_path,
        transport="stdio",
        server_id=server_id,
        server_env_keys=server_env_keys,
        current_config_provider=current_config,
    )
    return proxy.serve()

def _run_hermes_mcp_proxy(
    *,
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    config,
) -> int:
    server_command = getattr(args, "server_command", None)
    if server_command:
        # The relay-style launch carries the server on its argv, like the other harnesses.
        server_name = getattr(args, "server_name", None)
        config_path = getattr(args, "config_path", None)
        if not server_name or config_path is None:
            print("Guard Hermes MCP proxy needs --server-name and --config-path with --command.", file=sys.stderr)
            return 2
        return _serve_hermes_stdio_proxy(
            context=context,
            store=store,
            config=config,
            server_name=server_name,
            command=[server_command, *list(getattr(args, "server_args", []))],
            source_scope=getattr(args, "source_scope", "project"),
            config_path=config_path,
            server_id=getattr(args, "server_id", None),
            server_env_keys=tuple(getattr(args, "server_env_keys", ())),
        )
    server_key = getattr(args, "server", None)
    if not server_key:
        print("Guard Hermes MCP proxy needs --server or --command.", file=sys.stderr)
        return 2
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
    server = _managed_manifest_server(managed_install, str(server_key))
    if server is None:
        print(f"Unknown Hermes MCP server: {server_key}", file=sys.stderr)
        return 2
    transport = str(server.get("transport") or "stdio")
    if transport == "http":
        base_url = server.get("url")
        if not isinstance(base_url, str) or not base_url:
            print(f"Hermes MCP server {server_key} is missing a remote URL.", file=sys.stderr)
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
    command = _server_command(server)
    if len(command) == 0:
        print(f"Hermes MCP server {server_key} is missing a launch command.", file=sys.stderr)
        return 2
    # An overlay written before the relay launch resolves its server from the manifest;
    # the proxy reads the server's environment values from this process, as it does for
    # every other harness.
    env = proxy_process_env(_server_env(server))
    os.environ.update(env)
    identity = ManagedMcpServer(
        harness="hermes",
        name=str(server.get("name") or server_key),
        source_scope="global",
        config_path=str(server.get("config_path") or ""),
        command=command[0],
        args=tuple(command[1:]),
        transport="stdio",
        env=env,
        enabled=True,
    )
    return _serve_hermes_stdio_proxy(
        context=context,
        store=store,
        config=config,
        server_name=identity.name,
        command=command,
        source_scope=identity.source_scope,
        config_path=identity.config_path,
        server_id=stable_mcp_server_identifier(identity),
        server_env_keys=tuple(sorted(env)),
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
    "_canonical_harness_name",
    "_expand_prompt_scan_path", "_is_copilot_permission_request",
    "_managed_install_for", "_managed_manifest_server",
    "_prompt_scan_path_exists", "_queue_claude_native_approval_gate_fallback",
    "_redact_codex_prompt_secret_assignments",
    "_resolve_prompt_scan_path", "_run_hermes_mcp_proxy",
    "_runtime_detection", "_runtime_policy_path", "_runtime_request_summary",
    "_server_command", "_server_env", "_server_headers",
    "_truncate_codex_display_text",
]
