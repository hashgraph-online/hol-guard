"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store import GuardStore


from ._commands_shared import *
from .commands_parser_helpers import *
from ..adapters.mcp_servers import ManagedMcpServer, proxy_process_env, stable_mcp_server_identifier
from ..synced_policy import synced_policy_payload as _synced_policy_payload

def _truncate_codex_display_text(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 1].rstrip()}…"

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
    "_managed_install_for", "_managed_manifest_server",
    "_run_hermes_mcp_proxy",
    "_runtime_request_summary",
    "_server_command", "_server_env", "_server_headers",
    "_truncate_codex_display_text",
]
