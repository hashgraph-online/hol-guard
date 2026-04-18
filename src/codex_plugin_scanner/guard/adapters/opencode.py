"""OpenCode harness adapter."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..launcher import merge_guard_launcher_env
from ..models import HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _run_command_probe
from .mcp_servers import ManagedMcpServer, managed_stdio_servers, proxy_cli_args, skipped_stdio_server_names
from .opencode_artifacts import (
    append_config_artifacts,
    append_directory_artifacts,
    append_found_path,
    config_paths,
    runtime_config_path,
    runtime_overlay,
)


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Discover OpenCode config, commands, plugins, and skills."""

    harness = "opencode"
    executable = "opencode"
    approval_tier = "mixed"
    approval_summary = (
        "Guard evaluates OpenCode skills, MCP servers, commands, and plugins before launch, and the managed "
        "runtime overlay keeps native skill loads on ask."
    )
    fallback_hint = (
        "Use Guard approvals for blocked artifacts and OpenCode's native allow once or allow session flow for skills."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts = []
        found_paths: list[str] = []
        seen_artifact_ids: set[str] = set()
        for config_path in config_paths(context):
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error or not payload:
                continue
            append_found_path(found_paths, config_path)
            scope = self._scope_for(context, config_path)
            append_config_artifacts(
                artifacts=artifacts,
                seen_artifact_ids=seen_artifact_ids,
                scope=scope,
                config_path=config_path,
                payload=payload,
            )
        append_directory_artifacts(
            context=context,
            artifacts=artifacts,
            found_paths=found_paths,
            seen_artifact_ids=seen_artifact_ids,
        )
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        detection = self.detect(context)
        managed_servers = managed_stdio_servers(detection)
        skipped_servers = skipped_stdio_server_names(detection)
        existing_workspace_server_names = self._workspace_server_names(context)
        shim_manifest = install_guard_shim(self.harness, context)
        overlay_path = runtime_config_path(context)
        overlay_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.write_text(
            json.dumps(
                runtime_overlay(
                    permission_rules=self._proxy_permission_rules(
                        context,
                        managed_servers,
                        existing_workspace_server_names,
                    ),
                    mcp_servers=self._proxy_mcp_overrides(
                        context,
                        managed_servers,
                        existing_workspace_server_names,
                    ),
                ),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard added an OpenCode runtime overlay that keeps native skill loads on ask and routes managed "
            "local MCP servers through Guard runtime interception when you launch through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(overlay_path),
            **shim_manifest,
            "runtime_config_path": str(overlay_path),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "managed_servers": [server.name for server in managed_servers],
            "skipped_servers": list(skipped_servers),
            "source_config_paths": list(detection.config_paths),
            "notes": notes,
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard leaves the OpenCode runtime overlay on disk for auditability, but it is ignored unless you "
            "launch through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(runtime_config_path(context)),
            **shim_manifest,
            "runtime_config_path": str(runtime_config_path(context)),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
            "notes": notes,
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        overlay_path = runtime_config_path(context)
        if not overlay_path.exists():
            return {}
        try:
            runtime_config = json.loads(overlay_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        existing_config = _inline_config(os.getenv("OPENCODE_CONFIG_CONTENT"))
        merged_config = _merge_configs(existing_config, runtime_config)
        return {"OPENCODE_CONFIG_CONTENT": json.dumps(merged_config)}

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        if context.workspace_dir is not None and passthrough_args:
            return [self.executable, "run", *passthrough_args]
        if context.workspace_dir is not None:
            return [self.executable, str(context.workspace_dir)]
        if passthrough_args:
            return [self.executable, "run", *passthrough_args]
        return [self.executable]

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        if not _command_available(self.executable):
            return None
        return {
            "paths": _run_command_probe([self.executable, "debug", "paths"]),
            "config": _run_command_probe([self.executable, "debug", "config"]),
        }

    def _proxy_mcp_overrides(
        self,
        context: HarnessContext,
        servers: tuple[ManagedMcpServer, ...],
        existing_workspace_server_names: set[str],
    ) -> dict[str, object]:
        overrides: dict[str, object] = {}
        for server in servers:
            if self._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                continue
            entry: dict[str, object] = {
                "type": "local",
                "command": [
                    sys.executable,
                    *proxy_cli_args(
                        proxy_command="opencode-mcp-proxy",
                        guard_home=str(context.guard_home),
                        server=server,
                        home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
                        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
                    ),
                ],
                "enabled": server.enabled,
            }
            environment = merge_guard_launcher_env(getattr(server, "env", {}))
            if environment:
                entry["environment"] = environment
            overrides[server.name] = entry
        return overrides

    @staticmethod
    def _proxy_permission_rules(
        context: HarnessContext,
        servers: tuple[ManagedMcpServer, ...],
        existing_workspace_server_names: set[str],
    ) -> dict[str, object]:
        rules: dict[str, object] = {}
        for server in servers:
            if OpenCodeHarnessAdapter._should_skip_workspace_override(
                context=context,
                server=server,
                existing_workspace_server_names=existing_workspace_server_names,
            ):
                continue
            if not server.enabled:
                continue
            rules[f"{server.name}_*"] = "ask"
        return rules

    @staticmethod
    def _should_skip_workspace_override(
        *,
        context: HarnessContext,
        server: ManagedMcpServer,
        existing_workspace_server_names: set[str],
    ) -> bool:
        if context.workspace_dir is None:
            return False
        if server.source_scope == "project":
            return False
        return server.name in existing_workspace_server_names

    def _workspace_server_names(self, context: HarnessContext) -> set[str]:
        if context.workspace_dir is None:
            return set()
        workspace_server_names: set[str] = set()
        for config_path in config_paths(context):
            if not config_path.is_relative_to(context.workspace_dir):
                continue
            payload, parse_error, _parse_reason = _load_json_or_jsonc(config_path)
            if parse_error or not isinstance(payload, dict):
                continue
            mcp = payload.get("mcp")
            if not isinstance(mcp, dict):
                continue
            for name, value in mcp.items():
                if isinstance(name, str) and isinstance(value, dict):
                    workspace_server_names.add(name)
        return workspace_server_names


__all__ = ["OpenCodeHarnessAdapter"]


def _inline_config(raw_content: str | None) -> dict[str, object]:
    if not raw_content:
        return {}
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError:
        return {}
    parsed = _object_dict(payload)
    return parsed if parsed is not None else {}


def _merge_configs(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in overlay.items():
        existing_value = merged.get(key)
        nested_overlay = _object_dict(value)
        nested_existing = _object_dict(existing_value)
        if nested_overlay is not None and nested_existing is not None:
            merged[key] = _merge_configs(nested_existing, nested_overlay)
            continue
        merged[key] = value
    return merged


def _object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(key, str):
            result[key] = item
    return result
