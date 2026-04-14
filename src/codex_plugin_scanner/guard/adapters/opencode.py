"""OpenCode harness adapter."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..models import HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available, _run_command_probe
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
        shim_manifest = install_guard_shim(self.harness, context)
        overlay_path = runtime_config_path(context)
        overlay_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.write_text(json.dumps(runtime_overlay(), indent=2) + "\n", encoding="utf-8")
        notes = [
            *list(shim_manifest.get("notes", [])),
            "Guard added an OpenCode runtime overlay that keeps native skill loads on ask when you launch "
            "through Guard.",
        ]
        return {
            "harness": self.harness,
            "active": True,
            "config_path": str(overlay_path),
            **shim_manifest,
            "runtime_config_path": str(overlay_path),
            "runtime_env_var": "OPENCODE_CONFIG_CONTENT",
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
