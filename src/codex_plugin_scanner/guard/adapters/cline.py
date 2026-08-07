"""Cline harness adapter with native-hook and AgentPlugin enforcement transports."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..shims import ensure_guard_shim_path_in_shell_profile, install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext
from .cline_contract import register_cline_contract
from .cline_detection import ClineHostDetection, detect_cline_hosts
from .cline_hook_payload import register_cline_action_normalizer
from .cline_hooks import cline_native_hook_state, install_cline_hooks, uninstall_cline_hooks
from .cline_mcp import (
    cline_mcp_proxy_state,
    detect_cline_mcp,
    install_cline_mcp_proxies,
    restore_cline_mcp_proxies,
)
from .cline_plugin import cline_plugin_state, cline_plugin_syntax_probe, install_cline_plugin, uninstall_cline_plugin

register_cline_contract()
register_cline_action_normalizer()

_CLINE_SURFACES = frozenset({"auto", "hooks", "plugin", "cli", "all"})
_STATE_SCHEMA = 1


def _adapter_state_path(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "adapter-state.json"


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _load_adapter_state(context: HarnessContext) -> dict[str, object]:
    try:
        payload = json.loads(_adapter_state_path(context).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _host_artifacts(hosts: ClineHostDetection, context: HarnessContext) -> tuple[GuardArtifact, ...]:
    artifacts: list[GuardArtifact] = []
    if hosts.cli_executable:
        artifacts.append(
            GuardArtifact(
                artifact_id="cline:host:cli",
                name="Cline CLI",
                harness="cline",
                artifact_type="harness_host",
                source_scope="global",
                config_path=str(Path(hosts.cli_executable).parent),
                command=hosts.cli_executable,
                metadata={"version": hosts.cli_version or "unknown", "surface": "cli"},
            )
        )
    for version in hosts.vscode_versions:
        artifacts.append(
            GuardArtifact(
                artifact_id=f"cline:host:vscode:{version}",
                name="Cline VS Code",
                harness="cline",
                artifact_type="harness_host",
                source_scope="global",
                config_path=str(context.home_dir / ".vscode" / "extensions"),
                metadata={"version": version, "surface": "vscode"},
            )
        )
    for index, path in enumerate(hosts.jetbrains_paths):
        artifacts.append(
            GuardArtifact(
                artifact_id=f"cline:host:jetbrains:{index}",
                name="Cline JetBrains",
                harness="cline",
                artifact_type="harness_host",
                source_scope="global",
                config_path=path,
                metadata={"surface": "jetbrains", "protection_status": "unverified"},
            )
        )
    return tuple(artifacts)


def _surface(value: str | None, *, default: str) -> str:
    normalized = (value or default).strip().lower()
    if normalized == "editor":
        normalized = "hooks"
    if normalized not in _CLINE_SURFACES:
        raise ValueError(f"Unsupported Cline surface: {value}")
    return normalized


class ClineHarnessAdapter(HarnessAdapter):
    """Discover and manage Cline through one proven enforcement transport."""

    harness = "cline"
    aliases = ("cline-cli", "cline-vscode")
    executable = "cline"
    launcher_name = "cline"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard blocks Cline PreToolUse actions synchronously and routes review-required actions through the local "
        "approval center."
    )
    fallback_hint = "Resolve the Guard request, then retry the exact Cline tool action."
    approval_prompt_channel = "browser"
    approval_auto_open_browser = True

    def detect(self, context: HarnessContext) -> HarnessDetection:
        hosts = detect_cline_hosts(context)
        mcp = detect_cline_mcp(context)
        config_paths: list[str] = list(mcp.config_paths)
        for path in (
            context.home_dir / ".cline" / "hooks",
            context.home_dir / ".cline" / "plugins",
            context.home_dir / "Documents" / "Cline" / "Hooks",
            context.home_dir / "Documents" / "Cline" / "Plugins",
        ):
            if path.exists():
                config_paths.append(str(path))
        hook_state = cline_native_hook_state(context)
        plugin_state = cline_plugin_state(context)
        warnings: list[str] = []
        if hook_state.get("installed") and plugin_state.get("installed"):
            warnings.append(
                "Guard found both managed Cline enforcement transports. "
                "Run `hol-guard apps repair cline` to restore one transport."
            )
        if hosts.jetbrains_paths:
            warnings.append(
                "Cline JetBrains was detected, but Guard does not mark that IDE protected until a live pre-tool "
                "deny proof is observed."
            )
        return HarnessDetection(
            harness=self.harness,
            installed=bool(hosts.hosts or config_paths or hook_state.get("installed") or plugin_state.get("installed")),
            command_available=hosts.cli_executable is not None,
            config_paths=tuple(dict.fromkeys(config_paths)),
            artifacts=(*_host_artifacts(hosts, context), *mcp.artifacts),
            warnings=tuple(warnings),
        )

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return detect_cline_hosts(context).cli_executable

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [self.resolved_executable(context) or self.executable, *passthrough_args]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        return (self.launch_command(context, passthrough_args),)

    def _auto_transport(self, hosts: ClineHostDetection) -> str:
        if hosts.cli_executable and not hosts.vscode_versions and not hosts.jetbrains_paths:
            return "plugin"
        return "hooks"

    def _install_transport(self, context: HarnessContext, transport: str) -> dict[str, object]:
        if transport == "plugin":
            manifest = install_cline_plugin(context)
            syntax = cline_plugin_syntax_probe(context)
            if syntax.get("ok") is not True:
                uninstall_cline_plugin(context)
                raise RuntimeError("Guard-generated Cline plugin did not pass its syntax probe")
            manifest["syntax_probe"] = syntax
            return manifest
        if transport == "hooks":
            manifest = install_cline_hooks(context)
            canary = manifest.get("synthetic_canary")
            if not isinstance(canary, dict) or canary.get("ok") is not True:
                uninstall_cline_hooks(context)
                raise RuntimeError("Guard-generated Cline native hooks did not pass their bounded canary")
            return manifest
        raise ValueError(f"Unsupported Cline enforcement transport: {transport}")

    def _reconcile_transport(self, context: HarnessContext, transport: str) -> dict[str, object]:
        previous = _load_adapter_state(context).get("active_transport")
        manifest = self._install_transport(context, transport)
        target_state = cline_plugin_state(context) if transport == "plugin" else cline_native_hook_state(context)
        other_state = cline_native_hook_state(context) if transport == "plugin" else cline_plugin_state(context)
        transition_pending = bool(other_state.get("installed")) and not bool(target_state.get("ready"))
        removed_other: dict[str, object] | None = None
        if other_state.get("installed") and (target_state.get("ready") or not other_state.get("ready")):
            removed_other = uninstall_cline_hooks(context) if transport == "plugin" else uninstall_cline_plugin(context)
            transition_pending = False
        return {
            **manifest,
            "active_transport": transport,
            "previous_transport": previous if isinstance(previous, str) else None,
            "transition_pending_live_proof": transition_pending,
            "inactive_transport_cleanup": removed_other,
        }

    def install(self, context: HarnessContext, *, surface: str = "auto") -> dict[str, object]:
        selected_surface = _surface(surface, default="auto")
        hosts = detect_cline_hosts(context)
        requested_transport = (
            selected_surface if selected_surface in {"hooks", "plugin"} else self._auto_transport(hosts)
        )
        try:
            transport_manifest = self._reconcile_transport(context, requested_transport)
        except RuntimeError:
            if selected_surface not in {"auto", "all", "cli"} or requested_transport == "hooks":
                raise
            requested_transport = "hooks"
            transport_manifest = self._reconcile_transport(context, requested_transport)
            transport_manifest["fallback_from_plugin"] = True
        shim_manifest: dict[str, object] | None = None
        mcp_manifest: dict[str, object] | None = None
        if selected_surface in {"auto", "cli", "all"}:
            shim_manifest = install_guard_shim(self.harness, context, launcher_name="cline", display_name="Cline CLI")
            shim_manifest["shell_profile"] = ensure_guard_shim_path_in_shell_profile(context)
        if selected_surface in {"auto", "all"}:
            mcp_manifest = install_cline_mcp_proxies(context)
        hook_state = cline_native_hook_state(context)
        plugin_state = cline_plugin_state(context)
        mcp_state = cline_mcp_proxy_state(context)
        manifest: dict[str, object] = {
            "schema_version": _STATE_SCHEMA,
            "harness": self.harness,
            "active": True,
            "surface": selected_surface,
            "surfaces": [selected_surface],
            "active_transport": requested_transport,
            "transport": transport_manifest,
            "hosts": {
                "cli_version": hosts.cli_version,
                "vscode_versions": list(hosts.vscode_versions),
                "jetbrains_detected": bool(hosts.jetbrains_paths),
            },
            "native_hooks": hook_state,
            "plugin": plugin_state,
            "mcp": mcp_state,
            "shim": shim_manifest,
            "mcp_install": mcp_manifest,
            "coverage": self._coverage_label(hosts, requested_transport, hook_state, plugin_state),
            "blind_spots": self._blind_spots(hosts, requested_transport),
        }
        if shim_manifest:
            manifest["shim_path"] = shim_manifest.get("shim_path")
            manifest["shim_command"] = shim_manifest.get("shim_command")
        _atomic_json(
            _adapter_state_path(context),
            {
                "schema_version": _STATE_SCHEMA,
                "active_transport": requested_transport,
                "surface": selected_surface,
            },
        )
        return manifest

    def uninstall(self, context: HarnessContext, *, surface: str = "all") -> dict[str, object]:
        selected_surface = _surface(surface, default="all")
        hook_result: dict[str, object] | None = None
        plugin_result: dict[str, object] | None = None
        shim_result: dict[str, object] | None = None
        mcp_result: dict[str, object] | None = None
        if selected_surface in {"auto", "all", "hooks"}:
            hook_result = uninstall_cline_hooks(context)
        if selected_surface in {"auto", "all", "plugin"}:
            plugin_result = uninstall_cline_plugin(context)
        if selected_surface in {"auto", "all", "cli"}:
            shim_result = remove_guard_shim(self.harness, context, launcher_name="cline", display_name="Cline CLI")
        if selected_surface in {"auto", "all"}:
            mcp_result = restore_cline_mcp_proxies(context)
        complete = all(
            result is None or result.get("complete", True) is True
            for result in (hook_result, plugin_result, mcp_result)
        )
        if complete and selected_surface in {"auto", "all"} and _adapter_state_path(context).is_file():
            _adapter_state_path(context).unlink()
        return {
            "harness": self.harness,
            "active": not (selected_surface in {"auto", "all"} and complete),
            "surface": selected_surface,
            "native_hooks": hook_result,
            "plugin": plugin_result,
            "shim": shim_result,
            "mcp": mcp_result,
            "complete": complete,
        }

    def _coverage_label(
        self,
        hosts: ClineHostDetection,
        transport: str,
        hook_state: dict[str, object],
        plugin_state: dict[str, object],
    ) -> str:
        if transport == "plugin":
            if plugin_state.get("ready") is True:
                return "full"
            return "pending-live-proof"
        if hook_state.get("ready") is True:
            return "pre-execution"
        if hosts.jetbrains_paths:
            return "unverified"
        return "pending-live-proof"

    @staticmethod
    def _blind_spots(hosts: ClineHostDetection, transport: str) -> list[str]:
        blind_spots: list[str] = []
        if transport == "hooks":
            blind_spots.append(
                "Native PostToolUse is observation-only; use the plugin transport for model-visible output replacement."
            )
        if hosts.jetbrains_paths:
            blind_spots.append(
                "JetBrains runtime protection is unverified until Guard observes a live pre-tool deny proof."
            )
        return blind_spots

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        hosts = detect_cline_hosts(context)
        hook_state = cline_native_hook_state(context)
        plugin_state = cline_plugin_state(context)
        active_transport = _load_adapter_state(context).get("active_transport")
        duplicate = bool(hook_state.get("installed") and plugin_state.get("installed"))
        return {
            "hosts": list(hosts.hosts),
            "cli_version": hosts.cli_version,
            "vscode_versions": list(hosts.vscode_versions),
            "jetbrains_detected": bool(hosts.jetbrains_paths),
            "active_transport": active_transport,
            "native_hooks": hook_state,
            "plugin": plugin_state,
            "mcp": cline_mcp_proxy_state(context),
            "duplicate_managed_transports": duplicate,
        }

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        warnings = list(detection.warnings)
        if runtime_probe is None:
            return warnings
        if runtime_probe.get("duplicate_managed_transports") is True:
            warnings.append("Both Guard-managed Cline transports are present; run `hol-guard apps repair cline`.")
        transport = runtime_probe.get("active_transport")
        state = runtime_probe.get("plugin") if transport == "plugin" else runtime_probe.get("native_hooks")
        if isinstance(state, dict) and state.get("ready") is not True:
            warnings.append(
                "Cline protection is installed but live runtime proof is pending or stale. "
                "Run a safe Cline tool action, then `hol-guard apps test cline`."
            )
        if runtime_probe.get("jetbrains_detected") is True:
            warnings.append("Cline JetBrains remains unverified until a live pre-tool proof is recorded.")
        return warnings


__all__ = ["ClineHarnessAdapter"]
