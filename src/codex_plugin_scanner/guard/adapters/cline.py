"""Cline harness adapter with native-hook and AgentPlugin enforcement transports."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..frozen_runtime_commands import is_frozen_guard_runtime
from ..models import GuardArtifact, HarnessDetection
from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from .base import HarnessAdapter, HarnessContext
from .cline_contract import register_cline_contract
from .cline_detection import (
    ClineHostDetection,
    cline_hosts,
    detect_cline_hosts,
    native_cline_inventory,
    resolve_cline_cli,
)
from .cline_hooks import cline_native_hook_state
from .cline_mcp import cline_mcp_proxy_state, cline_mcp_settings_candidates
from .cline_plugin import cline_plugin_state

register_cline_contract()

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


def _cli_host_artifact(hosts: ClineHostDetection) -> tuple[GuardArtifact, ...]:
    if not hosts.cli_executable:
        return ()
    return (
        GuardArtifact(
            artifact_id="cline:host:cli",
            name="Cline CLI",
            harness="cline",
            artifact_type="harness_host",
            source_scope="global",
            config_path=str(Path(hosts.cli_executable).parent),
            command=hosts.cli_executable,
            metadata={"version": hosts.cli_version or "unknown", "surface": "cli"},
        ),
    )


def _install_plan(context: HarnessContext, op: str, **fields: object) -> dict[str, object]:
    """Ask the native ``cline_install_plan`` kind for one install decision."""

    from ..native_context import _resolve_existing_digest_home
    from ..native_runner_authority import native_runner_authority

    home = _resolve_existing_digest_home(context.guard_home)
    return native_runner_authority("cline_install_plan", {"op": op, **fields}, guard_home=home)


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
        executable, version = resolve_cline_cli(context)
        native_artifacts, config_paths, native_warnings = native_cline_inventory(
            context, cline_mcp_settings_candidates(context)
        )
        hosts = cline_hosts(executable, version, native_artifacts)
        artifacts = tuple(enrich_artifact_with_mcp_skill_firewall(artifact) for artifact in native_artifacts)
        hook_state = cline_native_hook_state(context)
        plugin_state = cline_plugin_state(context)
        warnings: list[str] = []
        if hook_state.get("installed") and plugin_state.get("installed"):
            warnings.append(
                "Guard found both managed Cline enforcement transports. "
                "Run `hol-guard apps repair cline` to restore one transport."
            )
        warnings.extend(native_warnings)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(hosts.hosts or config_paths or hook_state.get("installed") or plugin_state.get("installed")),
            command_available=hosts.cli_executable is not None,
            config_paths=config_paths,
            artifacts=(*_cli_host_artifact(hosts), *artifacts),
            warnings=tuple(warnings),
        )

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return resolve_cline_cli(context)[0]

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [self.resolved_executable(context) or self.executable, *passthrough_args]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        return (self.launch_command(context, passthrough_args),)

    def _install_transport(self, context: HarnessContext, transport: str) -> dict[str, object]:
        from .cline_hooks import install_cline_hooks, uninstall_cline_hooks
        from .cline_plugin import cline_plugin_syntax_probe, install_cline_plugin, uninstall_cline_plugin

        if transport == "plugin":
            manifest = install_cline_plugin(context)
            syntax = cline_plugin_syntax_probe(context)
            if syntax.get("ok") is not True:
                uninstall_cline_plugin(context)
                raise RuntimeError("Guard-generated Cline plugin did not pass its syntax probe")
            manifest["syntax_probe"] = syntax
            return manifest
        if transport == "hooks":
            if is_frozen_guard_runtime():
                raise RuntimeError("Cline native-hook repair requires the managed plugin in HOL Guard Desktop.")
            manifest = install_cline_hooks(context)
            canary = manifest.get("synthetic_canary")
            if not isinstance(canary, dict) or canary.get("ok") is not True:
                uninstall_cline_hooks(context)
                raise RuntimeError("Guard-generated Cline native hooks did not pass their bounded canary")
            return manifest
        raise ValueError(f"Unsupported Cline enforcement transport: {transport}")

    def _reconcile_transport(self, context: HarnessContext, transport: str) -> dict[str, object]:
        from .cline_hooks import uninstall_cline_hooks
        from .cline_plugin import uninstall_cline_plugin

        previous = _load_adapter_state(context).get("active_transport")
        manifest = self._install_transport(context, transport)
        target_state = cline_plugin_state(context) if transport == "plugin" else cline_native_hook_state(context)
        other_state = cline_native_hook_state(context) if transport == "plugin" else cline_plugin_state(context)
        plan = _install_plan(
            context,
            "reconcile",
            target_ready=bool(target_state.get("ready")),
            other_installed=bool(other_state.get("installed")),
            other_ready=bool(other_state.get("ready")),
        )
        removed_other: dict[str, object] | None = None
        if plan.get("remove_other") is True:
            removed_other = uninstall_cline_hooks(context) if transport == "plugin" else uninstall_cline_plugin(context)
        return {
            **manifest,
            "active_transport": transport,
            "previous_transport": previous if isinstance(previous, str) else None,
            "transition_pending_live_proof": plan.get("transition_pending") is True,
            "inactive_transport_cleanup": removed_other,
        }

    def install(self, context: HarnessContext, *, surface: str = "auto") -> dict[str, object]:
        from ..shims import ensure_guard_shim_path_in_shell_profile, install_guard_shim
        from .cline_mcp import install_cline_mcp_proxies

        selected_surface = _surface(surface, default="auto")
        hosts = detect_cline_hosts(context)
        transport_plan = _install_plan(
            context,
            "transport",
            surface=selected_surface,
            frozen=is_frozen_guard_runtime(),
            cli=bool(hosts.cli_executable),
            vscode=bool(hosts.vscode_versions),
            jetbrains=bool(hosts.jetbrains_paths),
        )
        requested_transport = str(transport_plan.get("transport"))
        try:
            transport_manifest = self._reconcile_transport(context, requested_transport)
        except RuntimeError:
            if transport_plan.get("fallback") is not True:
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
            **_install_plan(
                context,
                "posture",
                transport=requested_transport,
                hook_ready=hook_state.get("ready") is True,
                plugin_ready=plugin_state.get("ready") is True,
                jetbrains=bool(hosts.jetbrains_paths),
            ),
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
        from ..shims import remove_guard_shim
        from .cline_hooks import uninstall_cline_hooks
        from .cline_mcp import restore_cline_mcp_proxies
        from .cline_plugin import uninstall_cline_plugin

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
