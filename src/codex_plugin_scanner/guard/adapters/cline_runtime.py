"""Cline through the native ``harness_adapter`` kind.

The kind owns Cline's paths, host and MCP discovery, both enforcement
transports (native hooks and the managed AgentPlugin), their state and
removal, the transport choice and the MCP settings rewrite. This module keeps
what must run in the Guard process: the attested Guard CLI the transports
run, the ``--version`` probe, the launcher shim and Guard's own MCP proxy
entries. The kind runs the hook canary and ``node --check`` itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import HarnessDetection
from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask, detection_from

if TYPE_CHECKING:
    from .mcp_servers import ManagedMcpServer

_HARNESS = "cline"
_DISPLAY_NAME = "Cline CLI"
_HOOK_WORKER_FEATURE = "cline-hook-worker-v1"
_BRIDGE_TIMEOUT_SECONDS = 8
# Ops that may run the hook canary (10s) and `node --check` (5s) inside the request.
_PROBE_TIMEOUT_SECONDS = 20.0


def _facts(context: HarnessContext, transport: str) -> dict[str, object]:
    """The attested Guard CLI the managed transport runs."""
    from ..frozen_runtime_commands import is_frozen_guard_runtime
    from .bounded_cli_hook_bridge import bounded_cli_hook_command
    from .guard_cli_attestation import guard_hook_command, resolve_attested_guard_cli
    from .native_hook_bridge import native_hook_bridge_executable

    attested = resolve_attested_guard_cli(context)
    hook_argv: list[str] | None = None
    if not attested.frozen and attested.python is not None:
        guard_args = ["guard", "hook", "--guard-home", str(context.guard_home), "--harness", _HARNESS]
        if context.home_dir.resolve() != Path.home().resolve():
            guard_args.extend(["--home", str(context.home_dir)])
        hook_argv = list(
            bounded_cli_hook_command(
                python_executable=str(attested.python.executable),
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=guard_args,
                harness=_HARNESS,
                timeout_seconds=_BRIDGE_TIMEOUT_SECONDS,
            )
        )
    runtime = None
    if transport == "hooks" and not is_frozen_guard_runtime():
        runtime = native_hook_bridge_executable(_HOOK_WORKER_FEATURE, guard_home=context.guard_home)
    return {
        "identity": attested.manifest_payload(),
        "guard_cli": list(guard_hook_command(attested, harness=_HARNESS)[:-3]),
        "hook_argv": hook_argv,
        "runtime": None if runtime is None else str(runtime),
        "python": attested.python is not None,
    }


def _reconcile(context: HarnessContext, transport: str, *, frozen: bool) -> dict[str, Any]:
    """Install one transport, run its probe and let the kind confirm it."""
    installed = ask(
        "install_transport",
        context,
        harness=_HARNESS,
        timeout_seconds=_PROBE_TIMEOUT_SECONDS,
        transport=transport,
        frozen=frozen,
        facts=_facts(context, transport),
    )
    probe = installed["probe"]
    fields = {"canary": probe["canary"]} if "canary" in probe else {"verdict": probe["result"]}
    manifest = json.dumps(installed["manifest"])
    return ask(
        "confirm_transport",
        context,
        harness=_HARNESS,
        timeout_seconds=_PROBE_TIMEOUT_SECONDS,
        transport=transport,
        manifest=manifest,
        **fields,
    )


def proxy_entry(context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
    """Guard's MCP proxy launcher in Cline's settings shape."""
    from .mcp_servers import proxy_launcher_entry

    return {**proxy_launcher_entry(proxy_command="cline-mcp-proxy", context=context, server=server), "type": "stdio"}


def install_mcp_proxies(context: HarnessContext) -> dict[str, Any]:
    """Route every local Cline MCP server through Guard's proxy."""
    from .mcp_servers import ManagedMcpServer

    entries: list[dict[str, object]] = []
    for found in ask("mcp_scan", context, harness=_HARNESS)["candidates"]:
        replacements = {
            row["name"]: proxy_entry(
                context,
                ManagedMcpServer(
                    harness=_HARNESS,
                    name=row["name"],
                    source_scope="global",
                    config_path=found["path"],
                    command=row["command"],
                    args=tuple(row["args"]),
                    transport=row["transport"],
                    env=row["env"],
                    enabled=True,
                ),
            )
            for row in found["managed"]
        }
        entries.append({**found, "replacements": json.dumps(replacements)})
    return ask("mcp_apply", context, harness=_HARNESS, entries=json.dumps(entries))


class ClineHarnessAdapter(NativeHarnessAdapter):
    """Discover and manage Cline through one proven enforcement transport."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, ("cline-cli", "cline-vscode"), "cline")

    def _cli(self, context: HarnessContext) -> dict[str, object]:
        """The Cline CLI and its ``--version`` output."""
        path = self.resolved_executable(context)
        if path is None:
            return {"path": None, "output": ""}
        probe = _run_command_probe([path, "--version"], timeout_seconds=3)
        output = "" if probe is None else f"{probe.get('stdout', '')}\n{probe.get('stderr', '')}"
        return {"path": path, "output": output}

    def detect(self, context: HarnessContext) -> HarnessDetection:
        from ..aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
        from ..native_runner_authority import NativeRunnerAuthorityError

        try:
            answer = ask(
                "detect",
                context,
                harness=_HARNESS,
                timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS,
                cli=self._cli(context),
            )
        except NativeRunnerAuthorityError as error:
            raise NativeAibomError(str(error)) from error
        return detection_from(_HARNESS, context, answer)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..runtime_transition import TransitionError

        raise TransitionError("adapter_preparation_unavailable")

    def install(self, context: HarnessContext, *, surface: str = "auto") -> dict[str, object]:
        from ..frozen_runtime_commands import is_frozen_guard_runtime
        from ..shims import ensure_guard_shim_path_in_shell_profile, install_guard_shim

        frozen = is_frozen_guard_runtime()
        cli = self._cli(context)
        plan = ask("install_plan", context, harness=_HARNESS, surface=surface, frozen=frozen, cli=cli)
        transport = str(plan["transport"])
        try:
            transport_manifest = _reconcile(context, transport, frozen=frozen)
        except RuntimeError:
            if plan["fallback"] is not True:
                raise
            transport = "hooks"
            transport_manifest = _reconcile(context, transport, frozen=frozen)
            transport_manifest["fallback_from_plugin"] = True
        shim: dict[str, object] | None = None
        if plan["shim"]:
            shim = install_guard_shim(_HARNESS, context, launcher_name="cline", display_name=_DISPLAY_NAME)
            shim["shell_profile"] = ensure_guard_shim_path_in_shell_profile(context)
        mcp_install = install_mcp_proxies(context) if plan["mcp"] else None
        return ask(
            "finish_install",
            context,
            harness=_HARNESS,
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            surface=plan["surface"],
            transport=transport,
            transport_manifest=json.dumps(transport_manifest),
            shim=None if shim is None else json.dumps(shim, default=str),
            mcp_install=None if mcp_install is None else json.dumps(mcp_install),
            cli=cli,
        )

    def uninstall(self, context: HarnessContext, *, surface: str = "all") -> dict[str, object]:
        from ..shims import remove_guard_shim

        answer = ask("uninstall", context, harness=_HARNESS, surface=surface)
        manifest: dict[str, object] = answer["manifest"]
        if answer["remove_shim"]:
            manifest["shim"] = remove_guard_shim(_HARNESS, context, launcher_name="cline", display_name=_DISPLAY_NAME)
        return manifest

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        cli = self._cli(context)
        return ask("runtime_probe", context, harness=_HARNESS, timeout_seconds=_PROBE_TIMEOUT_SECONDS, cli=cli)["probe"]

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        answer = ask(
            "diagnostic_warnings",
            HarnessContext(home_dir=Path.home(), workspace_dir=None, guard_home=Path.home()),
            harness=_HARNESS,
            warnings=list(detection.warnings),
            probe=None if runtime_probe is None else json.loads(json.dumps(runtime_probe, default=str)),
        )
        return [str(warning) for warning in answer["warnings"]]


__all__ = ["ClineHarnessAdapter"]
