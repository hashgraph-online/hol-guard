"""Cline through the native ``harness_adapter`` kind.

The kind owns Cline's paths, host and MCP discovery, both enforcement
transports (native hooks and the managed AgentPlugin), their state and
removal, the transport choice and the MCP settings rewrite. This module keeps
what must run in the Guard process: the attested Guard CLI the transports
run, the ``--version``, ``node --check`` and hook-canary subprocesses, the
launcher shim and Guard's own MCP proxy entries.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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
_CANARY_TIMEOUT_SECONDS = 10
_NODE_CHECK_TIMEOUT_SECONDS = 5


def _run_canary(canary: dict[str, Any]) -> dict[str, object]:
    """Run the bound PreToolUse launcher once with the synthetic read."""
    env = {**os.environ, "HOL_GUARD_CLINE_CANARY": "1"}
    try:
        result = subprocess.run(
            [str(part) for part in canary["argv"]],
            input=str(canary["input"]),
            capture_output=True,
            text=True,
            timeout=_CANARY_TIMEOUT_SECONDS,
            env=env,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"returncode": None, "stdout": "", "error": type(exc).__name__}
    return {"returncode": result.returncode, "stdout": result.stdout, "error": None}


def _node_check(path: str) -> dict[str, object]:
    """Syntax-check the generated plugin without executing it."""
    from ..codex_hook_launch_runtime import isolated_hook_environment

    node = shutil.which("node")
    if node is None:
        return {"ok": True, "skipped": True, "reason": "node_not_available"}
    try:
        result = subprocess.run(
            [node, "--check", "--", path],
            capture_output=True,
            text=True,
            timeout=_NODE_CHECK_TIMEOUT_SECONDS,
            check=False,
            env=isolated_hook_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "reason": type(exc).__name__}
    return {"ok": result.returncode == 0, "return_code": result.returncode}


def _ask(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """One op, asked again with the hook canary's run when the answer needs it."""
    answer = ask(op, context, harness=_HARNESS, **fields)
    if set(answer) == {"canary"} and isinstance(answer["canary"], dict):
        answer = ask(op, context, harness=_HARNESS, canary=_run_canary(answer["canary"]), **fields)
    return answer


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
        transport=transport,
        frozen=frozen,
        facts=_facts(context, transport),
    )
    probe = installed["probe"]
    fields: dict[str, Any] = {}
    if "node_check" in probe:
        fields["verdict"] = _node_check(str(probe["node_check"]))
    elif "canary" in probe:
        fields["canary"] = _run_canary(probe["canary"])
    else:
        fields["verdict"] = probe["result"]
    manifest = json.dumps(installed["manifest"])
    if "canary" in fields:
        return ask("confirm_transport", context, harness=_HARNESS, transport=transport, manifest=manifest, **fields)
    return _ask("confirm_transport", context, transport=transport, manifest=manifest, **fields)


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

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [self.resolved_executable(context) or self.executable, *passthrough_args]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        return (self.launch_command(context, passthrough_args),)

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
        return _ask(
            "finish_install",
            context,
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
        return _ask("runtime_probe", context, cli=self._cli(context))["probe"]

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
