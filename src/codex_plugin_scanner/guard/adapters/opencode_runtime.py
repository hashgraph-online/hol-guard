"""OpenCode through the native ``harness_adapter`` kind.

The kind owns OpenCode's paths, detection, install and uninstall plans, the
pretool plugin, the protection checks and the launcher refresh. This module
keeps what must run in the Guard process: the home-scoped config lock held
across a publish, Guard's own proxy argv and launcher environment, the
attested Guard CLI the plugin runs, the probe subprocesses and the
``opencode_launch`` runner calls.
"""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask, detection_from, planned_files

if TYPE_CHECKING:
    from ..store import GuardStore

_HARNESS = "opencode"
_PROXY = "opencode-mcp-proxy"
_HOOK_TIMEOUT_SECONDS = 25


@contextmanager
def opencode_config_lock(home_dir: Path, *, timeout: float = 5.0) -> Iterator[None]:
    """Serialize Guard's OpenCode config readers and writers on one home-scoped lock.

    Lock before reading configs and keep it through writes and rollback. OpenCode
    and editors do not take it; byte comparisons catch their earlier edits.
    """
    from ..mdm.file_lock import release_file_lock
    from ..native_daemon_manage import try_lock_daemon_file

    path = home_dir / ".config" / "opencode" / ".hol-guard-config.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("OpenCode config lock must not be a symlink")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        info = os.fstat(handle.fileno())
        opened_path = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(opened_path.st_mode)
            or getattr(opened_path, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or (info.st_dev, info.st_ino) != (opened_path.st_dev, opened_path.st_ino)
            or info.st_nlink != 1
        ):
            raise ValueError("OpenCode config lock path changed or is not a regular file without hard-link aliases")
        if os.name != "nt" and info.st_uid != os.geteuid():
            raise ValueError("OpenCode config lock must be owned by the current user on POSIX")
        deadline = time.monotonic() + timeout
        while not try_lock_daemon_file(handle):
            if time.monotonic() >= deadline:
                raise TimeoutError("Another Guard operation is updating OpenCode config; try again shortly")
            time.sleep(0.05)
        try:
            yield
        finally:
            release_file_lock(handle)


def _guard_proxy_command(context: HarnessContext, proxy_args: list[str]) -> list[str]:
    from .hook_python import guard_cli_command
    from .mcp_relay_native import mcp_proxy_command

    return mcp_proxy_command(guard_cli_command(context, proxy_args))


def plugin_render_args(context: HarnessContext) -> dict[str, object]:
    """The attested Guard CLI facts the native kind renders the pretool plugin from."""
    from ..codex_hook_windows_job import windows_system_executable_path
    from .bounded_cli_hook_bridge import bounded_cli_hook_command
    from .guard_cli_attestation import executable_identity_payload, resolve_attested_guard_cli

    guard_cli = resolve_attested_guard_cli(context)
    identity = guard_cli.frozen_identity or (guard_cli.python.identity if guard_cli.python is not None else None)
    if identity is None:
        raise RuntimeError("Guard could not attest the OpenCode hook runtime.")
    native_bridge_argv: list[str] | None = None
    import_roots: list[str] = []
    if guard_cli.python is not None:
        # The plugin fills in the interpreter and the per-workspace CLI argv
        # when it runs a hook; the native kind keeps this argv only when it is
        # the bounded native bridge.
        native_bridge_argv = list(
            bounded_cli_hook_command(
                python_executable=str(guard_cli.python.executable),
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=[],
                harness=_HARNESS,
                timeout_seconds=_HOOK_TIMEOUT_SECONDS,
            )
        )
        import_roots = [str(root) for root in guard_cli.python.import_roots]
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    return {
        "guard_home": str(context.guard_home.resolve()),
        "python": executable_identity_payload(identity),
        "frozen": guard_cli.frozen,
        "native_bridge_argv": native_bridge_argv,
        "import_roots": import_roots,
        "taskkill_path": taskkill_path,
    }


def refresh_opencode_proxy_launchers(context: HarnessContext, *, warnings: list[str] | None = None) -> int:
    """Refresh verified Guard CLI prefixes without changing server or tool authority."""
    with opencode_config_lock(context.home_dir):
        scan = ask("refresh_scan", context, harness=_HARNESS)
        if warnings is not None:
            warnings.extend(str(warning) for warning in scan["warnings"])
        commands = [
            {
                "path": candidate["path"],
                "name": candidate["name"],
                "digest": candidate["digest"],
                "command": _guard_proxy_command(
                    context, ["-m", "codex_plugin_scanner.cli", "guard", *candidate["proxy_args"]]
                ),
            }
            for candidate in scan["candidates"]
        ]
        answer = ask("refresh_apply", context, harness=_HARNESS, commands=json.dumps(commands))
        return int(answer["refreshed"])


def opencode_protection_checks(context: HarnessContext, store: GuardStore | None) -> dict[str, object]:
    """Verify the managed OpenCode plugin, launcher and MCP routing configuration."""
    from . import get_adapter

    managed = store.get_managed_install(_HARNESS) if store is not None else None
    answer = ask(
        "protection",
        context,
        harness=_HARNESS,
        managed_active=bool(managed and managed.get("active")),
        config_paths=list(get_adapter(_HARNESS).detect(context).config_paths),
    )
    return json.loads(str(answer["checks"]))


class OpenCodeHarnessAdapter(NativeHarnessAdapter):
    """OpenCode, with Guard's MCP proxy argv and attested plugin facts."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def install(self, context: HarnessContext) -> dict[str, object]:
        with opencode_config_lock(context.home_dir):
            return self.prepare_install(context).publish(context.guard_home)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Render the whole install without taking the write-creating config lock."""
        from .hook_python import disposable_guard_hook_probe

        with disposable_guard_hook_probe():
            return self._plan_install(context)

    def _plan_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..launcher import merge_guard_launcher_env
        from ..shims import prepare_guard_shim
        from .mcp_servers import managed_stdio_servers, proxy_cli_args, proxy_process_env, skipped_stdio_server_names

        found = self._ask("install_detection", context)
        detection = detection_from(self.harness, context, found)
        home = str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None
        workspace = None if context.workspace_dir is None else str(context.workspace_dir)
        servers: list[dict[str, Any]] = []
        for server in managed_stdio_servers(detection):
            launches = [
                _guard_proxy_command(
                    context,
                    proxy_cli_args(
                        proxy_command=_PROXY,
                        guard_home=str(context.guard_home),
                        server=server,
                        home=home,
                        workspace=launch_workspace,
                    ),
                )
                for launch_workspace in (None, workspace)
            ]
            servers.append(
                {
                    "name": server.name,
                    "source_scope": server.source_scope,
                    "config_path": server.config_path,
                    "command": server.command,
                    "args": list(server.args),
                    "env": dict(server.env),
                    "enabled": server.enabled,
                    "proxy_environment": merge_guard_launcher_env(proxy_process_env(server.env)),
                    "launches": launches,
                }
            )
        artifacts = [artifact.name for artifact in detection.artifacts if artifact.artifact_type == "mcp_server"]
        plugin = plugin_render_args(context)
        shim = prepare_guard_shim(self.harness, context)
        answer = self._ask(
            "prepare_install",
            context,
            digest=found["digest"],
            shim=json.dumps(shim.manifest),
            servers=json.dumps(servers),
            skipped=json.dumps(list(skipped_stdio_server_names(detection))),
            artifacts=json.dumps(artifacts),
            source_config_paths=json.dumps(list(detection.config_paths)),
            plugin=plugin,
        )
        return PreparedHarnessInstall((*shim.files, *planned_files(answer)), json.loads(str(answer["manifest"])))

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        with opencode_config_lock(context.home_dir):
            return super().uninstall(context)

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        request = {"op": "environment", "inline": os.getenv("OPENCODE_CONFIG_CONTENT")}
        content = native_runner_authority("opencode_launch", request, guard_home=context.guard_home).get("content")
        return {"OPENCODE_CONFIG_CONTENT": content} if isinstance(content, str) else {}

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
        request = {"op": "argv", "args": "\0".join(passthrough_args), "count": len(passthrough_args)}
        answer = native_runner_authority("opencode_launch", request | {"workspace": workspace}, context.guard_home)
        argv, count = answer.get("argv"), answer.get("count")
        if not isinstance(argv, str) or not isinstance(count, int) or len(command := argv.split("\0")) != count:
            raise NativeRunnerAuthorityError("native_opencode_launch_invalid")
        return command

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        commands = self._ask("runtime_probe", context).get("commands")
        if not isinstance(commands, list):
            return None
        return {str(name): _run_command_probe([str(part) for part in argv]) for name, argv in commands}


__all__ = [
    "OpenCodeHarnessAdapter",
    "opencode_config_lock",
    "opencode_protection_checks",
    "plugin_render_args",
    "refresh_opencode_proxy_launchers",
]
