"""OpenCode through the native ``harness_adapter`` kind.

The kind owns OpenCode's paths, detection, install and uninstall plans, the
pretool plugin, the protection checks and the launcher refresh. This module
keeps what must run in the Guard process: the home-scoped config lock held
across a publish, the attested Guard CLI the plugin runs, the probe
subprocesses and the ``opencode_launch`` runner calls.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask

if TYPE_CHECKING:
    from ..store import GuardStore

_HARNESS = "opencode"
_HOOK_TIMEOUT_SECONDS = 25
_REPLY_LIMIT = 32
_INSTALL_OPS = frozenset({"prepare_install", "apply_install"})


@contextmanager
def opencode_config_lock(home_dir: Path, *, timeout: float = 5.0) -> Iterator[None]:
    """Serialize Guard's OpenCode config readers and writers on one home-scoped lock.

    Lock before reading configs and keep it through writes and rollback. OpenCode
    and editors do not take it; byte comparisons catch their earlier edits. The
    resident opens, checks and holds the lock file (``transition_files/lock_files.rs``).
    """
    from ..native_transition_files import acquire_lease, release_lease

    request: dict[str, object] = {"lock": "opencode", "home_dir": str(home_dir)}
    try:
        lease = acquire_lease(request, wait=True, deadline=time.monotonic() + timeout)
    except TimeoutError:
        raise TimeoutError("Another Guard operation is updating OpenCode config; try again shortly") from None
    except RuntimeError as error:
        raise ValueError(str(error)) from None
    try:
        yield
    finally:
        release_lease(lease)


def plugin_render_args(context: HarnessContext) -> dict[str, object]:
    """The attested Guard CLI facts the native kind renders the pretool plugin from."""
    from ..codex_hook_windows_job import windows_system_executable_path
    from .bounded_cli_hook_bridge import bounded_hook_command_for_config
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
        config = ask("hook_config", context, harness=_HARNESS, cli_args=[], timeout_seconds=_HOOK_TIMEOUT_SECONDS)[
            "config"
        ]
        native_bridge_argv = list(bounded_hook_command_for_config(str(config)))
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


def _answer_reply(context: HarnessContext, key: str, fields: dict[str, Any]) -> None:
    """Fill the one fact the native install asked for."""
    from .hook_python import disposable_guard_hook_probe

    if key == "plugin":
        with disposable_guard_hook_probe():
            fields["plugin"] = plugin_render_args(context)
    elif key == "workspace_skills":
        from ..aibom_detection import portable_workspace_skills

        fields["workspace_skills"] = portable_workspace_skills(_HARNESS, context.workspace_dir)
    else:
        raise ValueError("OpenCode adapter reply is malformed")


def refresh_opencode_proxy_launchers(context: HarnessContext, *, warnings: list[str] | None = None) -> int:
    """Refresh verified Guard CLI prefixes without changing server or tool authority."""
    with opencode_config_lock(context.home_dir):
        answer = ask("refresh_apply", context, harness=_HARNESS)
        if warnings is not None:
            warnings.extend(str(warning) for warning in answer["warnings"])
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
    """OpenCode, with the launch and attested plugin facts of the Guard process."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def install(self, context: HarnessContext) -> dict[str, object]:
        with opencode_config_lock(context.home_dir):
            return super().install(context)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Render the whole install without taking the write-creating config lock."""
        from .hook_python import disposable_guard_hook_probe

        with disposable_guard_hook_probe():
            return super().prepare_install(context)

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        """Answer the facts the native install plan asks of this process, then re-ask."""
        if op not in _INSTALL_OPS:
            return super()._ask(op, context, **fields)
        for _ in range(_REPLY_LIMIT):
            answer = super()._ask(op, context, **fields)
            if set(answer) != {"reply"}:
                return answer
            reply = answer["reply"]
            if not isinstance(reply, dict) or len(reply) != 1:
                raise ValueError("OpenCode adapter reply is malformed")
            ((key, _),) = reply.items()
            _answer_reply(context, key, fields)
        raise RuntimeError("OpenCode adapter request did not settle")

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
