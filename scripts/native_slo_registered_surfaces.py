"""Read actual nonpriority hook registrations before starting their processes.

These readers consume the installed adapter files. They never reconstruct a
Guard CLI invocation or substitute an HTTP request for a registered command.
Only private qualification homes are supported; third-party hook chains are
rejected rather than silently omitted from the execution boundary.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.cline_state_paths import canonical_cline_state_path, cline_hook_command
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hooks_path, install_cursor_hooks
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.config import resolve_guard_home_for_user_home
from codex_plugin_scanner.guard.windows_paths import windows_command_line_to_argv

CONFIG_LIMIT = 1_000_000
SURFACE_EVENTS = {
    "cursor": (
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "beforeWriteFile",
        "afterShellExecution",
        "afterMCPExecution",
    ),
    "copilot": ("preToolUse", "postToolUse"),
    "kimi": ("PreToolUse", "PostToolUse"),
    "grok": ("PreToolUse",),
    "zcode": ("PreToolUse",),
    "cline": ("PreToolUse", "PostToolUse"),
}
_ZCODE_MATCHERS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__.*",
    "run_terminal_command",
    "run_command",
    "read_file",
    "write_file",
    "search_replace",
    "multi_edit",
    "grep",
    "web_fetch",
    "web_search",
)
_TOML = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")


class SurfaceUnavailableError(RuntimeError):
    """An explicit installed-path limitation, never a successful observation."""


@dataclass(frozen=True, slots=True)
class RegisteredSurface:
    harness: str
    event: str
    scope: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cwd: Path
    config_path: Path
    registration_sha256: str
    matchers: tuple[str, ...] = ()
    artifact_sha256: tuple[tuple[str, str], ...] = ()


def _bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(CONFIG_LIMIT + 1)
    if len(raw) > CONFIG_LIMIT:
        raise RuntimeError("registered_surface_configuration_limit")
    return raw


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RuntimeError("registered_surface_configuration_invalid")
    return cast(Mapping[str, object], value)


def _read(path: Path) -> Mapping[str, object]:
    raw = _bytes(path)
    try:
        return _mapping(_TOML.loads(raw.decode("utf-8")) if path.suffix == ".toml" else json.loads(raw))
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("registered_surface_configuration_invalid") from error


def _entries(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("registered_surface_registration_missing")
    result = [_mapping(item) for item in value]
    if any(item.get("enabled", True) is not True for item in result):
        raise RuntimeError("registered_surface_registration_disabled")
    return result


def _command(value: object, *, windows: bool, zcode: bool = False) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeError("registered_surface_command_invalid")
    if zcode:
        marker = " # HOL_GUARD_MANAGED_ZCODE"
        if not value.endswith(marker):
            raise RuntimeError("registered_surface_zcode_marker_missing")
        if windows:
            # list2cmdline does not make '#' a cmd.exe comment. Do not silently
            # strip arguments and pretend that the host ran this registration.
            raise SurfaceUnavailableError("zcode_windows_shell_comment_unqualified")
        value = value[: -len(marker)]
    if windows:
        parsed = windows_command_line_to_argv(value)
        if not parsed:
            raise SurfaceUnavailableError("windows_command_line_parser_unavailable")
        canonical = subprocess.list2cmdline(parsed)
    else:
        try:
            parsed = shlex.split(value, posix=True)
        except ValueError as error:
            raise RuntimeError("registered_surface_command_invalid") from error
        canonical = shlex.join(parsed)
    if not parsed or canonical != value or any("\x00" in argument for argument in parsed):
        raise RuntimeError("registered_surface_command_not_lossless")
    if not Path(parsed[0]).is_absolute():
        raise RuntimeError("registered_surface_executable_not_absolute")
    return tuple(parsed)


def _bridge(argv: tuple[str, ...], harness: str, context: HarnessContext) -> None:
    if len(argv) != 5 or argv[1:3] != ("-I", "-c"):
        raise SurfaceUnavailableError("registered_surface_non_python_bridge_unqualified")
    if "codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv" not in argv[3]:
        raise RuntimeError("registered_surface_unmanaged_handler")
    try:
        config = _mapping(json.loads(argv[4]))
    except ValueError as error:
        raise RuntimeError("registered_surface_bridge_invalid") from error
    if config.get("harness") != harness or config.get("guard_home") != str(context.guard_home.resolve()):
        raise RuntimeError("registered_surface_bridge_context_mismatch")


def _environment(handler: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    value = _mapping(handler.get("env", {}))
    if any(not isinstance(item, str) for item in value.values()):
        raise RuntimeError("registered_surface_environment_invalid")
    return tuple(sorted(cast(Mapping[str, str], value).items()))


def _registered(
    context: HarnessContext,
    harness: str,
    event: str,
    scope: str,
    path: Path,
) -> RegisteredSurface:
    config = _read(path)
    hooks = config.get("hooks")
    matchers: tuple[str, ...] = ()
    if harness == "kimi":
        handlers = [item for item in _entries(hooks) if item.get("event") == event]
    else:
        hooks = _mapping(hooks)
        if harness == "zcode":
            hooks = _mapping(hooks.get("events"))
        groups = _entries(hooks.get(event))
        if harness in {"grok", "zcode"}:
            if harness == "zcode":
                raw_matchers = tuple(group.get("matcher") for group in groups)
                if len(raw_matchers) != len(_ZCODE_MATCHERS) or set(raw_matchers) != set(_ZCODE_MATCHERS):
                    raise RuntimeError("registered_surface_zcode_matchers_mismatch")
                matchers = cast(tuple[str, ...], raw_matchers)
            elif any(group.get("matcher") for group in groups):
                raise RuntimeError("registered_surface_grok_not_catchall")
            handlers = [handler for group in groups for handler in _entries(group.get("hooks"))]
        else:
            handlers = groups
    if len(handlers) != (len(_ZCODE_MATCHERS) if harness == "zcode" else 1):
        raise RuntimeError("registered_surface_registration_ambiguous")
    variants: list[tuple[tuple[str, ...], tuple[tuple[str, str], ...], Path]] = []
    for handler in handlers:
        if harness not in {"cursor", "kimi"} and handler.get("type") != "command":
            raise RuntimeError("registered_surface_handler_not_command")
        if harness == "cursor" and handler.get("failClosed") is not event.startswith("before"):
            raise RuntimeError("registered_surface_cursor_fail_closed_mismatch")
        key = ("powershell" if os.name == "nt" else "bash") if harness == "copilot" else "command"
        argv = _command(handler.get(key), windows=os.name == "nt" and harness != "cursor", zcode=harness == "zcode")
        if harness == "cursor":
            if len(argv) != 4 or Path(argv[1]) != context.home_dir / ".cursor/hooks/hol-guard-cursor-hook.py":
                raise RuntimeError("registered_surface_cursor_script_mismatch")
            if argv[-2:] != ("--cursor-hook-event", event):
                raise RuntimeError("registered_surface_cursor_event_mismatch")
        else:
            _bridge(argv, harness, context)
        cwd_value = handler.get("cwd", str(context.workspace_dir or context.home_dir))
        if not isinstance(cwd_value, str) or not Path(cwd_value).is_absolute():
            raise RuntimeError("registered_surface_cwd_invalid")
        variants.append((argv, _environment(handler), Path(cwd_value)))
    if len(set(variants)) != 1:
        raise RuntimeError("registered_surface_registration_ambiguous")
    argv, environment, cwd = variants[0]
    artifacts = ()
    if harness == "cursor":
        artifacts = (("cursor_worker", hashlib.sha256(_bytes(Path(argv[1]))).hexdigest()),)
    return RegisteredSurface(
        harness,
        event,
        scope,
        argv,
        environment,
        cwd,
        path,
        hashlib.sha256(_bytes(path)).hexdigest(),
        matchers,
        artifacts,
    )


def _cline(context: HarnessContext, event: str) -> RegisteredSurface:
    path = context.guard_home / "managed/cline/native-hooks-state.json"
    state = _read(path)
    active = _read(context.guard_home / "managed/cline/adapter-state.json")
    if active.get("active_transport") != "hooks" or state.get("transport") != "hooks":
        raise RuntimeError("registered_surface_cline_inactive")
    artifacts: list[tuple[str, str]] = []
    slot = None
    for group, digest_group, worker in (("paths", "sha256", False), ("workers", "worker_sha256", True)):
        target = canonical_cline_state_path(
            context,
            event,
            _mapping(state.get(group)).get(event),
            worker=worker,
            saved_root=state.get("root"),
        )
        if target is None:
            raise RuntimeError("registered_surface_cline_path_invalid")
        digest = hashlib.sha256(_bytes(target)).hexdigest()
        if digest != _mapping(state.get(digest_group)).get(event):
            raise RuntimeError("registered_surface_cline_artifact_changed")
        artifacts.append((group, digest))
        if not worker:
            slot = target
    assert slot is not None
    argv = tuple(cline_hook_command(slot))
    if not argv:
        raise SurfaceUnavailableError("cline_trusted_interpreter_unavailable")
    return RegisteredSurface(
        "cline",
        event,
        "global",
        argv,
        (),
        context.workspace_dir or context.home_dir,
        path,
        hashlib.sha256(_bytes(path)).hexdigest(),
        artifact_sha256=tuple(artifacts),
    )


def read_registered_surfaces(context: HarnessContext, harness: str) -> tuple[RegisteredSurface, ...]:
    if harness not in SURFACE_EVENTS:
        raise ValueError("registered_surface_harness_unsupported")
    if harness == "cline":
        return tuple(_cline(context, event) for event in SURFACE_EVENTS[harness])
    if harness == "cursor":
        paths = (("global", cursor_hooks_path(context)),)
    elif harness == "copilot":
        paths = (("global", CopilotHarnessAdapter._config_path(context)),)
        project = CopilotHarnessAdapter._hook_path(context)
        if project is not None:
            paths += (("project", project),)
    elif harness == "kimi":
        paths = (("global", KimiHarnessAdapter()._managed_config_path(context)),)
    elif harness == "grok":
        paths = (("global", GrokHarnessAdapter._hooks_dir(context) / "hol-guard-pretooluse.json"),)
    else:
        paths = (("global", ZCodeHarnessAdapter._config_path(context)),)
    return tuple(
        _registered(context, harness, event, scope, path) for scope, path in paths for event in SURFACE_EVENTS[harness]
    )


def install_registered_surface(context: HarnessContext, harness: str) -> tuple[RegisteredSurface, ...]:
    """Use the shipped installer, then read exact commands from its live files."""
    if harness not in SURFACE_EVENTS:
        raise ValueError("registered_surface_harness_unsupported")
    for name in ("KIMI_CODE_HOME", "GROK_HOME", "ZCODE_HOME", "CLINE_DATA_DIR", "CLINE_DIR"):
        if os.environ.get(name):
            raise SurfaceUnavailableError("registered_surface_ambient_home_override")
    if harness == "cline":
        if context.guard_home != resolve_guard_home_for_user_home(context.home_dir):
            raise SurfaceUnavailableError("cline_requires_default_guard_home")
        ClineHarnessAdapter().install(context, surface="hooks")
    elif harness == "cursor":
        install_cursor_hooks(context)
    else:
        adapters = {
            "copilot": CopilotHarnessAdapter,
            "kimi": KimiHarnessAdapter,
            "grok": GrokHarnessAdapter,
            "zcode": ZCodeHarnessAdapter,
        }
        adapters[harness]().install(context)
    return read_registered_surfaces(context, harness)
