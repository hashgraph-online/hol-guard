"""Bounded subprocess bridge for harnesses without a daemon-native hook."""

from __future__ import annotations

import json
import math
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..codex_hook_launch_runtime import (
    isolated_guard_cli_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from ..hook_execution_environment import stamp_hook_input_text
from ..stable_guard_cli import prune_safe_cli_executable
from ._modules.grok.grok_hook_invocation_template import configured_grok_payload
from .adapter_safe_output import write_text_at_authorized_path
from .bounded_cli_hook_envelope import (
    _canonical_event_token as _canonical_event_token,
)
from .bounded_cli_hook_envelope import (
    _event_name as _event_name,
)
from .bounded_cli_hook_envelope import (
    _grok_pretool_event_conflict as _grok_pretool_event_conflict,
)
from .bounded_cli_hook_envelope import (
    _has_json_object_line as _has_json_object_line,
)
from .bounded_cli_hook_envelope import (
    _json_object as _json_object,
)
from .bounded_cli_hook_failure import failure_payload as _failure_payload
from .bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
    bounded_python_argv,
    daemon_start_command,
    frozen_daemon_start_command,
    native_bridge_executable,
    take_native_handoff_environment,
)
from .bounded_cli_hook_script_template import BOUNDED_HOOK_SCRIPT_TEMPLATE
from .cursor_hook_config import isolated_cursor_hook_python
from .desktop_hook_proxy import (
    _DESKTOP_PROXY_LAUNCH_SCRIPT as _DESKTOP_PROXY_LAUNCH_SCRIPT,
)
from .desktop_hook_proxy import (
    _trusted_desktop_hook_proxy_command,
)
from .hook_input_reader import read_hook_input

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile

_FAILURE_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_TRAILING_MANAGED_MARKERS = frozenset({"HOL_GUARD_MANAGED_ZCODE"})
_FROZEN_BRIDGE_COMMAND = "__guard-bounded-hook"
_FROZEN_OPTIONAL_PATH_FLAGS = frozenset({"--home", "--workspace"})
_BOUNDED_HOOK_SCRIPT_DIR = ("managed", "bounded-hooks")


def _bounded_hook_script_stem(harness: str) -> str | None:
    stem = harness.strip().lower().replace("_", "-")
    if not stem or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in stem):
        return None
    return stem


def bounded_hook_script_path(guard_home: Path, harness: str) -> Path | None:
    """Return the managed stdlib hook client path for one harness."""

    stem = _bounded_hook_script_stem(harness)
    if stem is None:
        return None
    return guard_home.joinpath(*_BOUNDED_HOOK_SCRIPT_DIR, f"{stem}.py")


def _render_bounded_hook_script(*, guard_home: Path, harness: str, timeout_seconds: float) -> str:
    timeout_token = str(int(timeout_seconds)) if timeout_seconds == int(timeout_seconds) else str(timeout_seconds)
    return (
        BOUNDED_HOOK_SCRIPT_TEMPLATE.replace(
            "__GUARD_HOME__",
            json.dumps(str(guard_home.resolve(strict=False))),
        )
        .replace("__HARNESS__", json.dumps(harness.strip().lower().replace("_", "-")))
        .replace("__TIMEOUT_SECONDS__", timeout_token)
    )


def _isolated_bounded_hook_command(
    *,
    guard_home: Path,
    harness: str,
    timeout_seconds: float,
    prepared_files: list[TransitionFile] | None = None,
) -> tuple[str, ...] | None:
    interpreter = isolated_cursor_hook_python()
    script_path = bounded_hook_script_path(guard_home, harness)
    if interpreter is None or script_path is None:
        return None
    if prepared_files is not None:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        target = script_path.parent.resolve(strict=False) / script_path.name
        before = _snapshot(target)
        mode = target.stat().st_mode & 0o777 if before is not None else 0o600
        change = TransitionFile(
            target,
            before,
            _render_bounded_hook_script(guard_home=guard_home, harness=harness, timeout_seconds=timeout_seconds).encode(
                "utf-8"
            ),
            before_mode=mode,
            after_mode=0o600,
            no_follow=True,
        )
        change.payload()
        prepared_files.append(change)
        return (interpreter, "-I", str(target))
    try:
        script_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_text_at_authorized_path(
            script_path,
            _render_bounded_hook_script(
                guard_home=guard_home,
                harness=harness,
                timeout_seconds=timeout_seconds,
            ),
        )
    except (OSError, RuntimeError, ValueError):
        return None
    return (interpreter, "-I", str(script_path.resolve(strict=False)))


def bounded_cli_hook_command(  # NOSONAR(S8495) an argv whose length depends on the launcher
    *,
    python_executable: str,
    package_root: Path,
    guard_home: Path,
    cli_args: Sequence[str],
    harness: str,
    timeout_seconds: float,
    prepared_files: list[TransitionFile] | None = None,
    require_desktop_proxy: bool = False,
) -> tuple[str, ...]:
    """Build a shell-free hook command backed by a process-tree deadline."""

    frozen_launcher = bool(getattr(sys, "frozen", False))
    if frozen_launcher:
        python_executable = prune_safe_cli_executable(python_executable)
    config = {
        "python_executable": python_executable,
        "package_root": str(package_root.resolve()),
        "guard_home": str(guard_home.resolve(strict=False)),
        "cli_args": list(cli_args),
        "harness": harness,
        "timeout_seconds": timeout_seconds,
        "frozen_launcher": frozen_launcher,
    }
    grok = harness.strip().lower() == "grok"
    if frozen_launcher and not grok:
        config["start_command"] = frozen_daemon_start_command(python_executable, guard_home, cli_args)
    elif not grok:
        config["start_command"] = daemon_start_command(python_executable, package_root, guard_home, cli_args)
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0,{str(package_root.resolve())!r});"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
        "raise SystemExit(main_from_argv(sys.argv[1:]))"
    )
    config_json = json.dumps(config, ensure_ascii=True, separators=(",", ":"))
    if frozen_launcher:
        if require_desktop_proxy:
            desktop_proxy = _trusted_desktop_hook_proxy_command(
                python_executable,
                config_json,
                require_proxy=True,
            )
        else:
            desktop_proxy = _trusted_desktop_hook_proxy_command(python_executable, config_json)
        if desktop_proxy is not None:
            return desktop_proxy
        if require_desktop_proxy:
            raise RuntimeError("trusted Desktop hook proxy is unavailable")
    elif require_desktop_proxy:
        raise RuntimeError("trusted Desktop hook proxy requires a frozen launcher")
    frozen_native = None if grok or not frozen_launcher else native_bridge_executable(harness, guard_home=guard_home)
    if frozen_native is not None:
        # The native runtime answers from the daemon and fails closed; it
        # never runs the frozen Guard that follows its subcommand.
        return (str(frozen_native), NATIVE_BOUNDED_HOOK_COMMAND, python_executable, _FROZEN_BRIDGE_COMMAND, config_json)
    if frozen_launcher or grok:
        isolated_command = _isolated_bounded_hook_command(
            guard_home=guard_home,
            harness=harness,
            timeout_seconds=timeout_seconds,
            prepared_files=prepared_files,
        )
        if isolated_command is not None and not grok:
            return isolated_command
        if isolated_command is not None:
            # The native runtime answers the generated Grok client itself and
            # runs that same client for anything it does not answer.
            native_executable = native_bridge_executable("grok", guard_home=guard_home)
            if native_executable is not None:
                return (str(native_executable), NATIVE_BOUNDED_HOOK_COMMAND, *isolated_command, config_json)
            return (*isolated_command, config_json)
        if frozen_launcher:
            return (
                python_executable,
                _FROZEN_BRIDGE_COMMAND,
                config_json,
            )
    python_argv = (python_executable, "-I", "-c", bootstrap, config_json)
    native_executable = None if grok else native_bridge_executable(harness)
    if native_executable is not None:
        return (str(native_executable), NATIVE_BOUNDED_HOOK_COMMAND, *python_argv)
    return python_argv


def _read_bounded_stdin(deadline_monotonic: float) -> tuple[str | None, str]:
    try:
        text = read_hook_input(deadline_monotonic)
    except ValueError as error:
        prefix = getattr(error, "prefix", None)
        if isinstance(prefix, str):
            return None, prefix
        raise
    return text, text


def _validated_frozen_cli_args(
    cli_args: Sequence[str],
    *,
    guard_home: Path,
    harness: str,
) -> tuple[str, ...] | None:
    if len(cli_args) < 6 or tuple(cli_args[:3]) != ("guard", "hook", "--guard-home"):
        return None
    supplied_guard_home_value = Path(cli_args[3])
    if not supplied_guard_home_value.is_absolute() or not guard_home.is_absolute():
        return None
    try:
        supplied_guard_home = supplied_guard_home_value.resolve(strict=False)
        expected_guard_home = guard_home.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    if supplied_guard_home != expected_guard_home:
        return None
    if tuple(cli_args[4:6]) != ("--harness", harness):
        return None
    tail = cli_args[6:]
    if tail and tail[-1] == "--json":
        tail = tail[:-1]
    if len(tail) % 2 != 0:
        return None
    seen_flags: set[str] = set()
    for index in range(0, len(tail), 2):
        flag, value = tail[index : index + 2]
        if flag not in _FROZEN_OPTIONAL_PATH_FLAGS or flag in seen_flags:
            return None
        if not Path(value).is_absolute():
            return None
        seen_flags.add(flag)
    return (
        "hook",
        "--guard-home",
        str(expected_guard_home),
        "--harness",
        harness,
        *tail,
        "--json",
    )


def _cli_args_with_json(cli_args: Sequence[str]) -> list[str]:
    if cli_args and cli_args[-1] == "--json":
        return list(cli_args)
    return [*cli_args, "--json"]


def _emit_failure(
    *,
    harness: str,
    input_text: str,
    reason: str = _FAILURE_REASON,
    guard_home: Path | None = None,
    continue_session: bool = False,
    deadline_monotonic: float | None = None,
) -> int:
    # Retain the legacy caller argument; a state-home path supplies no mode authority.
    payload, returncode = _failure_payload(
        harness=harness,
        event_name="PreToolUse"
        if harness == "grok" and _grok_pretool_event_conflict(input_text)
        else _event_name(input_text),
        reason=reason,
        # Failed evaluation supplies no authenticated recording-only authority.
        recording_only=False,
    )
    _ = sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return returncode


def run_bounded_cli_hook(
    config: Mapping[str, object],
    *,
    input_text: str,
    deadline_monotonic: float | None = None,
    skip_daemon: bool = False,
) -> int:
    """Run one isolated CLI hook and preserve its native stdout contract.

    ``skip_daemon`` is set when the native bridge already asked the daemon
    about this hook, so one hook never reaches the daemon twice.
    """

    started_monotonic = time.monotonic()
    from .bounded_cli_hook_daemon import _apply_grok_bridge_approval_wait, try_daemon_hook

    python_executable = config.get("python_executable")
    package_root_value = config.get("package_root")
    guard_home_value = config.get("guard_home")
    cli_args_value = config.get("cli_args")
    harness = config.get("harness")
    timeout_seconds = config.get("timeout_seconds")
    frozen_launcher = config.get("frozen_launcher", False)
    if (
        not isinstance(python_executable, str)
        or not isinstance(package_root_value, str)
        or not isinstance(guard_home_value, str)
        or not isinstance(cli_args_value, list)
        or not isinstance(harness, str)
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or not isinstance(frozen_launcher, bool)
        or timeout_seconds <= 0
    ):
        return _emit_failure(harness=str(harness or "unknown"), input_text=input_text)
    raw_cli_args = cast(list[object], cli_args_value)
    if harness == "grok" and _grok_pretool_event_conflict(input_text):
        return _emit_failure(
            harness=harness,
            input_text=input_text,
            reason="HOL Guard blocked this action because hook event labels conflict.",
        )
    cli_args = [item for item in raw_cli_args if isinstance(item, str)]
    if len(cli_args) != len(raw_cli_args):
        return _emit_failure(harness=harness, input_text=input_text)
    input_text = configured_grok_payload(input_text, cli_args) if harness == "grok" else input_text
    deadline = started_monotonic + float(timeout_seconds) if deadline_monotonic is None else deadline_monotonic
    if time.monotonic() >= deadline:
        return _emit_failure(harness=harness, input_text=input_text)
    package_root = Path(package_root_value)
    guard_home = Path(guard_home_value)

    def fail(reason: str = _FAILURE_REASON) -> int:
        return _emit_failure(
            harness=harness, input_text=input_text, guard_home=guard_home, reason=reason, deadline_monotonic=deadline
        )

    runtime_frozen = bool(getattr(sys, "frozen", False))
    if runtime_frozen:
        if _validated_frozen_cli_args(cli_args, guard_home=guard_home, harness=harness) is None:
            return fail()
    elif frozen_launcher:
        return fail()
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        return fail()
    daemon_result = (
        None
        if skip_daemon
        else try_daemon_hook(
            guard_home=guard_home,
            harness=harness,
            input_text=input_text,
            timeout_seconds=remaining,
            deadline_monotonic=deadline,
        )
    )
    if daemon_result is None and runtime_frozen:
        from .bounded_cli_hook_frozen_recovery import ask_after_frozen_recovery

        daemon_result = ask_after_frozen_recovery(
            guard_home=guard_home, harness=harness, input_text=input_text, cli_args=cli_args, deadline=deadline
        )
    if time.monotonic() >= deadline:
        return fail()
    if daemon_result is not None:
        remaining = max(0.0, deadline - time.monotonic())
        daemon_stdout, daemon_stderr, daemon_exit = _apply_grok_bridge_approval_wait(
            guard_home=guard_home,
            harness=harness,
            input_text=input_text,
            stdout=daemon_result[0],
            stderr=daemon_result[1],
            exit_code=daemon_result[2],
            timeout_seconds=remaining,
        )
        if time.monotonic() >= deadline:
            return fail()
        if daemon_stdout:
            _ = sys.stdout.write(daemon_stdout)
        if daemon_stderr:
            print(daemon_stderr, file=sys.stderr)
        return daemon_exit
    if runtime_frozen:
        # A frozen Guard has no cold evaluator: without a recovered daemon the hook fails closed.
        return fail()
    if harness == "grok" and _event_name(input_text).lower().replace("_", "").replace("-", "") in {
        "userpromptsubmit",
        "userpromptsubmitted",
    }:
        # A cold evaluator fallback can outlive Grok's prompt deadline and fail open.
        # Return a native block while the trusted daemon is unavailable instead.
        return fail()
    if time.monotonic() >= deadline:
        return fail()
    command = isolated_guard_cli_command(python_executable, package_root, _cli_args_with_json(cli_args))
    result = run_isolated_hook_process(
        command,
        input_text=input_text,
        cwd=guard_home,
        environment=isolated_hook_environment(),
        timeout_seconds=float(timeout_seconds),
        deadline_monotonic=deadline,
    )
    if result.timed_out or time.monotonic() >= deadline:
        return fail()
    if result.output_limit_exceeded:
        return fail("HOL Guard blocked this action because hook output exceeded the safe size limit.")
    if result.returncode is None:
        return fail()
    # The CLI answers as the daemon would, so a Grok review gets the same
    # in-hook approval wait as on the daemon path.
    stdout, _stderr, exit_code = _apply_grok_bridge_approval_wait(
        guard_home=guard_home,
        harness=harness,
        input_text=input_text,
        stdout=result.stdout,
        stderr="",
        exit_code=result.returncode,
        timeout_seconds=max(0.0, deadline - time.monotonic()),
    )
    if time.monotonic() >= deadline:
        return fail()
    compact_payload = _json_object(stdout.strip())
    if compact_payload is None and not _has_json_object_line(stdout):
        return fail()
    if compact_payload is not None:
        _ = sys.stdout.write(json.dumps(compact_payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    elif stdout:
        _ = sys.stdout.write(stdout)
    return exit_code


def _is_config_argv(argv: Sequence[str]) -> bool:
    # ZCode hook commands end with "# <marker>". POSIX shells drop that comment,
    # but cmd.exe has no comment syntax and passes both words as arguments.
    return len(argv) == 1 or (len(argv) == 3 and argv[1] == "#" and argv[2] in _TRAILING_MANAGED_MARKERS)


def main_from_argv(argv: Sequence[str]) -> int:
    """Parse the authenticated install-time hook config and run it."""

    started_monotonic = time.monotonic()
    native_elapsed, daemon_tried = take_native_handoff_environment()
    config = _json_object(argv[0]) if _is_config_argv(argv) else None
    configured_harness = config.get("harness") if config is not None else None
    harness = configured_harness if isinstance(configured_harness, str) else "unknown"
    timeout = config.get("timeout_seconds") if config is not None else None
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        return _emit_failure(harness=harness, input_text="{}")
    started_monotonic -= native_elapsed(float(timeout))
    deadline = started_monotonic + float(timeout)
    try:
        input_text, stdin_prefix = _read_bounded_stdin(deadline)
    except (TimeoutError, OSError, ValueError):
        return _emit_failure(harness=harness, input_text="{}")
    if input_text is None:
        guard_home_value = config.get("guard_home") if config is not None else None
        guard_home = Path(guard_home_value) if isinstance(guard_home_value, str) else None
        return _emit_failure(
            harness=harness,
            input_text=stdin_prefix or "{}",
            reason="HOL Guard blocked this action because hook input exceeded the safe size limit.",
            guard_home=guard_home,
            deadline_monotonic=deadline,
        )
    input_text = stamp_hook_input_text(input_text)
    if config is None:
        return _emit_failure(harness=harness, input_text=input_text)
    return run_bounded_cli_hook(config, input_text=input_text, deadline_monotonic=deadline, skip_daemon=daemon_tried)


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "_FROZEN_BRIDGE_COMMAND",
    "bounded_cli_hook_command",
    "bounded_hook_script_path",
    "bounded_python_argv",
    "main_from_argv",
    "run_bounded_cli_hook",
]
