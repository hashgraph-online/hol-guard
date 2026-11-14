"""Bounded subprocess bridge for harnesses without a daemon-native hook."""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..stable_guard_cli import prune_safe_cli_executable
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
    _json_object as _json_object,
)
from .bounded_cli_hook_failure import failure_payload as _failure_payload
from .bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
    NATIVE_MUSE_HOOK_FEATURE,
    bounded_python_argv,
    daemon_start_command,
    frozen_daemon_start_command,
    native_bridge_executable,
)
from .bounded_cli_hook_script_template import BOUNDED_HOOK_SCRIPT_TEMPLATE
from .desktop_hook_proxy import _trusted_desktop_hook_proxy_command
from .hook_input_reader import read_hook_input
from .isolated_hook_python import isolated_cursor_hook_python

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile

_FAILURE_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_TRAILING_MANAGED_MARKERS = frozenset({"HOL_GUARD_MANAGED_ZCODE"})
_FROZEN_BRIDGE_COMMAND = "__guard-bounded-hook"
_BOUNDED_HOOK_SCRIPT_DIR = ("managed", "bounded-hooks")
# The native bridge answers within the hook deadline; this only bounds a
# runtime that stopped answering.
_NATIVE_EXIT_GRACE_SECONDS = 2.0


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


def _bridge_bootstrap(package_root: str) -> str:
    return (
        "import sys;"
        f"sys.path.insert(0,{package_root!r});"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
        "raise SystemExit(main_from_argv(sys.argv[1:]))"
    )


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
    bootstrap = _bridge_bootstrap(str(package_root.resolve()))
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
    if grok:
        isolated_command = _isolated_bounded_hook_command(
            guard_home=guard_home,
            harness=harness,
            timeout_seconds=timeout_seconds,
            prepared_files=prepared_files,
        )
        native_executable = native_bridge_executable("grok", guard_home=guard_home)
        if isolated_command is not None and native_executable is not None:
            # The native runtime reads the generated Grok client's constants
            # and answers the hook itself; the client never runs.
            return (str(native_executable), NATIVE_BOUNDED_HOOK_COMMAND, *isolated_command, config_json)
        # Without a runtime to wrap the client, register the bridge form: it
        # looks the runtime up on every hook, so the hook recovers once one
        # is installed instead of running the fail-closed client forever.
    if frozen_launcher:
        # The frozen Guard hands the hook to its runtime's durable copy when
        # it runs, and fails it closed when there is none.
        return (python_executable, _FROZEN_BRIDGE_COMMAND, config_json)
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


def _native_runtime(harness: str, guard_home: Path | None, deadline: float) -> Path | None:
    from .native_hook_bridge import native_hook_bridge_executable

    feature = NATIVE_MUSE_HOOK_FEATURE if harness == "muse" else NATIVE_BOUNDED_HOOK_FEATURE
    try:
        return native_hook_bridge_executable(feature, guard_home=guard_home, deadline_monotonic=deadline)
    except (OSError, RuntimeError, ValueError):
        return None


def _native_argv(native: Path, package_root: str, config_argv: Sequence[str]) -> list[str]:
    """The native bridge argv for a hook this interpreter was started for.

    The argv after the subcommand only names the launcher; the native bridge
    reads the config from its last argument and never runs it.
    """
    if getattr(sys, "frozen", False):
        launcher = [sys.executable, _FROZEN_BRIDGE_COMMAND]
    else:
        launcher = [sys.executable, "-I", "-c", _bridge_bootstrap(package_root)]
    return [str(native), NATIVE_BOUNDED_HOOK_COMMAND, *launcher, *config_argv]


def _config_fields(config: Mapping[str, object] | None) -> tuple[str, Path | None, str, float | None]:
    harness = config.get("harness") if config is not None else None
    guard_home = config.get("guard_home") if config is not None else None
    package_root = config.get("package_root") if config is not None else None
    timeout = config.get("timeout_seconds") if config is not None else None
    valid_timeout = (
        isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and math.isfinite(timeout) and timeout > 0
    )
    return (
        harness if isinstance(harness, str) else "unknown",
        Path(guard_home) if isinstance(guard_home, str) and guard_home else None,
        package_root if isinstance(package_root, str) else "",
        float(cast(float, timeout)) if valid_timeout else None,
    )


def run_bounded_cli_hook(
    config: Mapping[str, object],
    *,
    input_text: str,
    deadline_monotonic: float | None = None,
) -> int:
    """Answer one hook through the native bridge in its native stdout contract.

    The native runtime asks the daemon and renders its answer; Python never
    evaluates or renders a hook. Without a native runtime the hook fails closed.
    """

    started_monotonic = time.monotonic()
    harness, guard_home, package_root, timeout = _config_fields(config)
    if timeout is None:
        return _emit_failure(harness=harness, input_text=input_text)
    deadline = started_monotonic + timeout if deadline_monotonic is None else deadline_monotonic
    native = _native_runtime(harness, guard_home, deadline)
    remaining = deadline - time.monotonic()
    if native is None or remaining <= 0:
        return _emit_failure(harness=harness, input_text=input_text)
    try:
        completed = subprocess.run(
            _native_argv(native, package_root, [_config_with_budget(config, remaining)]),
            input=input_text.encode("utf-8", "surrogatepass"),
            capture_output=True,
            timeout=remaining + _NATIVE_EXIT_GRACE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _emit_failure(harness=harness, input_text=input_text)
    if time.monotonic() > deadline:
        # An answer that arrives after the hook's deadline is not forwarded.
        return _emit_failure(harness=harness, input_text=input_text)
    if completed.stdout:
        _ = sys.stdout.write(completed.stdout.decode("utf-8", "replace"))
    if completed.stderr:
        _ = sys.stderr.write(completed.stderr.decode("utf-8", "replace"))
    return completed.returncode


def _is_config_argv(argv: Sequence[str]) -> bool:
    # ZCode hook commands end with "# <marker>". POSIX shells drop that comment,
    # but cmd.exe has no comment syntax and passes both words as arguments.
    return len(argv) == 1 or (len(argv) == 3 and argv[1] == "#" and argv[2] in _TRAILING_MANAGED_MARKERS)


def main_from_argv(argv: Sequence[str]) -> int:
    """Run the hook an install-time config names through the native bridge.

    Registrations written before the native bridge was required start this
    interpreter. The native bridge reads the hook from the inherited stdin,
    so nothing here reads or decides it; without a native runtime the hook
    fails closed.
    """

    started_monotonic = time.monotonic()
    config = _json_object(argv[0]) if _is_config_argv(argv) else None
    harness, guard_home, package_root, timeout = _config_fields(config)
    if timeout is None:
        return _emit_failure(harness=harness, input_text="{}")
    deadline = started_monotonic + timeout
    native = _native_runtime(harness, guard_home, deadline)
    remaining = deadline - time.monotonic()
    if native is None or remaining <= 0:
        return _fail_without_runtime(harness=harness, deadline=deadline)
    config = cast(dict[str, object], config)
    sys.stdout.flush()
    try:
        completed = subprocess.run(
            _native_argv(native, package_root, [_config_with_budget(config, remaining), *argv[1:]]),
            timeout=remaining + _NATIVE_EXIT_GRACE_SECONDS,
            check=False,
        )
    except OSError:
        # The runtime never started, so the hook input is still unread.
        return _fail_without_runtime(harness=harness, deadline=deadline)
    except subprocess.SubprocessError:
        # The runtime may have consumed the input before it timed out.
        return _emit_failure(harness=harness, input_text="{}")
    return completed.returncode


def _config_with_budget(config: Mapping[str, object], remaining: float) -> str:
    """The config with the hook's remaining time, so the runtime keeps its deadline."""
    return json.dumps({**config, "timeout_seconds": remaining}, ensure_ascii=True, separators=(",", ":"))


def _fail_without_runtime(*, harness: str, deadline: float) -> int:
    """The fail-closed answer for the event the hook names."""
    try:
        input_text, stdin_prefix = _read_bounded_stdin(deadline)
    except (TimeoutError, OSError, ValueError):
        return _emit_failure(harness=harness, input_text="{}")
    return _emit_failure(harness=harness, input_text=input_text if input_text is not None else stdin_prefix or "{}")


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
