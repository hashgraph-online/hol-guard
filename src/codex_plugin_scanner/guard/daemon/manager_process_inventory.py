"""Guard daemon process inventory helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _guard_home_from_command(command: str) -> _manager.Path | None:
    parts = _manager._split_process_command(command)
    if parts is None:
        return None
    return _manager._guard_home_from_command_parts(parts)


def _guard_home_from_command_parts(parts: list[str]) -> _manager.Path | None:
    frozen_context = _manager._frozen_daemon_serve_context(parts)
    if frozen_context is not None:
        return frozen_context[0]
    for index, part in enumerate(parts):
        if part == "--guard-home" and index + 1 < len(parts):
            return _manager.Path(parts[index + 1])
    return None


def _guard_daemon_port_from_command(command: str) -> int | None:
    parts = _manager._split_process_command(command)
    if parts is None:
        return None
    frozen_context = _manager._frozen_daemon_serve_context(parts)
    if frozen_context is not None:
        return frozen_context[2]
    for index, part in enumerate(parts):
        if part.startswith("--port="):
            try:
                port = int(part.split("=", 1)[1])
            except ValueError:
                return None
            return port if port > 0 else None
        if part != "--port" or index + 1 >= len(parts):
            continue
        try:
            port = int(parts[index + 1])
        except ValueError:
            return None
        return port if port > 0 else None
    return None


def _guard_daemon_command_matches(command: str) -> bool:
    parts = _manager._split_process_command(command)
    if parts is None:
        return False
    return _manager._guard_daemon_command_parts_match(parts)


def _split_process_command(command: str) -> list[str] | None:
    if _manager.os.name == "nt":
        return _manager.windows_command_line_to_argv(command)
    try:
        return _manager.shlex.split(command)
    except ValueError:
        return None


def _guard_daemon_command_parts_match(parts: list[str]) -> bool:
    if _manager._frozen_daemon_serve_context(parts) is not None:
        return True
    for index in range(len(parts) - 1):
        prefix = parts[:index]
        if parts[index : index + 2] == ["daemon", "--serve"]:
            if any(part == "codex_plugin_scanner.cli" for part in prefix):
                return True
            if index > 0:
                launcher_name = _manager.ntpath.basename(parts[index - 1]).lower()
                if launcher_name in {
                    "hol-guard",
                    "hol-guard.exe",
                    "plugin-guard",
                    "plugin-guard.exe",
                }:
                    return True
            continue
        if parts[index : index + 3] != ["guard", "daemon", "--serve"]:
            continue
        if any(part == "codex_plugin_scanner.cli" for part in prefix):
            return True
        if index == 0:
            continue
        launcher_name = _manager.ntpath.basename(parts[index - 1]).lower()
        if launcher_name in {
            "hol-guard",
            "hol-guard.exe",
            "plugin-guard",
            "plugin-guard.exe",
        }:
            return True
    return False


def _frozen_daemon_serve_context(parts: list[str]) -> tuple[_manager.Path, _manager.Path, int] | None:
    if len(parts) != 3 or parts[1] != _manager.FROZEN_DAEMON_SERVE_ARG:
        return None
    launcher_name = _manager.ntpath.basename(parts[0]).lower()
    if launcher_name not in {
        "hol-guard",
        "hol-guard.exe",
        "plugin-guard",
        "plugin-guard.exe",
    }:
        return None
    try:
        return _manager.decode_frozen_daemon_serve_payload(parts[2])
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _guard_daemon_process_inventory_for_guard_home(
    guard_home: _manager.Path,
) -> list[tuple[int, int]] | None:
    """Return a proven process inventory, or ``None`` when enumeration is unknown."""

    if _manager.os.name == "nt":
        candidate_names = {
            "hol-guard.exe",
            "plugin-guard.exe",
            "py.exe",
            "python.exe",
            "python3.exe",
            "pythonw.exe",
        }
        executable_name = _manager.ntpath.basename(_manager.sys.executable).strip().lower()
        if executable_name:
            candidate_names.add(executable_name)
        entries = _manager.windows_processes.windows_process_command_line_inventory(
            candidate_executable_names=frozenset(candidate_names),
            max_command_line_bytes=_manager._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
        )
        if entries is None:
            return None
    else:
        ps_path = _manager._trusted_posix_ps_path()
        if ps_path is None:
            if not _manager.sys.platform.startswith("linux"):
                return None
            proc_entries = _manager._linux_proc_process_entries()
            if proc_entries is None:
                return None
            entries = proc_entries
        else:
            output = _manager._bounded_process_query_stdout([ps_path, "-axo", "pid=,command="])
            if output is None:
                return None
            entries = []
            for line in output.splitlines():
                match = _manager.re.match(r"^\s*(\d+)\s+(.*)$", line)
                if match is None:
                    continue
                entries.append((int(match.group(1)), match.group(2).strip()))

    processes: list[tuple[int, int]] = []
    for pid, command_line in entries:
        parts = _manager._split_process_command(command_line)
        if parts is None:
            lowered = command_line.lower()
            if (
                "codex_plugin_scanner" in lowered or "guard" in lowered
            ) and _manager._malformed_command_may_launch_guard(command_line):
                return None
            continue
        if not _manager._guard_daemon_command_parts_match(parts):
            continue
        command_guard_home = _manager._guard_home_from_command_parts(parts)
        port = _manager._guard_daemon_port_from_command(command_line)
        if command_guard_home is None or port is None:
            return None
        try:
            matches_home = command_guard_home.resolve() == guard_home.resolve()
        except OSError:
            matches_home = command_guard_home == guard_home
        if matches_home:
            processes.append((pid, port))
    return sorted(processes, key=lambda item: item[1])


def _malformed_command_may_launch_guard(command_line: str) -> bool:
    trimmed_command = command_line.lstrip()
    if not trimmed_command:
        return False
    if trimmed_command[0] in {'"', "'"}:
        quote = trimmed_command[0]
        closing_quote = trimmed_command.find(quote, 1)
        if closing_quote <= 1:
            lowered = trimmed_command.lower()
            launcher_names = (
                "hol-guard",
                "hol-guard.exe",
                "plugin-guard",
                "plugin-guard.exe",
            )
            launcher_present = any(
                _manager.re.search(
                    rf"(?:^|[\\/\s]){_manager.re.escape(name)}(?:$|[\\/\s\"'])",
                    lowered,
                )
                for name in launcher_names
            )
            if _manager.FROZEN_DAEMON_SERVE_ARG in lowered:
                return launcher_present
            daemon_invocation = _manager.re.search(r"(?:^|\s)(?:guard\s+)?daemon\s+--serve(?:\s|$)", lowered)
            return daemon_invocation is not None and launcher_present
        first_token = trimmed_command[1:closing_quote]
    else:
        first_token = trimmed_command.split(maxsplit=1)[0]
    launcher = _manager.ntpath.basename(first_token).lower()
    lowered = command_line.lower()
    if _manager.FROZEN_DAEMON_SERVE_ARG in lowered:
        return launcher in {
            "hol-guard",
            "hol-guard.exe",
            "plugin-guard",
            "plugin-guard.exe",
        }
    daemon_invocation = _manager.re.search(r"(?:^|\s)(?:guard\s+)?daemon\s+--serve(?:\s|$)", lowered)
    if daemon_invocation is None:
        return False
    if launcher.startswith("python"):
        module_launch = (
            "runpy.run_module" in lowered
            or _manager.re.search(r"(?:^|\s)-m\s+codex_plugin_scanner\.cli(?:\s|$)", lowered) is not None
        )
        return "codex_plugin_scanner.cli" in lowered and module_launch
    if launcher in {"env", "uv", "uv.exe"}:
        return _manager.re.search(r"(?:^|\s)(?:hol-guard|plugin-guard)(?:\.exe)?(?:\s|$)", lowered) is not None
    return launcher in {
        "hol-guard",
        "hol-guard.exe",
        "plugin-guard",
        "plugin-guard.exe",
    }


def _running_guard_daemon_processes_for_guard_home(guard_home: _manager.Path) -> list[tuple[int, int]]:
    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory if inventory is not None else []
