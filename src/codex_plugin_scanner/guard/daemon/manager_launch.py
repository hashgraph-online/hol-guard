"""Guard daemon launch helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _trusted_daemon_home(home_dir: _manager.Path | None) -> _manager.Path:
    candidate = _manager.Path.home() if home_dir is None else _manager.Path(home_dir)
    if not candidate.is_absolute():
        raise RuntimeError("Guard daemon requires an absolute user home directory.")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Guard daemon requires an available user home directory.") from error
    if not resolved.is_dir():
        raise RuntimeError("Guard daemon requires a directory-valued user home.")
    return resolved


def _daemon_launcher_env(
    *,
    home_dir: _manager.Path | None = None,
    guard_home: _manager.Path | None = None,
    executable: _manager.Path | None = None,
) -> dict[str, str]:
    """Build a minimal detached-daemon environment without Python startup hooks."""

    env = {key: value for key, value in _manager.os.environ.items() if key.upper() in _manager._GUARD_DAEMON_ENV_KEYS}
    trusted_home = _manager._trusted_daemon_home(home_dir)
    env.update(
        {
            "HOME": str(trusted_home),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
    )
    if getattr(_manager.sys, "frozen", False) is True or executable is not None:
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        for key in _manager._GUARD_DAEMON_DESKTOP_ENV_KEYS:
            if value := _manager.os.environ.get(key):
                env[key] = value
            else:
                env.pop(key, None)
    else:
        env.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
        for key in _manager._GUARD_DAEMON_DESKTOP_ENV_KEYS:
            env.pop(key, None)
    if _manager.os.name == "nt":
        env["USERPROFILE"] = str(trusted_home)
    if guard_home is not None and not _manager._guard_home_is_ephemeral(guard_home):
        env["GUARD_DAEMON_IDLE_TIMEOUT_SECONDS"] = "0"
    return env


def _trusted_daemon_prefix(value: str) -> _manager.Path:
    prefix = _manager.Path(value).expanduser()
    if not prefix.is_absolute():
        raise RuntimeError("Guard daemon requires an absolute active Python prefix.")
    try:
        resolved = prefix.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Guard daemon requires an available active Python prefix.") from error
    if not resolved.is_dir():
        raise RuntimeError("Guard daemon requires a directory-valued active Python prefix.")
    return resolved


def _trusted_daemon_interpreter() -> _manager.Path:
    interpreter = _manager.Path(_manager.sys.executable).expanduser()
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise RuntimeError("Guard daemon requires an absolute active Python interpreter.")
    return interpreter


def _trusted_daemon_python_flags() -> list[str]:
    flags = ["-I"]
    if tuple(_manager.sys.version_info[:2]) >= (3, 11):
        flags.append("-P")
    return flags


def _trusted_daemon_import_paths() -> tuple[_manager.Path, ...]:
    source_root = _manager.Path(_manager.__file__).resolve().parents[3]
    candidates = [source_root]
    try:
        configured_paths = _manager.sysconfig.get_paths()
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        raise RuntimeError("Guard daemon could not resolve active Python import paths.") from error
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(_manager.Path(value).expanduser())

    trusted_paths: list[_manager.Path] = []
    seen: set[_manager.Path] = set()
    for index, candidate in enumerate(candidates):
        required = index == 0
        if not candidate.is_absolute():
            if required:
                raise RuntimeError("Guard daemon requires absolute trusted import paths.")
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            if required:
                raise RuntimeError("Guard daemon requires available trusted import paths.") from error
            continue
        if not resolved.is_dir():
            if required:
                raise RuntimeError("Guard daemon requires directory-valued trusted import paths.")
            continue
        if resolved not in seen:
            seen.add(resolved)
            trusted_paths.append(resolved)
    return tuple(trusted_paths)


def _isolated_python_module_command(
    module: str,
    import_paths: tuple[_manager.Path, ...],
    module_args: list[str],
    *,
    gate_on_stdin: bool = False,
) -> list[str]:
    return [
        str(_manager._trusted_daemon_interpreter()),
        *_manager._trusted_daemon_python_flags(),
        "-S",
        "-c",
        _manager._GUARD_DAEMON_GATED_BOOTSTRAP if gate_on_stdin else _manager._GUARD_DAEMON_BOOTSTRAP,
        str(_manager._trusted_daemon_prefix(_manager.sys.prefix)),
        str(_manager._trusted_daemon_prefix(_manager.sys.exec_prefix)),
        _manager.json.dumps([str(path) for path in import_paths], separators=(",", ":")),
        module,
        *module_args,
    ]


def _guard_daemon_launch_command(
    guard_home: _manager.Path,
    port: int,
    *,
    home_dir: _manager.Path | None = None,
    gate_on_stdin: bool = False,
    executable: _manager.Path | None = None,
) -> list[str]:
    trusted_home = _manager._trusted_daemon_home(home_dir)
    if bool(getattr(_manager.sys, "frozen", False)) or executable is not None:
        launch = (
            _manager.Path(executable) if executable is not None else _manager.Path(_manager.sys.executable).expanduser()
        )
        if not launch.is_absolute() or not launch.is_file():
            raise RuntimeError("Frozen Guard daemon requires the signed Guard executable.")
        if gate_on_stdin:
            if not bool(getattr(_manager.sys, "frozen", False)):
                raise RuntimeError("Frozen Guard daemon gated launch requires the signed Guard executable.")
            return list(
                _manager.frozen_daemon_serve_command(
                    guard_home,
                    trusted_home,
                    port,
                    executable=str(launch.resolve(strict=True)),
                )
            )
        return [
            str(launch.resolve(strict=True)),
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home),
            "--home",
            str(trusted_home),
            "--port",
            str(port),
        ]
    return _manager._isolated_python_module_command(
        "codex_plugin_scanner.cli",
        _manager._trusted_daemon_import_paths(),
        [
            "guard",
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home),
            "--home",
            str(trusted_home),
            "--port",
            str(port),
        ],
        gate_on_stdin=gate_on_stdin,
    )


def desktop_preflight_requested() -> bool:
    return _manager.os.environ.get("HOL_GUARD_DESKTOP_PREFLIGHT", "").strip().lower() in {"1", "true", "yes"}


def _default_guard_daemon_start_timeout() -> float:
    if _manager.os.environ.get("HOL_GUARD_DESKTOP", "").strip() == "1":
        return _manager.GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS
    return _manager.GUARD_DAEMON_START_TIMEOUT_SECONDS


def _windows_daemon_creation_flags(*, allow_job_breakaway: bool) -> int:
    flags = _manager._WINDOWS_CREATE_NEW_PROCESS_GROUP | _manager._WINDOWS_DETACHED_PROCESS
    if allow_job_breakaway:
        flags |= _manager._WINDOWS_CREATE_BREAKAWAY_FROM_JOB
    return flags
