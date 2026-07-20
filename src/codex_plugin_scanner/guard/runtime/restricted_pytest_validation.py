"""Validation helpers for fail-closed restricted pytest launches."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
from collections.abc import Sequence
from pathlib import Path

from .restricted_pytest_model import (
    _MAX_ARG_BYTES,
    _MAX_ARG_COUNT,
    _PROJECT_WORKSPACE_MARKERS,
    _PYTEST_EXECUTABLE_NAMES,
    _PYTHON_EXECUTABLE_PATTERN,
    _SENSITIVE_HOME_ROOT_NAMES,
    _TRUSTED_EXECUTABLE_ROOTS,
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestBackend,
    RestrictedPytestError,
)

if os.name == "posix":
    import pwd as _pwd
else:
    _pwd = None


def _normalized_command(command: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(str(item) for item in command)
    if normalized and normalized[0] == "--":
        normalized = normalized[1:]
    total_bytes = sum(len(item.encode("utf-8", errors="surrogatepass")) for item in normalized)
    if not normalized or len(normalized) > _MAX_ARG_COUNT or total_bytes > _MAX_ARG_BYTES:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest requires a bounded, non-empty argv after `--`.",
        )
    if any("\x00" in item for item in normalized):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest argv cannot contain NUL bytes.",
        )
    return normalized


def _resolve_workspace(workspace: Path) -> Path:
    try:
        resolved = workspace.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            f"Restricted pytest workspace could not be resolved: {error}",
        ) from error
    if not resolved.is_dir():
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an existing directory.",
        )
    if _workspace_is_broad_or_sensitive(resolved):
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace cannot be a filesystem, home, temporary, or credential-directory root.",
        )
    if not any((resolved / marker).exists() for marker in _PROJECT_WORKSPACE_MARKERS):
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an explicit project root with a recognized project marker.",
        )
    return resolved


def _workspace_is_broad_or_sensitive(workspace: Path) -> bool:
    broad_roots = {
        Path("/"),
        Path("/Users"),
        Path("/etc"),
        Path("/home"),
        Path("/private"),
        Path("/private/tmp"),
        Path("/private/var"),
        Path("/tmp"),
        Path("/var"),
        Path("/var/tmp"),
    }
    if workspace in broad_roots:
        return True
    home = _host_home_directory()
    if home is None:
        return True
    if workspace == home or workspace in home.parents:
        return True
    try:
        relative_to_home = workspace.relative_to(home)
    except ValueError:
        return False
    return bool(relative_to_home.parts and relative_to_home.parts[0] in _SENSITIVE_HOME_ROOT_NAMES)


def _resolve_cwd(cwd: Path, *, workspace: Path) -> Path:
    try:
        resolved = cwd.expanduser().resolve(strict=True)
        _ = resolved.relative_to(workspace)
    except (OSError, RuntimeError, ValueError) as error:
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest cwd must resolve to an existing directory inside the approved workspace.",
        ) from error
    if not resolved.is_dir():
        raise RestrictedPytestError(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest cwd must be a directory.",
        )
    return resolved


def _resolve_pytest_executable(
    command: tuple[str, ...],
    *,
    cwd: Path,
    workspace: Path,
) -> tuple[Path, Path]:
    command_name = Path(command[0].replace("\\", "/")).name.lower()
    if command_name in _PYTEST_EXECUTABLE_NAMES:
        _validate_pytest_args(command[1:])
    elif _PYTHON_EXECUTABLE_PATTERN.fullmatch(command_name):
        if not _python_args_target_pytest(command[1:]):
            raise RestrictedPytestError(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
            )
    else:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
        )
    launch_executable = _locate_executable(command[0], cwd=cwd)
    executable = _resolve_executable(command[0], cwd=cwd)
    launched_from_workspace = _path_is_within_lexically(launch_executable, workspace)
    if not launched_from_workspace and not _path_is_within_any(executable, _TRUSTED_EXECUTABLE_ROOTS):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable must be inside the workspace or a trusted system installation root.",
        )
    if command_name in _PYTEST_EXECUTABLE_NAMES and Path(executable).name.lower() not in _PYTEST_EXECUTABLE_NAMES:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable symlink does not resolve to a pytest executable.",
        )
    if _PYTHON_EXECUTABLE_PATTERN.fullmatch(command_name) and not _PYTHON_EXECUTABLE_PATTERN.fullmatch(executable.name):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted Python symlink does not resolve to a Python executable.",
        )
    return launch_executable, executable


def _validate_pytest_args(args: Sequence[str]) -> None:
    if any(item in {";", "&&", "||", "|", "|&", "&"} for item in args):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest receives argv directly and does not accept shell control operators.",
        )


def _python_args_target_pytest(args: Sequence[str]) -> bool:
    index = 0
    while index < len(args):
        item = args[index]
        if item == "--":
            return False
        if item in {"-c", "--command"} or item.startswith(("-c", "--command=")):
            return False
        if item == "-m":
            return index + 1 < len(args) and args[index + 1].split(".", 1)[0] == "pytest"
        if item.startswith("-m") and len(item) > 2:
            return item[2:].split(".", 1)[0] == "pytest"
        if item in {"-W", "-X", "--check-hash-based-pycs"}:
            index += 2
            continue
        if item.startswith(("-W", "-X", "--check-hash-based-pycs=")):
            index += 1
            continue
        if not item.startswith("-"):
            return False
        index += 1
    return False


def _resolve_executable(value: str, *, cwd: Path) -> Path:
    candidate = _locate_executable(value, cwd=cwd)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            f"Restricted pytest executable could not be resolved: {value}",
        ) from error
    try:
        metadata = resolved.stat()
    except OSError as error:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            f"Restricted pytest executable could not be inspected: {value}",
        ) from error
    if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and metadata.st_mode & 0o111 == 0):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            f"Restricted pytest target is not an executable regular file: {value}",
        )
    return resolved


def _locate_executable(value: str, *, cwd: Path) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute() or "/" in value or "\\" in value:
        if not candidate.is_absolute():
            candidate = cwd / candidate
        return candidate.absolute()
    located = shutil.which(value)
    if located is None:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            f"Restricted pytest executable was not found on PATH: {value}",
        )
    return Path(located).expanduser().absolute()


def _select_backend(
    *,
    platform: str,
    backend_executable: Path | None,
) -> tuple[RestrictedPytestBackend, Path]:
    if platform == "darwin":
        backend: RestrictedPytestBackend = "macos-seatbelt"
        candidate = backend_executable or Path("/usr/bin/sandbox-exec")
    elif platform.startswith("linux"):
        backend = "linux-bubblewrap"
        located = shutil.which("bwrap")
        candidate = backend_executable or (Path(located) if located else Path("/usr/bin/bwrap"))
    else:
        raise RestrictedPytestError(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "No enforceable restricted pytest backend is available for this platform; execution was not started.",
        )
    trusted = _trusted_backend_executable(candidate)
    if trusted is None:
        raise RestrictedPytestError(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            f"Required {backend} backend is missing or not a trusted system executable; execution was not started.",
        )
    return backend, trusted


def _trusted_backend_executable(candidate: Path) -> Path | None:
    try:
        resolved = candidate.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        return None
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None
    if hasattr(os, "getuid") and metadata.st_uid != 0:
        return None
    if not _path_is_within_any(resolved, (Path("/bin"), Path("/usr/bin"), Path("/usr/local/bin"))):
        return None
    return resolved


def _allowed_executables(
    executable: Path,
    launch_executable: Path,
    command: tuple[str, ...],
    *,
    cwd: Path,
    workspace: Path,
) -> tuple[Path, ...]:
    allowed = [launch_executable, executable]
    if Path(command[0].replace("\\", "/")).name.lower() in _PYTEST_EXECUTABLE_NAMES:
        interpreter = _script_interpreter(executable, cwd=cwd)
        if interpreter is not None:
            if _PYTHON_EXECUTABLE_PATTERN.fullmatch(interpreter[-1].name) is None:
                raise RestrictedPytestError(
                    PYTEST_INVALID_COMMAND_REASON_CODE,
                    "Restricted pytest entry points must use a Python interpreter.",
                )
            allowed.extend(interpreter)
    for allowed_executable in tuple(allowed):
        allowed.extend(_framework_python_helpers(allowed_executable))
    workspace_launcher = _path_is_within_lexically(launch_executable, workspace)
    if any(
        not _allowed_executable_path(path, workspace=workspace, workspace_launcher=workspace_launcher)
        for path in allowed
    ):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest script resolves to an interpreter outside the workspace and trusted system roots.",
        )
    if any(not _executable_symlink_chain_is_approved(path, workspace=workspace) for path in allowed):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an unapproved path in its interpreter symlink chain.",
        )
    return tuple(dict.fromkeys(allowed))


def _framework_python_helpers(executable: Path) -> tuple[Path, ...]:
    if executable.parent.name != "bin":
        return ()
    version_root = executable.parent.parent
    if version_root.parent.name != "Versions" or version_root.parent.parent.name != "Python.framework":
        return ()
    helper = version_root / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    if not helper.exists():
        return ()
    try:
        resolved = _resolve_executable(str(helper), cwd=helper.parent)
    except RestrictedPytestError:
        return ()
    return tuple(dict.fromkeys((helper.absolute(), resolved)))


def _allowed_executable_path(path: Path, *, workspace: Path, workspace_launcher: bool) -> bool:
    if _path_is_within_lexically(path, workspace) or _path_is_within_any(path, _TRUSTED_EXECUTABLE_ROOTS):
        return True
    basename = path.name.lower()
    return (
        workspace_launcher
        and _PYTHON_EXECUTABLE_PATTERN.fullmatch(basename) is not None
        and _approved_user_python_runtime(path)
    )


def _approved_user_python_runtime(path: Path) -> bool:
    """Allow exact, recognized interpreter distributions without widening to home."""

    home = _host_home_directory()
    if home is None:
        return False
    try:
        relative_parts = path.absolute().relative_to(home).parts
    except (OSError, RuntimeError, ValueError):
        return False
    managed_prefixes = (
        (".asdf", "installs", "python"),
        (".local", "share", "mise", "installs", "python"),
        (".local", "share", "uv", "python"),
        (".pyenv", "versions"),
        ("Library", "Application Support", "uv", "python"),
        ("Library", "Caches", "uv", "python"),
    )
    if any(
        len(relative_parts) > len(prefix) and relative_parts[: len(prefix)] == prefix for prefix in managed_prefixes
    ):
        return True
    return bool(
        relative_parts
        and relative_parts[0] in {"anaconda3", "mambaforge", "miniconda3", "miniforge3"}
        and len(relative_parts) > 2
    )


def _executable_symlink_chain_is_approved(path: Path, *, workspace: Path) -> bool:
    current = path.absolute()
    for _depth in range(16):
        expansion = _first_symlink_expansion(current)
        if expansion is None:
            return True
        current = expansion
        if (
            not _path_is_within_lexically(current, workspace)
            and not _path_is_within_any_lexically(current, _TRUSTED_EXECUTABLE_ROOTS)
            and not _approved_user_python_runtime(current)
        ):
            return False
    return _first_symlink_expansion(current) is None


def _script_interpreter(executable: Path, *, cwd: Path) -> tuple[Path, ...] | None:
    try:
        with executable.open("rb") as handle:
            first_line = handle.readline(4_096)
    except OSError:
        return None
    if not first_line.startswith(b"#!"):
        return None
    try:
        shebang = first_line[2:].decode("utf-8", errors="strict").strip()
        parts = shlex.split(shebang, posix=True)
    except (UnicodeDecodeError, ValueError):
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an invalid interpreter declaration.",
        ) from None
    if not parts:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an empty interpreter declaration.",
        )
    interpreter_launch = _locate_executable(parts[0], cwd=cwd)
    interpreter = _resolve_executable(parts[0], cwd=cwd)
    interpreters = [interpreter_launch, interpreter]
    if interpreter == Path("/usr/bin/env") and len(parts) >= 2:
        target_launch = _locate_executable(parts[-1], cwd=cwd)
        interpreters.extend((target_launch, _resolve_executable(parts[-1], cwd=cwd)))
    return tuple(interpreters)


def _restricted_pythonpath(value: str, *, workspace: Path, cwd: Path) -> str:
    entries: list[str] = []
    for raw_entry in value.split(os.pathsep):
        if raw_entry == "":
            resolved = cwd
        else:
            candidate = Path(raw_entry).expanduser()
            try:
                resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve(strict=False)
                _ = resolved.relative_to(workspace)
            except (OSError, RuntimeError, ValueError) as error:
                raise RestrictedPytestError(
                    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
                    "Restricted pytest rejected PYTHONPATH because it references a path outside the workspace.",
                ) from error
        text = str(resolved)
        if text not in entries:
            entries.append(text)
    return os.pathsep.join(entries)


def _first_symlink_expansion(path: Path) -> Path | None:
    parts = path.parts
    if not parts:
        return None
    current = Path(parts[0])
    for index, part in enumerate(parts[1:], start=1):
        current /= part
        try:
            if not current.is_symlink():
                continue
            raw_target = Path(os.readlink(current))
        except OSError:
            return None
        target = raw_target if raw_target.is_absolute() else current.parent / raw_target
        expanded = target.joinpath(*parts[index + 1 :])
        return Path(os.path.abspath(expanded))
    return None


def _runtime_distribution_root(executable: Path) -> Path:
    bin_indexes = [index for index, part in enumerate(executable.parts) if part == "bin"]
    if not bin_indexes:
        return executable.parent
    return Path(*executable.parts[: bin_indexes[-1]])


def _host_home_directory() -> Path | None:
    password_database = _pwd
    if password_database is not None and hasattr(os, "getuid"):
        try:
            return Path(password_database.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        except (KeyError, OSError, RuntimeError):
            return None
    try:
        return Path.home().resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        _ = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _path_is_within_lexically(path: Path, root: Path) -> bool:
    try:
        _ = path.absolute().relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _path_is_within_any(path: Path, roots: Sequence[Path]) -> bool:
    return any(_path_is_within(path, root) for root in roots)


def _path_is_within_any_lexically(path: Path, roots: Sequence[Path]) -> bool:
    return any(_path_is_within_lexically(path, root) for root in roots)
