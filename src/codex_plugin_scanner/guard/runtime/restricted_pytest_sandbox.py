"""Operating-system sandbox construction and execution for restricted pytest."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import FrameType

from .restricted_pytest_model import (
    _DEFAULT_CPU_SECONDS,
    _DEFAULT_FILE_BYTES,
    _DEFAULT_MEMORY_BYTES,
    _DEFAULT_OPEN_FILES,
    _DEFAULT_PROCESSES,
    _DENIED_ENV_KEYS,
    _LINUX_READ_FILES,
    _LINUX_READ_ROOTS,
    _MACOS_READ_FILES,
    _MACOS_READ_ROOTS,
    _PROXY_ENV_KEYS,
    _SAFE_ENV_KEYS,
    _SEALED_SYSTEM_EXECUTABLE_ROOTS,
    _SECRET_ENV_PATTERN,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_validation import (
    _first_symlink_expansion,
    _path_is_within,
    _path_is_within_any,
    _restricted_pythonpath,
    _runtime_distribution_root,
)

_RESOURCE_AVAILABLE = os.name == "posix"
if _RESOURCE_AVAILABLE:
    import resource as _resource
else:
    _resource = None


def _restricted_environment(
    source: Mapping[str, str],
    *,
    workspace: Path,
    cwd: Path,
    private_home: Path,
    private_tmp: Path,
    allowed_executables: tuple[Path, ...],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in source.items():
        if (
            key in _DENIED_ENV_KEYS
            or key in _PROXY_ENV_KEYS
            or _SECRET_ENV_PATTERN.search(key)
            or "\x00" in key
            or "\x00" in value
        ):
            continue
        if key in {"HOME", "PATH", "TEMP", "TMP", "TMPDIR"}:
            continue
        if key == "PYTHONPATH":
            result[key] = _restricted_pythonpath(value, workspace=workspace, cwd=cwd)
            continue
        if key == "VIRTUAL_ENV":
            virtual_environment = Path(value).expanduser()
            try:
                resolved_virtual_environment = virtual_environment.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if _path_is_within(resolved_virtual_environment, workspace):
                result[key] = str(resolved_virtual_environment)
            continue
        if key in _SAFE_ENV_KEYS or key.startswith("LC_"):
            result[key] = value
    executable_dirs = list(dict.fromkeys(str(path.parent) for path in allowed_executables))
    result.update(
        {
            "HOME": str(private_home),
            "PATH": os.pathsep.join(executable_dirs),
            "PWD": str(cwd),
            "PYTHONNOUSERSITE": "1",
            "TEMP": str(private_tmp),
            "TMP": str(private_tmp),
            "TMPDIR": str(private_tmp),
        }
    )
    return result


def _backend_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    if plan.backend == "macos-seatbelt":
        profile = _macos_profile(plan, private_root=private_root)
        return [str(plan.backend_executable), "-p", profile, "--", *plan.command]
    return _bubblewrap_argv(plan, private_root=private_root)


def _macos_profile(plan: RestrictedPytestPlan, *, private_root: Path) -> str:
    read_roots = [plan.workspace, private_root]
    read_roots.extend(path for path in _MACOS_READ_ROOTS if path.exists())
    read_roots.extend(_runtime_read_roots(plan))
    read_files = [path for path in _MACOS_READ_FILES if path.exists()]
    read_filters = " ".join(f"(subpath {_seatbelt_string(path)})" for path in read_roots)
    read_file_filters = " ".join(f"(literal {_seatbelt_string(path)})" for path in read_files)
    metadata_paths = (Path("/"), *_ancestor_paths((*read_roots, *plan.allowed_executables)))
    metadata_filters = " ".join(f"(literal {_seatbelt_string(path)})" for path in metadata_paths)
    executable_filters = " ".join(f"(literal {_seatbelt_string(path)})" for path in plan.allowed_executables)
    write_filters = " ".join(
        (
            f"(subpath {_seatbelt_string(plan.workspace)})",
            f"(subpath {_seatbelt_string(private_root)})",
            '(literal "/dev/null")',
        )
    )
    return "\n".join(
        (
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            f"(allow process-exec {executable_filters})",
            "(allow signal (target self))",
            "(allow sysctl-read)",
            '(allow file-read-data (literal "/"))',
            f"(allow file-read-metadata {metadata_filters})",
            f"(allow file-read* {read_filters} {read_file_filters})",
            f"(allow file-write* {write_filters})",
        )
    )


def _seatbelt_string(path: Path) -> str:
    value = str(path)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _bubblewrap_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    argv = [
        str(plan.backend_executable),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-net",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    readonly_paths = [path for path in (*_LINUX_READ_ROOTS, *_LINUX_READ_FILES) if path.exists()]
    readonly_paths.extend(_runtime_read_roots(plan))
    readonly_paths.extend(path for path in plan.allowed_executables if not _path_is_within(path, plan.workspace))
    for path in _dedupe_parent_paths(readonly_paths):
        argv.extend(("--ro-bind", str(path), str(path)))
    argv.extend(("--bind", str(plan.workspace), str(plan.workspace)))
    argv.extend(("--dir", str(private_root)))
    argv.extend(("--bind", str(private_root), str(private_root)))
    argv.extend(("--chdir", str(plan.cwd), "--", *plan.command))
    return argv


def _dedupe_parent_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for path in sorted({item.resolve(strict=False) for item in paths}, key=lambda item: (len(item.parts), str(item))):
        if any(_path_is_within(path, parent) for parent in resolved):
            continue
        resolved.append(path)
    return tuple(resolved)


def _ancestor_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    ancestors: list[Path] = []
    for path in paths:
        current = path
        for parent in (current, *current.parents):
            if parent == Path("/") or parent in ancestors:
                continue
            ancestors.append(parent)
    return tuple(ancestors)


def _runtime_read_roots(plan: RestrictedPytestPlan) -> tuple[Path, ...]:
    roots: list[Path] = []
    for executable in plan.allowed_executables:
        symlink_runtime_roots = _symlink_runtime_roots(executable)
        for symlink_runtime_root in symlink_runtime_roots:
            if symlink_runtime_root not in roots:
                roots.append(symlink_runtime_root)
        if symlink_runtime_roots:
            continue
        if _path_is_within(executable, plan.workspace) or _path_is_within_any(
            executable, _SEALED_SYSTEM_EXECUTABLE_ROOTS
        ):
            continue
        root = executable.parent.parent if executable.parent.name == "bin" else executable.parent
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def _symlink_runtime_roots(executable: Path) -> tuple[Path, ...]:
    """Return lexical runtime roots named by an executable's symlink chain.

    Managed Python installations commonly expose a stable version alias (for
    example ``cpython-3.12-*``) that points at a patch-version directory.  The
    macOS sandbox must be able to traverse that alias before it can reach the
    already-approved resolved executable. Homebrew adds both a package alias
    and a framework-entrypoint symlink, so walk every bounded expansion. Keep
    each grant at its exact distribution root instead of widening it to a
    user runtime cache or package-manager prefix.
    """

    roots: list[Path] = []
    current = executable.absolute()
    for _depth in range(16):
        expansion = _first_symlink_expansion(current)
        if expansion is None:
            break
        current = expansion
        if _path_is_within_any(current, _SEALED_SYSTEM_EXECUTABLE_ROOTS):
            continue
        root = _runtime_distribution_root(current)
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def _run_backend_process(argv: Sequence[str], *, env: Mapping[str, str], timeout_seconds: int) -> int:
    def apply_limits() -> None:
        resource_module = _resource
        if resource_module is None:
            return
        _set_resource_limit(resource_module.RLIMIT_CPU, _DEFAULT_CPU_SECONDS)
        _set_resource_limit(resource_module.RLIMIT_AS, _DEFAULT_MEMORY_BYTES)
        _set_resource_limit(resource_module.RLIMIT_FSIZE, _DEFAULT_FILE_BYTES)
        _set_resource_limit(resource_module.RLIMIT_NOFILE, _DEFAULT_OPEN_FILES)
        if hasattr(resource_module, "RLIMIT_NPROC"):
            _set_resource_limit(resource_module.RLIMIT_NPROC, _DEFAULT_PROCESSES)

    try:
        process = subprocess.Popen(
            list(argv),
            env=dict(env),
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=True,
            start_new_session=True,
            preexec_fn=apply_limits if _RESOURCE_AVAILABLE else None,
        )
    except OSError as error:
        raise RestrictedPytestError(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            f"Restricted pytest sandbox could not start; execution was not started: {error}",
        ) from error

    previous_handlers: dict[int, int | signal.Handlers | Callable[[int, FrameType | None], object] | None] = {}

    def forward_signal(signum: int, _frame: object) -> None:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        _ = signal.signal(signum, forward_signal)
    try:
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            with contextlib.suppress(OSError):
                os.killpg(process.pid, signal.SIGKILL)
            _ = process.wait()
            raise RestrictedPytestError(
                "pytest_restricted_timeout",
                f"Restricted pytest exceeded its {timeout_seconds}-second execution deadline.",
                exit_code=124,
            ) from error
    finally:
        for signum, handler in previous_handlers.items():
            _ = signal.signal(signum, handler)
    return return_code if return_code >= 0 else 128 + abs(return_code)


def _set_resource_limit(resource_name: int, requested: int) -> None:
    resource_module = _resource
    if resource_module is None:
        return
    try:
        current_soft, current_hard = resource_module.getrlimit(resource_name)
        hard = requested if current_hard < 0 else min(requested, current_hard)
        soft = hard if current_soft < 0 else min(requested, current_soft, hard)
        resource_module.setrlimit(resource_name, (soft, hard))
    except (OSError, ValueError):
        return
