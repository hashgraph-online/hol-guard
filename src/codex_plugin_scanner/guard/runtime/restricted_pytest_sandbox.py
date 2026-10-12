"""Operating-system sandbox construction and execution for restricted pytest."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import BinaryIO, TextIO

from ..native_restricted_pytest import restricted_native
from .restricted_pytest_model import (
    _DEFAULT_CPU_SECONDS,
    _DEFAULT_FILE_BYTES,
    _DEFAULT_MEMORY_BYTES,
    _DEFAULT_OPEN_FILES,
    _DEFAULT_PROCESSES,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    READ_ONLY_TEST_PROFILES,
    RestrictedPytestError,
    RestrictedPytestPlan,
)

_RESOURCE_AVAILABLE = os.name == "posix"
_MAX_REPLAY_BYTES = 1_048_576
_NODE_VIRTUAL_ADDRESS_BYTES = 16 * 1024 * 1024 * 1024
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
    result = restricted_native(
        "environment",
        {
            "source": dict(source),
            "workspace": workspace,
            "cwd": cwd,
            "private_home": private_home,
            "private_tmp": private_tmp,
            "allowed_executables": allowed_executables,
        },
        dict,
    )
    if not all(isinstance(value, str) for value in result.values()):
        raise ValueError("Invalid native restricted environment reply")
    return result


def _backend_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    if plan.output_roots:
        if plan.profile_version != "node-build-output-v1":
            raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Unexpected output grants.")
        from .restricted_node_tool import validate_build_output_root

        for path in plan.output_roots:
            validate_build_output_root(path, workspace=plan.workspace)
    if plan.read_only_roots and plan.profile_version != "git-readonly-v1":
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Unexpected extra read grants.")
    if plan.backend == "macos-seatbelt":
        profile = _macos_profile(plan, private_root=private_root)
        return [str(plan.backend_executable), "-p", profile, "--", *plan.command]
    return _bubblewrap_argv(plan, private_root=private_root)


def _profile_fields(plan: RestrictedPytestPlan, private_root: Path) -> Mapping[str, object]:
    return {
        key: getattr(plan, key)
        for key in (
            "profile_version",
            "workspace",
            "cwd",
            "allowed_executables",
            "read_only_roots",
            "output_roots",
            "command",
            "backend_executable",
        )
    } | {"private_root": private_root}


def _macos_profile(plan: RestrictedPytestPlan, *, private_root: Path) -> str:
    return restricted_native("macos_profile", _profile_fields(plan, private_root), str)


def _collection_link_metadata(plan: RestrictedPytestPlan) -> tuple[Path, ...]:
    return tuple(
        Path(path)
        for path in restricted_native("collection_link_metadata", _profile_fields(plan, plan.workspace), list)
    )


def _bubblewrap_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    if plan.profile_version in READ_ONLY_TEST_PROFILES:
        from .restricted_linux_namespace import linux_readonly_argv

        return linux_readonly_argv(plan, private_root=private_root)
    return restricted_native("bubblewrap_argv", _profile_fields(plan, private_root), list)


def _dedupe_parent_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    return tuple(Path(path) for path in restricted_native("dedupe_parent_paths", {"roots": paths}, list))


def _ancestor_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    return tuple(Path(path) for path in restricted_native("ancestor_paths", {"roots": paths}, list))


def _runtime_read_roots(plan: RestrictedPytestPlan, *, private_root: Path | None = None) -> tuple[Path, ...]:
    return tuple(
        Path(path)
        for path in restricted_native(
            "runtime_roots",
            {
                "allowed_executables": plan.allowed_executables,
                "workspace": plan.workspace,
                "private_root": private_root,
            },
            list,
        )
    )


def _symlink_runtime_roots(executable: Path) -> tuple[Path, ...]:
    return tuple(Path(path) for path in restricted_native("symlink_runtime_roots", {"path": executable}, list))


def _current_user_process_ceiling() -> int:
    if sys.platform not in {"darwin", "linux"}:
        return _DEFAULT_PROCESSES
    return restricted_native("process_ceiling", {}, int)


def _run_backend_process(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: int,
    cwd: Path | None = None,
    stdout_capture: bytearray | None = None,
    node_virtual_address_space: bool = False,
    merge_stderr: bool = False,
) -> int:
    if (
        node_virtual_address_space
        and sys.platform == "linux"
        and (not _RESOURCE_AVAILABLE or _resource is None or not hasattr(_resource, "RLIMIT_DATA"))
    ):
        raise RestrictedPytestError(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "Linux Node memory limits are unavailable; execution was not started.",
        )
    # RLIMIT_NPROC counts the whole user, not this run. A static 64-process
    # ceiling prevents Node from spawning even one test worker on busy desktops.
    process_ceiling = _current_user_process_ceiling() if _RESOURCE_AVAILABLE else _DEFAULT_PROCESSES

    def apply_limits() -> None:
        resource_module = _resource
        if resource_module is None:
            return
        _set_resource_limit(resource_module.RLIMIT_CPU, _DEFAULT_CPU_SECONDS)
        if node_virtual_address_space and sys.platform == "linux":
            # V8/Wasm reserves inaccessible cages larger than its working heap.
            # DATA bounds heap/private writable maps on the required Linux kernel;
            # it is not an aggregate RSS/cgroup limit. Never widen AS without it.
            if not hasattr(resource_module, "RLIMIT_DATA"):
                raise RuntimeError("Linux Node data limits are unavailable.")
            _set_resource_limit(resource_module.RLIMIT_DATA, _DEFAULT_MEMORY_BYTES, required=True)
            _set_resource_limit(resource_module.RLIMIT_AS, _NODE_VIRTUAL_ADDRESS_BYTES, required=True)
        else:
            _set_resource_limit(resource_module.RLIMIT_AS, _DEFAULT_MEMORY_BYTES)
        _set_resource_limit(resource_module.RLIMIT_FSIZE, _DEFAULT_FILE_BYTES)
        _set_resource_limit(resource_module.RLIMIT_NOFILE, _DEFAULT_OPEN_FILES)
        if hasattr(resource_module, "RLIMIT_NPROC"):
            _set_resource_limit(resource_module.RLIMIT_NPROC, process_ceiling)

    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        try:
            process = subprocess.Popen(
                list(argv),
                env=dict(env),
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stdout_file if merge_stderr else stderr_file,
                close_fds=True,
                start_new_session=True,
                preexec_fn=apply_limits if _RESOURCE_AVAILABLE else None,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RestrictedPytestError(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
                f"Restricted pytest sandbox could not start; execution was not started: {error}",
            ) from error

        previous_handlers: dict[
            int,
            int | signal.Handlers | Callable[[int, FrameType | None], object] | None,
        ] = {}

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
            # The run owns this new session/group. Stop lingering workers even
            # if the launcher exited successfully before all descendants did.
            with contextlib.suppress(OSError):
                os.killpg(process.pid, signal.SIGKILL)
            for signum, handler in previous_handlers.items():
                _ = signal.signal(signum, handler)
            if stdout_capture is None:
                _replay_sandbox_output(stdout_file, sys.stdout)
            else:
                stdout_file.seek(0)
                stdout_capture.extend(stdout_file.read(_MAX_REPLAY_BYTES))
            if not merge_stderr:
                _replay_sandbox_output(stderr_file, sys.stderr)
        return return_code if return_code >= 0 else 128 + abs(return_code)


def _replay_sandbox_output(source: BinaryIO, destination: TextIO) -> None:
    source.seek(0)
    raw = source.read(_MAX_REPLAY_BYTES + 1)
    truncated = len(raw) > _MAX_REPLAY_BYTES
    text = raw[:_MAX_REPLAY_BYTES].decode("utf-8", errors="replace")
    safe_text = "".join(character if character in {"\n", "\t"} or ord(character) >= 32 else "�" for character in text)
    if truncated:
        safe_text += "\n[HOL Guard truncated restricted pytest output]\n"
    destination.write(safe_text)
    destination.flush()


def _set_resource_limit(resource_name: int, requested: int, *, required: bool = False) -> None:
    resource_module = _resource
    if resource_module is None:
        if required:
            raise RuntimeError("Required resource limits are unavailable.")
        return
    try:
        current_soft, current_hard = resource_module.getrlimit(resource_name)
        hard = requested if current_hard < 0 else min(requested, current_hard)
        soft = hard if current_soft < 0 else min(requested, current_soft, hard)
        resource_module.setrlimit(resource_name, (soft, hard))
        if required and any(value < 0 or value > requested for value in resource_module.getrlimit(resource_name)):
            raise RuntimeError("Required resource limits were not enforced.")
    except (OSError, ValueError) as error:
        if required:
            raise RuntimeError("Required resource limits could not be enforced.") from error
        return
