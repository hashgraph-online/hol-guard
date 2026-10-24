"""Operating-system sandbox construction and execution for restricted pytest."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
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
# Output that names a denied file operation. A failed contained run that
# prints one of these gets the sandbox's own explanation appended, so the
# agent can move the write instead of treating the failure as a test bug.
_WRITE_DENIAL_MARKERS = (b"eperm", b"erofs", b"operation not permitted", b"read-only file system")
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
    user_site_root: Path | None = None,
) -> dict[str, str]:
    fields: dict[str, object] = {
        "source": dict(source),
        "workspace": workspace,
        "cwd": cwd,
        "private_home": private_home,
        "private_tmp": private_tmp,
        "allowed_executables": allowed_executables,
    }
    if user_site_root is not None:
        fields["user_site_root"] = user_site_root
    result = restricted_native("environment", fields, dict)
    if not all(isinstance(value, str) for value in result.values()):
        raise ValueError("Invalid native restricted environment reply")
    return result


def link_private_caches(private_tmp: Path, exec_roots: Sequence[Path] = ()) -> None:
    """Link the host caches a contained run reads into the tree it owns.

    Cargo takes its locks inside `CARGO_HOME`, so a contained run needs one it
    can write; the fetched crate sources it only reads stay where the host
    keeps them, linked in under the names cargo looks for. Nothing is linked
    when the native side grants no cache, and the plan's own executable roots
    decide that: a run the plan gave no cache to is not handed a link naming
    one either.
    """
    fields = {"private_tmp": private_tmp, "roots": list(exec_roots)}
    for entry in restricted_native("private_links", fields, list):
        link = Path(str(entry["link"]))
        link.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            link.symlink_to(Path(str(entry["target"])), target_is_directory=True)


def _link_user_site(source: Mapping[str, str], private_home: Path) -> Path | None:
    """Link the user's own Python packages into the private HOME for reading."""

    target = restricted_native("user_site_link_target", {"source": dict(source)}, (str, type(None)))
    if target is None:
        return None
    library = private_home / "Library"
    library.mkdir(mode=0o700)
    (library / "Python").symlink_to(target, target_is_directory=True)
    return Path(target)


def _backend_argv(plan: RestrictedPytestPlan, *, private_root: Path, user_site_root: Path | None = None) -> list[str]:
    if plan.output_roots:
        if plan.profile_version != "node-build-output-v1":
            raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Unexpected output grants.")
        from .restricted_node_tool import validate_build_output_root

        for path in plan.output_roots:
            validate_build_output_root(path, workspace=plan.workspace, cwd=plan.cwd)
    if plan.read_only_roots and plan.profile_version != "git-readonly-v1":
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Unexpected extra read grants.")
    if plan.backend == "macos-seatbelt":
        profile = _macos_profile(plan, private_root=private_root, user_site_root=user_site_root)
        return [str(plan.backend_executable), "-p", profile, "--", *plan.command]
    if plan.backend != "linux-bubblewrap":
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Unexpected restricted backend.")
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


def _macos_profile(plan: RestrictedPytestPlan, *, private_root: Path, user_site_root: Path | None = None) -> str:
    fields = dict(_profile_fields(plan, private_root))
    if user_site_root is not None:
        fields["user_site_root"] = user_site_root
    return restricted_native("macos_profile", fields, str)


def _bubblewrap_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    if plan.profile_version in READ_ONLY_TEST_PROFILES:
        from .restricted_linux_namespace import linux_readonly_argv

        return linux_readonly_argv(plan, private_root=private_root)
    return restricted_native("bubblewrap_argv", _profile_fields(plan, private_root), list)


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
    write_denial_note: str | Callable[[Iterable[bytes]], str | None] | None = None,
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

        def signal_run(signum: int | None = None) -> None:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL if signum is None else signum)
            else:
                # The Windows runner's kill-on-close job ends its descendants.
                process.kill()

        def forward_signal(signum: int, _frame: object) -> None:
            with contextlib.suppress(OSError):
                signal_run(signum)

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            _ = signal.signal(signum, forward_signal)
        try:
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as error:
                with contextlib.suppress(OSError):
                    signal_run()
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
                signal_run()
            for signum, handler in previous_handlers.items():
                _ = signal.signal(signum, handler)
            if stdout_capture is None:
                _replay_sandbox_output(stdout_file, sys.stdout)
            else:
                stdout_file.seek(0)
                stdout_capture.extend(stdout_file.read(_MAX_REPLAY_BYTES))
            if not merge_stderr:
                _replay_sandbox_output(stderr_file, sys.stderr)
        note = (
            _denial_note(write_denial_note, stdout_file, None if merge_stderr else stderr_file)
            if return_code != 0
            else None
        )
        if note is not None:
            destination = sys.stdout if merge_stderr else sys.stderr
            destination.write(f"\n[HOL Guard] {note}\n")
            destination.flush()
        return return_code if return_code >= 0 else 128 + abs(return_code)


def _denial_note(note: str | Callable[[Iterable[bytes]], str | None] | None, *sources: BinaryIO | None) -> str | None:
    """`note` for output that names a denial: a fixed note, or one chosen from the output."""
    if note is None:
        return None
    outputs = []
    for source in sources:
        if source is not None:
            source.seek(0)
            outputs.append(source.read(_MAX_REPLAY_BYTES))
    if callable(note):
        return note(outputs)
    denied = any(marker in output.lower() for output in outputs for marker in _WRITE_DENIAL_MARKERS)
    return note if denied else None


def _replay_sandbox_output(source: BinaryIO, destination: TextIO) -> None:
    source.seek(0)
    raw = source.read(_MAX_REPLAY_BYTES + 1)
    truncated = len(raw) > _MAX_REPLAY_BYTES
    # Windows programs end lines with CRLF; a lone CR stays replaced.
    text = raw[:_MAX_REPLAY_BYTES].decode("utf-8", errors="replace").replace("\r\n", "\n")
    safe_text = "".join(character if character in {"\n", "\t"} or ord(character) >= 32 else "�" for character in text)
    if truncated:
        safe_text += "\n[HOL Guard truncated restricted pytest output]\n"
    # A Windows pipe may use a code page without the replacement character.
    encoding = getattr(destination, "encoding", None) or "utf-8"
    destination.write(safe_text.encode(encoding, errors="replace").decode(encoding))
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
