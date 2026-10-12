"""Direct Node test execution under the shared read-only OS capability boundary."""

from __future__ import annotations

import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from .restricted_pytest_model import NODE_TEST_READ_ONLY_PROFILE_VERSION, RestrictedPytestError, RestrictedPytestPlan
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process
from .restricted_pytest_validation import (
    _locate_executable,
    _normalized_command,
    _path_is_within,
    _resolve_cwd,
    _resolve_executable,
    _resolve_workspace,
    _select_backend,
)

_INVALID = "node_test_restricted_invalid_command"
_MAGIC = {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}


def _node_runtime_args(command: Sequence[str]) -> tuple[str, ...]:
    """Accept only one bounded V8 heap option before a Node entrypoint."""
    argv = _normalized_command(command)
    runtime_args: list[str] = []
    if len(argv) >= 2 and Path(argv[0]).name in {"node", "nodejs"}:
        option = argv[1]
        if option.startswith("--max-old-space-size="):
            value = option.partition("=")[2]
            if not value.isascii() or not value.isdecimal() or not 16 <= int(value) <= 131072:
                raise RestrictedPytestError(_INVALID, "Invalid bounded Node memory option.")
            runtime_args.append(option)
    return tuple(runtime_args)


def nearest_project_root(cwd: Path, workspace: Path, relative: str) -> Path:
    """The closest directory holding `relative`, from cwd up to the workspace root.

    Mirrors Node and package-manager lookup, so a run in a package subdirectory
    still finds dependencies hoisted to the approved workspace root.
    """
    root = workspace.resolve(strict=True)
    directory = cwd.resolve(strict=True)
    if not _path_is_within(directory, root):
        return root
    while directory != root and not os.path.lexists(directory / relative):
        directory = directory.parent
    return directory


def _approved_node(executable: Path, workspace: Path) -> bool:
    metadata = executable.stat()
    if metadata.st_uid not in {0, os.getuid()}:
        return False
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or executable.name not in {"node", "nodejs"}:
        return False
    nvm = Path.home() / ".nvm" / "versions" / "node"
    trusted = any(
        _path_is_within(executable, root)
        for root in (
            workspace,
            Path("/usr/bin"),
            Path("/usr/local"),
            Path("/opt/homebrew"),
        )
    ) or (
        executable.parent.name == "bin"
        and executable.parent.parent.parent == nvm
        and re.fullmatch(r"v\d+\.\d+\.\d+", executable.parent.parent.name) is not None
    )
    if not trusted:
        return False
    with executable.open("rb") as stream:
        return stream.read(4) in _MAGIC


def prepare_restricted_node_test(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    platform: str | None = None,
    backend_executable: Path | None = None,
) -> RestrictedPytestPlan:
    argv = _normalized_command(command)
    runtime_args = _node_runtime_args(argv)
    test_index = 1 + len(runtime_args)
    if (
        len(argv) <= test_index
        or Path(argv[0]).name not in {"node", "nodejs"}
        or argv[test_index] != "--test"
        or any(value in {";", "&&", "||", "|", "|&", "&"} for value in argv)
    ):
        raise RestrictedPytestError(_INVALID, "Protected Node execution requires direct node --test argv.")
    backend, backend_path = _select_backend(platform=platform or sys.platform, backend_executable=backend_executable)
    if backend not in {"macos-seatbelt", "linux-bubblewrap"}:
        raise RestrictedPytestError(
            "node_test_restricted_sandbox_unavailable",
            "Credential-filtering Node containment is unavailable; execution was not started.",
        )
    root = _resolve_workspace(workspace)
    directory = _resolve_cwd(cwd or root, workspace=root)
    executable = _resolve_executable(argv[0], cwd=directory)
    if not _approved_node(executable, root):
        raise RestrictedPytestError(_INVALID, "The Node runtime does not resolve to an approved native executable.")
    launcher = _locate_executable(argv[0], cwd=directory)
    # Launch the resolved native image: no mutable shell entrypoint or PATH retry.
    return RestrictedPytestPlan(
        profile_version=NODE_TEST_READ_ONLY_PROFILE_VERSION,
        backend=backend,
        backend_executable=backend_path,
        workspace=root,
        cwd=directory,
        command=(str(executable), *runtime_args, *argv[test_index:]),
        executable=executable,
        allowed_executables=tuple(dict.fromkeys((launcher, executable))),
        denied_capabilities=(
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "workspace-write",
            "workspace-credential-read",
            "unapproved-process-exec",
            "privileged-operation",
        ),
    )


def run_restricted_node_test(
    command: Sequence[str],
    *,
    workspace: Path,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: int = 1800,
    prepared_plan: RestrictedPytestPlan | None = None,
    authorize_capability: Callable[[tuple[str, ...]], None] | None = None,
) -> int:
    if timeout_seconds <= 0 or timeout_seconds > 86400:
        raise RestrictedPytestError(_INVALID, "Protected Node timeout must be between 1 second and 24 hours.")
    plan = prepared_plan or prepare_restricted_node_test(command, workspace=workspace, cwd=cwd)
    if plan.profile_version != NODE_TEST_READ_ONLY_PROFILE_VERSION or plan.backend not in {
        "macos-seatbelt",
        "linux-bubblewrap",
    }:
        raise RestrictedPytestError(_INVALID, "Unexpected protected Node execution profile.")
    with tempfile.TemporaryDirectory(prefix="hol-guard-node-test-") as temporary:
        root = Path(temporary).resolve()
        home, tmp = root / "home", root / "tmp"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        launch_env = _restricted_environment(
            env if env is not None else os.environ,
            workspace=plan.workspace,
            cwd=plan.cwd,
            private_home=home,
            private_tmp=tmp,
            allowed_executables=plan.allowed_executables,
        )
        # Node preloads and search paths from the host are not repository test input.
        launch_env.pop("NODE_OPTIONS", None)
        launch_env.pop("NODE_PATH", None)
        from .restricted_node_capabilities import linux_node_environment

        launch_env = linux_node_environment(
            plan,
            private_root=root,
            environment=launch_env,
            timeout_seconds=timeout_seconds,
            authorize_capability=authorize_capability,
        )
        return _run_backend_process(
            _backend_argv(plan, private_root=root),
            env=launch_env,
            timeout_seconds=timeout_seconds,
            cwd=plan.cwd,
            node_virtual_address_space=plan.backend == "linux-bubblewrap",
        )
