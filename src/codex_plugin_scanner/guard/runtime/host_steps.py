"""Run a step Guard proved again directly on the host, outside the sandbox."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from pathlib import Path

from .restricted_pytest_model import RestrictedPytestError

# Variables that move Git to another repository, index or object store. A host
# step runs in the directory Guard judged, so Git must find its repository
# there.
_GIT_LOCATION = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    }
)


def run_on_host(
    command: str,
    *,
    cwd: Path,
    workspace: Path,
    timeout_seconds: int,
    merge_stderr: bool,
    label: str,
    excluded: tuple[Path, ...] = (),
) -> int:
    """Run `command` with `/bin/sh` in `cwd` and return its exit status.

    `label` names the step in the timeout error. The search path drops every
    entry inside `workspace` or `excluded`, which hold files the step's own
    repository or contained work could have written, and Git finds its
    repository from `cwd` alone.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    environment = {name: value for name, value in os.environ.items() if name not in _GIT_LOCATION}
    environment["PATH"] = outside_search_path(os.environ.get("PATH", ""), workspace, *excluded)
    process = subprocess.Popen(
        ["/bin/sh", "-c", command],
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stderr=subprocess.STDOUT if merge_stderr else None,
        start_new_session=True,
    )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise RestrictedPytestError(
            "pytest_restricted_timeout",
            f"{label} exceeded the {timeout_seconds}-second execution deadline.",
            exit_code=124,
        ) from error
    return return_code if return_code >= 0 else 128 + abs(return_code)


def outside_search_path(search_path: str, workspace: Path, *excluded: Path) -> str:
    """`search_path` without relative entries or entries inside `workspace` or `excluded`.

    The checks could plant a `git` or `gh` in a relative or workspace entry,
    and a new checkout holds whatever its branch tracks; a host step would run
    either unsandboxed, as the sandbox's own PATH filter anticipates.
    """
    roots = [root.resolve() for root in (workspace, *excluded)]
    kept: list[str] = []
    for entry in search_path.split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        resolved = Path(entry).resolve()
        if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
            kept.append(entry)
    return os.pathsep.join(kept)
