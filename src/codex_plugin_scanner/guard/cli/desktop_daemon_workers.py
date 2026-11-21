"""Fast path for the native daemon's Python children.

The native daemon starts `desktop daemon-workers`, `desktop library-serve` and
`desktop library-call` with `--guard-home <path>`. The worker host must
publish policy and the artifact reconcile (a library call) must finish before
the daemon reports ready, so both sit on every cold start. Building the Guard
command parser, importing the command hub and constructing the router's store
and context first added seconds before either ran, and none of them uses that
work. No lifecycle approval gate applies to these subcommands.

The worker host's first step after its imports is the installed-bundle check.
It starts here on a thread of its own, before those imports and the store
open, and the host waits for it instead of running it again. It runs the
packaged runtime, so it mostly waits on child processes and hashing, which
leave the interpreter free for the imports.

The store's first native call needs the runtime status: a hash of the packaged
runtime and a capability probe that starts it. That also starts here, on a
thread beside the imports, for the worker host and the library children alike:
each opens a store for its first call, and the reconcile the daemon waits on
before ready is a library call. They wait for it before opening the store.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable, Sequence
from contextlib import suppress
from pathlib import Path

_FAST_PATH_COMMANDS = frozenset({"daemon-workers", "library-serve", "library-call"})
_bundle_check: threading.Thread | None = None
_runtime_status: threading.Thread | None = None
# The status probe has its own deadlines; this only bounds a wait on a stuck one.
_RUNTIME_STATUS_WAIT_SECONDS = 30.0


def _launch_tokens(argv: Sequence[str]) -> list[str]:
    tokens = list(argv)
    if tokens[:1] == ["guard"]:
        tokens = tokens[1:]
    return tokens


def is_daemon_workers_fast_path_argv(argv: Sequence[str]) -> bool:
    """Return True for the exact launch the native daemon makes.

    That launch is `desktop <child> --guard-home <path>`. Any other shape,
    help included, stays on argparse.
    """

    tokens = _launch_tokens(argv)
    return (
        len(tokens) == 4
        and tokens[0] == "desktop"
        and tokens[1] in _FAST_PATH_COMMANDS
        and tokens[2] == "--guard-home"
        and bool(tokens[3])
        and not tokens[3].startswith("-")
    )


def _check_installed_bundle() -> None:
    from ..catalog_delivery.preparation_authority import load_installed_bundle

    # A failure is left for the migration's own load to raise and record.
    with suppress(Exception):
        load_installed_bundle()


def _start_bundle_check(guard_home: Path) -> None:
    global _bundle_check
    from ..extension_builder.native_executable_root import use_guard_home

    # The store registers the same folder when it opens; the check runs
    # before that, and its copy belongs in the same place.
    use_guard_home(guard_home)
    thread = threading.Thread(target=_check_installed_bundle, name="installed-bundle-check", daemon=True)
    thread.start()
    _bundle_check = thread


def wait_for_early_bundle_check() -> bool:
    """Wait for the bundle check this process started early.

    Only the first caller waits for it. False when none was started or it was
    already waited for, so a later migration attempt checks for itself.
    """

    global _bundle_check
    thread, _bundle_check = _bundle_check, None
    if thread is None:
        return False
    thread.join()
    return True


def _resolve_runtime_status() -> None:
    from ..native_runtime import native_runtime_status

    # The status is remembered for the process; a failure is left for the
    # store's own call to meet and report.
    with suppress(Exception):
        native_runtime_status()


def _start_runtime_status() -> None:
    global _runtime_status
    thread = threading.Thread(target=_resolve_runtime_status, name="native-runtime-status", daemon=True)
    thread.start()
    _runtime_status = thread


def wait_for_early_runtime_status() -> bool:
    """Wait for the runtime status this process started resolving early.

    Every caller waits until it has resolved, so library calls that arrive
    together do not each resolve it again. False when none was started.
    """

    thread = _runtime_status
    if thread is None:
        return False
    thread.join(_RUNTIME_STATUS_WAIT_SECONDS)
    return True


def _child(command: str) -> Callable[[Path], int]:
    if command == "daemon-workers":
        from ..workers.host import run_worker_host

        return run_worker_host
    from .desktop_library_call import run_library_call, serve_library_calls

    return serve_library_calls if command == "library-serve" else run_library_call


def run_daemon_workers_cli(argv: Sequence[str]) -> int:
    """Run the daemon child the launch names, for the guard home it names."""

    tokens = _launch_tokens(argv)
    if not is_daemon_workers_fast_path_argv(tokens):
        print("Guard daemon children require --guard-home.", file=sys.stderr)
        return 2
    _start_runtime_status()

    from ..config import resolve_guard_home
    from ..native_context import bind_context_digest_home

    guard_home: Path = resolve_guard_home(tokens[3])
    # The command router binds this for every subcommand; the child's digest
    # calls resolve against the same home.
    bind_context_digest_home(guard_home)
    if tokens[1] == "daemon-workers":
        _start_bundle_check(guard_home)
    return _child(tokens[1])(guard_home)


__all__ = [
    "is_daemon_workers_fast_path_argv",
    "run_daemon_workers_cli",
    "wait_for_early_bundle_check",
    "wait_for_early_runtime_status",
]
