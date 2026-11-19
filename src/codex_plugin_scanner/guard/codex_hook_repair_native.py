"""Read-only, deadline-owned native inspection for an exact repair plan."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import group_write_trust
from . import native_runtime as native
from .codex_hook_file_integrity import hook_validation_deadline
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import inspect_runtime
from .runtime_transition import TransitionError, inverse_recovery_budget


def _expanded(override: str | None) -> str | None:
    """The override with ``~user`` expanded as the launcher does; the resident expands only a bare ``~``."""
    if not override:
        return override
    try:
        return str(Path(override).expanduser())
    except RuntimeError:
        return override


def inspect_codex_repair_native_runtime(*, deadline_monotonic: float) -> NativeRuntimeIdentity:
    """Inspect existing selection without chmod, installation or launch override.

    The resident finds, admits, probes and pins the runtime; see
    ``rust/crates/guard-runtime/src/transition_files/publication_inspect_runtime.rs``.
    This process names the facts only it holds: the launch mode and override,
    the installed layout and package version, the checker file whose group the
    manifest trust follows, and the interpreter's base prefix.
    """

    mode = native.native_mode()
    with inverse_recovery_budget(deadline_monotonic), hook_validation_deadline(deadline_monotonic):
        identity = inspect_runtime(
            deadline=deadline_monotonic,
            mode=mode,
            binary_override=_expanded(os.environ.get(native._NATIVE_BINARY_ENV)),
            bundled=native._bundled_runtime_candidate(),
            distribution=native._distribution_candidates() if mode == "force" else (),
            package_version=native._python_package_version(),
            checker=getattr(group_write_trust, "__file__", None),
            base_prefix=getattr(sys, "base_prefix", None),
        )
    path, size, mtime_ns, sha256 = (identity.get(key) for key in ("path", "size", "mtime_ns", "sha256"))
    if not (
        isinstance(path, str)
        and isinstance(sha256, str)
        and isinstance(size, int)
        and isinstance(mtime_ns, int)
        and not isinstance(size, bool)
        and not isinstance(mtime_ns, bool)
    ):
        raise TransitionError("native_transition_invalid")
    return NativeRuntimeIdentity(Path(path), size, mtime_ns, sha256)
