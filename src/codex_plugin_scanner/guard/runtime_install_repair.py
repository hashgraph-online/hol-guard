"""Repair the native runtime install itself, for the one break the runtime cannot fix.

``hol-guard repair`` already prunes stale resident state, but it never touched
the install that state is launched from. Two things stop a runtime before it
starts, and only one of them has a repair: a bundled binary that lost its owner
execute bit can have it put back, while a binary that disagrees with the package
calling it can only be replaced by reinstalling.

The execute bit belongs here rather than in the runtime because a binary with no
execute bit cannot run the code that would restore it. Guard does restore the
bit on its own bundled copy on the way to launching it, but ``runtime status``
and ``doctor --native`` read the install without launching anything, so a host
in that state reports the fault every time and never clears it.

Nothing here evaluates a command, produces a verdict or replaces a file. The
only write is the execute bit on a copy Guard installed and still owns, and it
is verified afterwards, so running this twice changes nothing the second time.
A mismatched install is reported with the reinstall that clears it, never
reinstalled on the user's behalf.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Literal, TypedDict

from .cli.doctor_native_diagnosis import NativeRuntimeCandidate, bundled_runtime_without_execute_bit

Outcome = Literal["healthy", "absent", "planned", "restored", "refused", "needs_reinstall"]


class NativeInstallRepair(TypedDict):
    """What the install needed, what was done about it, and what is left for the user."""

    outcome: Outcome
    summary: str
    # The step the user may still have to take, or ``None`` when none is left.
    action: str | None
    candidates: list[NativeRuntimeCandidate]


_RESTORED = (
    "Guard's bundled native runtime had lost its execute permission; the bit is back and the "
    "runtime can be launched again."
)
_NOEXEC_CAVEAT = (
    "If the runtime still does not start, the folder it sits in is mounted `noexec`. Reinstall "
    "hol-guard outside that mount: `uv tool install --force hol-guard`."
)
_PLANNED = "Guard's bundled native runtime carries no execute permission; the bit would be restored."
_REFUSED = (
    "Guard could not restore the execute permission on its own bundled native runtime. The file "
    "system is read-only, or the file is no longer owned by this account."
)
_REFUSED_ACTION = (
    "Reinstall hol-guard as the account that runs it, without `sudo`: `uv tool install --force hol-guard`."
)
_HEALTHY = (
    "Guard's native runtime is installed where Guard looks for it, owned by this account, and "
    "carries the execute bit. Nothing here launched it: `hol-guard doctor --native` is the check "
    "that starts the runtime and confirms it matches the manifest it shipped with."
)


def _is_executable(path: Path) -> bool:
    """True when the owner execute bit is set, read from the file rather than guessed.

    ``os.access`` answers for the calling account and ignores how the file
    system is mounted, so it would call a binary on a ``noexec`` mount
    executable. The bit itself is the only part of this that Guard controls, so
    the bit is what this verifies and the caller names the mount as the
    remaining possibility.
    """

    try:
        metadata = path.lstat()
    except (OSError, RuntimeError, ValueError):
        return False
    return stat.S_ISREG(metadata.st_mode) and bool(stat.S_IMODE(metadata.st_mode) & stat.S_IXUSR)


def _report(
    outcome: Outcome,
    summary: str,
    action: str | None,
    candidates: list[NativeRuntimeCandidate] | None = None,
) -> NativeInstallRepair:
    from .cli.doctor_native_diagnosis import native_runtime_candidates

    # Read after the repair, so the evidence describes the install as it now is.
    rows = native_runtime_candidates() if candidates is None else candidates
    return {"outcome": outcome, "summary": summary, "action": action, "candidates": rows}


def _pending_reinstall() -> NativeInstallRepair:
    """Report what the installed files show, for the faults this cannot repair.

    Only the files are read. A runtime that is in place and trusted is reported
    healthy even though nothing here started it: this step owns the install, and
    whether the runtime then answers is what ``doctor --native`` asks.

    A host carrying no runtime binary at all is reported but not counted as
    something this repair left undone. An install that never had one -- a source
    checkout, a platform with no native wheel -- is not a Guard home that broke,
    and the updater already owns putting a missing wheel back.
    """

    from .cli.doctor_native_diagnosis import native_install_file_state

    state, diagnosis = native_install_file_state()
    if diagnosis is None:
        return _report("healthy", _HEALTHY, None)
    outcome: Outcome = "absent" if state == "absent" else "needs_reinstall"
    return _report(outcome, diagnosis["summary"], diagnosis["action"], diagnosis["candidates"])


def repair_native_runtime_install(*, dry_run: bool) -> NativeInstallRepair:
    """Restore a missing execute bit on Guard's own runtime; report anything else.

    This takes no Guard home: the runtime install belongs to the installed
    package, and every home on the account launches the same copy.
    """

    target = bundled_runtime_without_execute_bit()
    if target is None:
        return _pending_reinstall()
    if dry_run:
        return _report("planned", _PLANNED, None)

    from .native_runtime import _restore_bundled_runtime_execute_bit

    # The helper applies the same ownership checks the launch path applies and
    # reports nothing, so the file itself is what says whether it worked.
    _restore_bundled_runtime_execute_bit(target)
    if not _is_executable(target):
        return _report("refused", _REFUSED, _REFUSED_ACTION)
    return _report("restored", _RESTORED, _NOEXEC_CAVEAT)


__all__ = ["NativeInstallRepair", "repair_native_runtime_install"]
