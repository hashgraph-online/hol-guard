"""Plain language for a native runtime that is not ready, and the action that changes it.

``doctor --native`` and ``runtime status`` report a reason code. A code names
what the runtime layer decided, not what the person reading it can do, and the
one reason that already carried a message (another install owns the resident)
showed the difference: the code said ``native_resident_owner_busy`` and the
message said nothing crashed. This module answers the second question for the
rest of the reasons, and for the one state a code cannot explain at all.

That state is the common one. Both callers read the installed files without
running them, so a host with no usable runtime reports ``available: no`` under
``native_status_probe_skipped`` -- a reason that describes the probe rather than
the absence. Why each place Guard looks was refused is decidable from file
metadata alone, so this module decides it there and names the slot, never the
path, to keep a pasted report free of home directories and user names.

Nothing here starts a process, repairs a file or produces a verdict.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal, TypedDict

CandidateSlot = Literal["override", "bundled", "distribution"]
CandidateState = Literal[
    "absent",
    "not_a_regular_file",
    "untrusted_owner_or_mode",
    "not_executable",
    "unreadable",
    "present",
]


class NativeRuntimeCandidate(TypedDict):
    """One place Guard looks for its runtime, and what the files there say."""

    slot: CandidateSlot
    state: CandidateState


class NativeRuntimeDiagnosis(TypedDict):
    """What is wrong in plain words, the single action that changes it, and the evidence."""

    summary: str
    action: str
    candidates: list[NativeRuntimeCandidate]


_REINSTALL = (
    "Reinstall hol-guard so the runtime bundled with this version is restored: "
    "`uv tool install --force hol-guard` (or `pipx install --force hol-guard`)."
)
_REINSTALL_MATCHED = (
    "Reinstall hol-guard so the Python package and the runtime it bundles come from one "
    "version: `uv tool install --force hol-guard` (or `pipx install --force hol-guard`)."
)

# A resident that keeps dying is respawned under bounded backoff. The pause is
# the designed answer to a crash loop, but while it runs nothing evaluates a
# command, so it is a fault to report rather than a state to keep quiet about.
_RESTART_CIRCUIT_OPEN = (
    "Guard's native runtime kept failing to stay up, so restarts of it are paused. Until the "
    "pause ends, a request that needs the runtime is refused instead of evaluated, and the "
    "hooks that ask for one fail closed.",
    "Run `hol-guard repair` in a terminal to clear the dead resident state behind the loop, "
    "then retry. The pause itself lifts on its own once the retry time shown has passed.",
)

# Two Guard installs (for example a desktop app and a package-manager CLI) share
# one home-wide resident. Only one owns it; the other is healthy, not broken.
_RESIDENT_OWNER_BUSY = (
    "Another Guard install on this account owns the native resident runtime, so this "
    "install cannot start its own. Nothing crashed and no restarts were used. Keep one "
    "Guard install per user, or keep both on the same version so they share one runtime."
)

# Keyed by the reason codes ``native_runtime.py`` and ``doctor_native_runtime.py``
# produce. A reason absent from this table is one that needs no explaining
# (``native_ready``) or one the candidate evidence explains better.
_DIAGNOSES: dict[str, tuple[str, str]] = {
    "native_resident_owner_busy": (_RESIDENT_OWNER_BUSY, "No action is needed; protection is already running."),
    "native_version_mismatch": (
        "The installed runtime was built for a different hol-guard version than the Python "
        "package calling it. Guard will not pair them, because a rule the two disagree about "
        "would be decided differently on each side.",
        _REINSTALL_MATCHED,
    ),
    "native_protocol_mismatch": (
        "The installed runtime speaks a different request protocol than this package. This is "
        "a partial upgrade: one half of the install moved and the other did not.",
        _REINSTALL_MATCHED,
    ),
    "native_manifest_missing": (
        "The runtime binary is installed but the manifest that records what it should be is "
        "not next to it. Guard cannot confirm the binary is the one this version shipped.",
        _REINSTALL,
    ),
    "native_manifest_invalid": (
        "The manifest next to the runtime binary could not be read, or another account can "
        "write to it. Guard will not take an identity from a file it does not trust.",
        _REINSTALL,
    ),
    "native_manifest_runtime_mismatch": (
        "The runtime binary's size and hash are not the ones its own manifest records, so the "
        "binary was replaced or truncated after it was installed.",
        _REINSTALL,
    ),
    "native_manifest_protocol_mismatch": (
        "The runtime reports a different protocol version than its manifest records, so the "
        "binary and the manifest came from different builds.",
        _REINSTALL,
    ),
    "native_manifest_version_mismatch": (
        "The runtime's version does not match its manifest or the installed Python package, "
        "so part of this install is left over from an earlier version.",
        _REINSTALL_MATCHED,
    ),
    "native_manifest_rule_mismatch": (
        "The runtime carries a different rule set than its manifest records. Guard will not "
        "enforce rules it cannot tie back to the build it believes is installed.",
        _REINSTALL,
    ),
    "native_manifest_build_mismatch": (
        "The runtime was built from a different source commit than its manifest records, so "
        "the binary beside the manifest is not the one that manifest describes.",
        _REINSTALL,
    ),
    "native_resident_restart_circuit_open": _RESTART_CIRCUIT_OPEN,
    "native_status_probe_failed": (
        "Guard could not finish reading the installed runtime: the check itself failed rather "
        "than returning an answer.",
        "Run `hol-guard guard doctor --native` again. If it keeps failing, reinstall hol-guard: "
        "`uv tool install --force hol-guard`.",
    ),
    "native_status_reason_unavailable": (
        "The runtime returned a status Guard could not read, so the reason it gave is not reported here.",
        "Run `hol-guard guard doctor <harness>` for the full check.",
    ),
}

_UNAVAILABLE: dict[CandidateState, tuple[str, str]] = {
    "untrusted_owner_or_mode": (
        "Guard found its native runtime, but the file is owned by another account or is "
        "writable by one. Guard refuses to run a binary that someone else can replace, so "
        "protection stays off rather than running code it does not trust.",
        "Reinstall hol-guard as the account that runs it, without `sudo`: `uv tool install --force hol-guard`.",
    ),
    "not_executable": (
        "Guard's native runtime is in place but carries no execute permission, so it cannot "
        "be launched. Guard restores that bit on its own bundled copy the next time it runs "
        "the runtime, but it cannot do so on a filesystem mounted `noexec` or on a copy it "
        "does not own, and until the bit is back nothing evaluates a command.",
        "Run `hol-guard repair`, which puts the bit back on Guard's own copy. If it stays "
        "missing, reinstall hol-guard outside any `noexec` mount: "
        "`uv tool install --force hol-guard`.",
    ),
    "not_a_regular_file": (
        "What Guard found where its runtime belongs is not a regular file. A symlink or a "
        "device in that place is not something Guard will run.",
        _REINSTALL,
    ),
    "unreadable": (
        "Guard's native runtime is in place but this account cannot read it, so its identity "
        "could not be confirmed and nothing was launched. A file with no read permission, or "
        "a directory above it this account cannot enter, will do this.",
        _REINSTALL,
    ),
    "present": (
        "Guard's native runtime is installed and trusted, but it did not answer when asked "
        "what it supports. A runtime that cannot start cannot enforce anything.",
        "Run `hol-guard guard doctor <harness>` to run the full check and see the launch error.",
    ),
    "absent": (
        "This install has no native runtime binary. Guard's Python package is a control plane "
        "only: without the runtime it ships with, nothing evaluates a command, so protection "
        "is off.",
        _REINSTALL,
    ),
}

# Most specific first: an installed-but-refused file explains an unavailable
# runtime better than an empty slot beside it does.
_UNAVAILABLE_ORDER: tuple[CandidateState, ...] = (
    "untrusted_owner_or_mode",
    "unreadable",
    "not_executable",
    "not_a_regular_file",
    "present",
    "absent",
)


# ``availability.message`` reports the one decision that is not a fault: a
# resident another install already owns is working protection, so it needs a
# sentence rather than a repair. Every other explanation belongs to the
# diagnosis, which pairs it with the action that clears it; repeating it here
# would print it twice and carry it twice in the JSON payload.
_REPORTED_AS_MESSAGE = frozenset({"native_resident_owner_busy"})

# What the passive callers report when they read the installed files without
# running them. It describes the probe rather than the install, so it is the
# one code the candidate files answer better than the table does.
_PROBE_SKIPPED = "native_status_probe_skipped"


def native_runtime_message(reason_code: str) -> str | None:
    """The one-paragraph message the availability block itself carries, if any."""

    if reason_code not in _REPORTED_AS_MESSAGE:
        return None
    return _DIAGNOSES[reason_code][0]


def _candidate_state(path: Path) -> CandidateState:
    """Classify one candidate by its metadata alone, matching what validation checks.

    The order follows ``validate_native_binary``: file kind, then ownership and
    mode, then whether the bytes can be read at all, so the state names the
    first check the file would fail. The execute bit is checked after those
    because validation itself does not test it -- a non-executable binary
    validates and then fails to launch, which is a different repair from a
    binary nobody trusts and a different one again from a binary nobody can
    read.
    """

    from ..group_write_trust import trusted_owner_and_mode

    expanded = path.expanduser()
    try:
        metadata = expanded.lstat()
    except FileNotFoundError:
        return "absent"
    except (OSError, RuntimeError, ValueError):
        return "unreadable"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return "not_a_regular_file"
    if os.name != "nt":
        # Windows regular files carry no POSIX ownership semantics Guard reads;
        # identity validation accepts any regular file there.
        try:
            if not trusted_owner_and_mode(metadata, expanded):
                return "untrusted_owner_or_mode"
        except (OSError, RuntimeError, ValueError):
            return "unreadable"
    # Validation hashes the bytes before Guard will use a binary, so one this
    # account cannot open is refused with nothing launched. A file carrying
    # execute bits and no read bit passes every check above this one.
    if not os.access(expanded, os.R_OK):
        return "unreadable"
    if os.name == "nt":
        return "present"
    if not stat.S_IMODE(metadata.st_mode) & stat.S_IXUSR:
        return "not_executable"
    return "present"


def _candidate_slot(path: Path, override: str | None) -> CandidateSlot:
    from ..native_runtime import _is_bundled_candidate

    if _is_bundled_candidate(path):
        return "bundled"
    if override:
        try:
            if path.expanduser().absolute() == Path(override).expanduser().absolute():
                return "override"
        except (OSError, RuntimeError, ValueError):
            pass
    return "distribution"


def _candidate_rows() -> list[tuple[Path, NativeRuntimeCandidate]]:
    """Each place Guard looks, kept beside the row that describes it."""

    from ..native_runtime import _NATIVE_BINARY_ENV, _runtime_candidates

    override = os.environ.get(_NATIVE_BINARY_ENV)
    return [
        (path, {"slot": _candidate_slot(path, override), "state": _candidate_state(path)})
        for path in _runtime_candidates()
    ]


def native_runtime_candidates() -> list[NativeRuntimeCandidate]:
    """Say what the files in each place Guard looks are, without naming the places.

    A slot is a role, not a path, so this report can be pasted into an issue:
    ``bundled`` is the runtime inside the installed wheel, ``override`` the one
    an environment variable points at, ``distribution`` a separately installed
    one. Nothing here is executed.
    """

    return [row for _, row in _candidate_rows()]


def bundled_runtime_without_execute_bit() -> Path | None:
    """Guard's own runtime copy when the only thing wrong with it is the execute bit.

    ``not_executable`` is reached only after the file passed every check
    identity validation makes, so a path returned here is a regular file this
    account owns, can read, and installed itself. That is the one runtime fault
    Guard can repair, and ``runtime_install_repair`` is what repairs it. This
    reads file metadata and changes nothing.
    """

    return next(
        (path for path, row in _candidate_rows() if row["slot"] == "bundled" and row["state"] == "not_executable"),
        None,
    )


def native_install_file_state() -> tuple[CandidateState, NativeRuntimeDiagnosis | None]:
    """What the installed runtime files show on their own, without running them.

    This is the half of ``native_runtime_diagnosis`` that needs no reason code,
    answered the way selection answers it. Selection walks the candidates in
    order and takes the first one it accepts, so one candidate in a state Guard
    accepts is a working install however broken the ones beside it are: an
    override pointing at a file this account does not own does not make the
    bundled runtime underneath it need reinstalling. ``present`` is returned
    with no diagnosis, because whether a trusted binary then starts is a
    question only launching it answers and nothing here launches anything.

    Only when no candidate is in that state does this fall back to the worst
    fault among them, by the same order that answers an unavailable runtime,
    paired with the explanation for it. ``absent`` is returned with its
    diagnosis so the caller can decide what an install carrying no runtime at
    all means for it.
    """

    rows = _candidate_rows()
    candidates = [row for _, row in rows]
    states = {candidate["state"] for candidate in candidates}
    if "present" in states:
        return "present", None
    state: CandidateState = "absent"
    for candidate_state in _UNAVAILABLE_ORDER:
        if candidate_state in states:
            state = candidate_state
            break
    summary, action = _UNAVAILABLE[state]
    return state, {"summary": summary, "action": action, "candidates": candidates}


def _measured_state(rows: list[tuple[Path, NativeRuntimeCandidate]]) -> CandidateState | None:
    """The state of the candidate the passive availability answer measured.

    ``_passive_runtime_sha256`` reports ``available`` from the first candidate
    identity validation accepts, so that candidate, and only that one, is what
    a passive ``available: yes`` is about. Asking the validator which one it is
    keeps this from deciding admission a second time: a candidate Guard refuses
    for a reason the file metadata does not show is skipped here too.
    """

    from ..native_binary_identity import validate_native_binary

    return next((row["state"] for path, row in rows if validate_native_binary(path) is not None), None)


def native_runtime_diagnosis(
    reason_code: str,
    *,
    available: bool | None,
    restart_paced: bool = False,
) -> NativeRuntimeDiagnosis | None:
    """Explain a runtime that is not ready, or return None when nothing is wrong.

    A reason code in the table is a decision the runtime layer reached that the
    installed files cannot show -- a probe that failed, a manifest that
    disagrees with its binary, a resident another install owns -- so it is
    answered first. Everything else is diagnosed from the files, because the
    passive callers report a code about the probe they skipped while the files
    say what is actually missing. The files also catch the one broken state no
    reason code describes: a runtime that validates, is reported available, and
    still cannot be launched. ``restart_paced`` carries the one fault no file
    beside the binary can show: a runtime that is installed correctly, failed
    repeatedly anyway, and is now refused a restart until its pause ends.
    """

    rows = _candidate_rows()
    candidates = [row for _, row in rows]
    diagnosis = _DIAGNOSES.get(reason_code)
    if diagnosis is not None:
        return {"summary": diagnosis[0], "action": diagnosis[1], "candidates": candidates}
    if available is False:
        states = {candidate["state"] for candidate in candidates}
        state: CandidateState = "absent"
        for candidate_state in _UNAVAILABLE_ORDER:
            if candidate_state in states:
                state = candidate_state
                break
        summary, action = _UNAVAILABLE[state]
        return {"summary": summary, "action": action, "candidates": candidates}
    # Identity validation never tests the execute bit, so a runtime missing it
    # validates, is counted as available by the passive answer, and then fails
    # to launch. Only the passive answer carries that gap: a reason code from
    # the full probe either launched the runtime that produced it or is in the
    # table above, and blaming a candidate the probe stepped over would report
    # a healthy install as broken.
    if reason_code == _PROBE_SKIPPED and _measured_state(rows) == "not_executable":
        summary, action = _UNAVAILABLE["not_executable"]
        return {"summary": summary, "action": action, "candidates": candidates}
    # Last, because every answer above names the install fault a crash loop
    # grew out of, and fixing that fault is what clears the pause. On its own
    # it is still the whole story: a paused restart refuses every request for
    # the runtime while the files it was launched from stay perfectly valid.
    if restart_paced:
        summary, action = _RESTART_CIRCUIT_OPEN
        return {"summary": summary, "action": action, "candidates": candidates}
    return None
