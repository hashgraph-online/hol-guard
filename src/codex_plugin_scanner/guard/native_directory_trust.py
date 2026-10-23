"""Typed client for the native directory-trust owner; no Python evaluator.

Whether a request may name a directory is a Guard verdict, not transport, so
Rust decides it. Python frames what it read -- the Guard home it is serving,
its own home and temporary directory, and the candidate paths a hook sent --
binds the answer by ``request_id`` and canonical ``request_sha256``, and reads
the verdicts back in the order it asked.

Nothing here resolves a path or compares it against a root. A transport,
capability, or binding failure raises ``NativeDirectoryTrustError``; the hook
routes turn that into the same rejection an untrusted path gets, so an
unreachable runtime refuses a directory instead of trusting it.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TypeAlias

from .native_context import (
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)
from .path_resolution_cache import IdentityWitness, identity_unchanged, identity_witness

_FEATURE = "directory-trust-v1"
_HOOK_PATH_FEATURE = "hook-path-rules-v1"

#: The rules whose value is a harness spelling rather than a directory: the
#: runtime normalizes them before it decides, so a runtime that predates that
#: would read the spelling as a plain path.
_HOOK_PATH_RULES = frozenset({"hook-workspace", "exec-workdir", "payload-reference"})
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-directory-trust-request.v1"
_RESULT_SCHEMA = "guard-directory-trust-result.v1"
_MAX_REQUEST_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_directory_trust_result_invalid"

#: The reason a caller records when the runtime could not answer at all. It is
#: not one of the runtime's own verdicts: those name what was wrong with the
#: path, and this names what was wrong with the runtime.
UNAVAILABLE_REASON = "native_directory_trust_unavailable"


class NativeDirectoryTrustError(ValueError):
    """The native owner could not supply a bound directory-trust answer."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DirectoryTrustVerdict:
    """One candidate's answer: the path to use, or why it may not be used.

    A hook spelling has a third answer. ``absent`` means the request named
    no directory at all -- a blank value, a harness sentinel, or the shared
    temporary root a process without a workspace of its own runs in -- which
    is not a rejection and carries no reason.
    """

    __slots__ = ("absent", "parameter", "path", "reason")

    def __init__(self, parameter: str, path: str | None, reason: str | None, absent: bool = False) -> None:
        self.parameter = parameter
        self.path = path
        self.reason = reason
        self.absent = absent

    @property
    def trusted(self) -> bool:
        return self.path is not None


#: One candidate: the caller's label and the value, optionally followed by the
#: rule to hold it to when the label is not the rule's own name.
DirectoryTrustCandidate: TypeAlias = tuple[str, str] | tuple[str, str, str]


def _candidate_rule(candidate: DirectoryTrustCandidate) -> str:
    """The rule a candidate is held to: the third element, or its label."""

    return candidate[2] if len(candidate) == 3 else candidate[0]


def _candidate_payload(candidate: DirectoryTrustCandidate) -> dict[str, str]:
    payload = {"parameter": candidate[0], "value": candidate[1]}
    if len(candidate) == 3:
        payload["rule"] = candidate[2]
    return payload


def native_directory_trust(
    candidates: Sequence[DirectoryTrustCandidate],
    *,
    guard_home: Path | str,
    home_dir: Path | str | None = None,
    deadline_monotonic: float | None = None,
) -> list[DirectoryTrustVerdict]:
    """Settle every ``(parameter, value)`` candidate in one resident call.

    ``parameter`` names the rule, unless the candidate carries a third element
    that names it instead -- which is how one request asks about several
    spellings of the same directory without its labels colliding. The rules:
    ``guard-home`` has to resolve to the store
    this process is serving, ``workspace`` may also name a scratch directory
    the caller owns under a temporary root, and anything else has to sit under
    a trusted root. ``hook-workspace`` and ``exec-workdir`` are the harness
    spellings of a workspace, which the runtime normalizes before it applies
    the workspace rule, and ``payload-reference`` is an out-of-band payload
    file only Guard's own writer could have put where it is. The verdicts
    come back in the order they were asked for.

    ``deadline_monotonic`` caps the wait. A caller working to a deadline of
    its own — a hook with a host budget to keep — passes it so a slow resident
    cannot spend the whole budget settling paths; without one the call waits
    the module's own timeout.

    An identical ask the runtime has already answered is answered from that
    reply, for as long as every directory it was framed against is still the
    same object, owner and kind. See the memo below for what that reuse covers
    and why it is bounded by the directories rather than by a clock.
    """

    if not candidates:
        return []
    home = Path.home() if home_dir is None else Path(home_dir)
    temp_dir = tempfile.gettempdir()
    asked = tuple(candidates)
    remembered_key = (str(guard_home), str(home), temp_dir, asked)
    remembered = _remembered_answer(remembered_key)
    if remembered is not None:
        return remembered
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "guard_home": str(guard_home),
        "home_dir": str(home),
        # The resident has its own `TMPDIR`, which an isolated environment may
        # not share; the temporary-root rules follow this process's.
        "temp_dir": temp_dir,
        "candidates": [_candidate_payload(candidate) for candidate in asked],
    }
    hook_paths = any(_candidate_rule(candidate) in _HOOK_PATH_RULES for candidate in asked)
    result = _round_trip(
        request,
        _resolve_digest_home(Path(guard_home)),
        deadline_monotonic=deadline_monotonic,
        hook_paths=hook_paths,
    )
    verdicts = result.get("results")
    if not isinstance(verdicts, list) or len(verdicts) != len(candidates):
        raise NativeDirectoryTrustError(_INVALID_RESULT)
    answers: list[DirectoryTrustVerdict] = []
    for candidate, verdict in zip(candidates, verdicts, strict=True):
        parameter = candidate[0]
        if not isinstance(verdict, dict) or verdict.get("parameter") != parameter:
            raise NativeDirectoryTrustError(_INVALID_RESULT)
        path = verdict.get("path")
        reason = verdict.get("reason")
        if verdict.get("trusted") is True:
            if not isinstance(path, str) or not path:
                raise NativeDirectoryTrustError(_INVALID_RESULT)
            answers.append(DirectoryTrustVerdict(parameter, path, None))
            continue
        if verdict.get("absent") is True:
            answers.append(DirectoryTrustVerdict(parameter, None, None, absent=True))
            continue
        if not isinstance(reason, str) or not reason:
            raise NativeDirectoryTrustError(_INVALID_RESULT)
        answers.append(DirectoryTrustVerdict(parameter, None, reason))
    _remember_answer(remembered_key, asked, answers)
    return answers


# A hook names the same few directories on every request, and settling them is
# a round trip the hook's own budget pays for. An answer the runtime already
# gave is reused while everything it could have been about is demonstrably
# unchanged: every component of every spelling asked about, of every path the
# runtime returned, and of the Guard home, home and temporary directory the
# question was framed against is still the same object, with the same owner,
# of the same kind, and reached without a symlink.
#
# Those are the facts the runtime's rules read -- where a path resolves to,
# which root it falls under, whether it is a directory, and who owns a scratch
# workspace under a temporary root -- so an answer whose witness still holds is
# the answer the runtime would give again. That is why the reuse is bounded by
# the directories rather than by a clock: a timer would let a changed directory
# keep its old answer until it expired, and would spend a round trip on an
# unchanged one.
#
# Nothing here works a verdict out. Reuse can only repeat an admission the
# runtime made; a refusal is never remembered, so a path that was refused is
# always asked about again, and a relative or `~` spelling this process must
# not resolve is never remembered either.
_MAX_REMEMBERED_ASKS = 256
_memo_lock = threading.Lock()
_AskKey = tuple[str, str, str, tuple[DirectoryTrustCandidate, ...]]
_remembered_asks: dict[_AskKey, tuple[tuple[tuple[str, str], ...], IdentityWitness]] = {}


def _remembered_answer(key: _AskKey) -> list[DirectoryTrustVerdict] | None:
    """The runtime's own answer to this exact ask, while its witness still holds."""

    with _memo_lock:
        entry = _remembered_asks.get(key)
    if entry is None:
        return None
    settled, witness = entry
    if not identity_unchanged(witness):
        with _memo_lock:
            _remembered_asks.pop(key, None)
        return None
    return [DirectoryTrustVerdict(parameter, path, None) for parameter, path in settled]


def _remember_answer(
    key: _AskKey,
    asked: tuple[DirectoryTrustCandidate, ...],
    answers: Sequence[DirectoryTrustVerdict],
) -> None:
    """Remember an ask the runtime trusted every candidate of, if it can be witnessed."""

    settled: list[tuple[str, str]] = []
    for answer in answers:
        if answer.path is None:
            return
        settled.append((answer.parameter, answer.path))
    guard_home, home, temp_dir, _candidates = key
    witness = identity_witness(
        [guard_home, home, temp_dir] + [candidate[1] for candidate in asked] + [path for _parameter, path in settled]
    )
    if witness is None:
        return
    with _memo_lock:
        if len(_remembered_asks) >= _MAX_REMEMBERED_ASKS:
            _remembered_asks.clear()
        _remembered_asks[key] = (tuple(settled), witness)


def clear_remembered_directory_trust() -> None:
    with _memo_lock:
        _remembered_asks.clear()


def _round_trip(
    request: dict[str, Any],
    guard_home: Path,
    *,
    deadline_monotonic: float | None = None,
    hook_paths: bool = False,
) -> dict[str, object]:
    """One bound resident round trip; returns the verified result document."""

    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)

    status = _native_runtime_status_memo()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or (hook_paths and _HOOK_PATH_FEATURE not in status.capabilities.features)
    ):
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeDirectoryTrustError("native_directory_trust_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeDirectoryTrustError(
            prerequisite_unavailable_code("native_directory_trust_prerequisite_unavailable", guard_home)
        )
    started_at = time.monotonic()
    local_deadline = started_at + _TIMEOUT_SECONDS
    deadline = min(local_deadline, deadline_monotonic) if deadline_monotonic is not None else local_deadline
    remaining_seconds = deadline - time.monotonic()
    if remaining_seconds <= 0:
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)
    budget_ms = max(1, int(remaining_seconds * 1000))
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        envelope = json.dumps(
            {"operation": "directory_trust", "deadline_budget_ms": budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        # A path carrying lone surrogates cannot cross a strict JSON
        # transport. It is not a path this runtime may trust either.
        raise NativeDirectoryTrustError("native_directory_trust_component_unencodable") from error
    if len(envelope) > _MAX_REQUEST_BYTES:
        raise NativeDirectoryTrustError("native_directory_trust_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=deadline,
        )
    except Exception:
        output = None
    if output is None:
        # A shorter caller deadline is not evidence that the resident failed.
        caller_budget_expired = (
            deadline_monotonic is not None
            and deadline_monotonic < local_deadline
            and time.monotonic() >= deadline_monotonic
        )
        if not caller_budget_expired:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=UNAVAILABLE_REASON)
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeDirectoryTrustError(_INVALID_RESULT) from error
    error_code = _native_error(result)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeDirectoryTrustError(error_code)
    if (
        not isinstance(result, dict)
        or result.get("schema") != _RESULT_SCHEMA
        or result.get("request_id") != request["request_id"]
        or result.get("request_sha256") != request_sha256
        or result.get("status") != "ok"
        or result.get("code") != "ok"
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeDirectoryTrustError(_INVALID_RESULT)
    native_record_resident_success(status.identity.sha256, guard_home)
    return result


__all__ = [
    "UNAVAILABLE_REASON",
    "DirectoryTrustVerdict",
    "NativeDirectoryTrustError",
    "clear_remembered_directory_trust",
    "native_directory_trust",
]
