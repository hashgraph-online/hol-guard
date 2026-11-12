"""Resident bridge for the ``codex_hook_manifest_verify`` op.

The resident decides whether the authenticated Codex hook manifest still
describes the live installation; this module ships what the caller
authenticated plus the path, package-root, command-split and private-group
spellings only this interpreter can produce. An unavailable resident reports
the installation as unverified, never as valid.
"""

from __future__ import annotations

import math
import os
import time
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from . import codex_hook_file_integrity as integrity
from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS
from .codex_hook_file_integrity import CodexHookIntegrityError, active_hook_validation_deadline, split_hook_command
from .native_context import _resolve_existing_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

CODEX_HOOK_MANIFEST_VERIFY_FEATURE = "codex-hook-manifest-verify-v1"
_REQUEST_SCHEMA = "guard-codex-hook-manifest-verify-request.v1"
_RESULT_SCHEMA = "guard-codex-hook-manifest-verify-result.v1"
# Mirrors ``CODEX_HOOK_MANIFEST_VERIFY_MAX_BYTES``.
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
# The resident stats and hashes a dozen packaged files and the interpreter.
_TIMEOUT_SECONDS = 10.0
# Each round answers every private-group question the previous one asked, so
# a second round settles the walk; a third covers files that changed between
# the two.
_MAX_ROUNDS = 3
# The resident's JSON parser refuses a value nested past 32 levels with the
# frame at 0. A live hook group sits under the request object, ``hooks`` and
# its event's list, so its deepest value may sit 29 levels down, counting the
# group itself as the first. The authenticated manifest sits one level higher.
_MAX_GROUP_DEPTH = 29
_MAX_MANIFEST_DEPTH = 31
# The widest integers the resident's number type carries exactly.
_EXACT_INT_MIN = -(2**63)
_EXACT_INT_MAX = 2**64 - 1
_UNAVAILABLE_REASON = "codex_hook_manifest_verification_unavailable"
_UNAVAILABLE_MESSAGE = "Guard could not verify the Codex hook installation; run repair and retry."
_MANIFEST_INVALID = ("codex_hook_manifest_invalid", "The Codex hook manifest holds values Guard cannot verify.")


class _UnrepresentableError(ValueError):
    """A value JSON cannot carry without changing its meaning."""


def native_codex_hook_manifest_verify(
    *,
    guard_home: Path,
    hooks: object,
    manifest: Mapping[str, object] | None = None,
    expected: Mapping[str, object] | None = None,
    failure: tuple[str, str] | None = None,
) -> dict[str, object]:
    """The integrity state the resident decides for ``manifest`` or ``failure``."""

    try:
        home = Path(_resolve_existing_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        return _unavailable_state()
    if not ensure_resident_prerequisite(home):
        return _unavailable_state()
    wire = _request(hooks, manifest, expected, failure)
    answers: list[dict[str, object]] = []
    for _ in range(_MAX_ROUNDS):
        wire["request_id"] = f"codex-hook-manifest-verify-{uuid4().hex}"
        wire["private_groups"] = answers
        payload = _ask(wire, home)
        if payload is None:
            return _unavailable_state()
        questions = payload.get("private_group_questions")
        state = payload.get("state")
        if not isinstance(questions, list) or not isinstance(state, dict) or set(state) != set(_unavailable_state()):
            return _unavailable_state()
        if not questions:
            return dict(state)
        answered = {(item["owner_uid"], item["group_gid"]) for item in answers}
        for question in questions:
            owner_uid = question.get("owner_uid") if isinstance(question, dict) else None
            group_gid = question.get("group_gid") if isinstance(question, dict) else None
            if not isinstance(owner_uid, int) or not isinstance(group_gid, int) or (owner_uid, group_gid) in answered:
                return _unavailable_state()
            private = integrity._owner_is_only_group_member(owner_uid, group_gid)
            answers.append({"owner_uid": owner_uid, "group_gid": group_gid, "private": private is True})
    return _unavailable_state()


def _request(
    hooks: object,
    manifest: Mapping[str, object] | None,
    expected: Mapping[str, object] | None,
    failure: tuple[str, str] | None,
) -> dict[str, object]:
    posix = os.name != "nt"
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": "",
        "posix": posix,
        "current_uid": os.getuid() if posix else None,
        "failure": None,
        "manifest": None,
        "hooks": _hooks_wire(hooks),
        "expected": None,
        "canonical_paths": {},
        "installed_python_package_files": [],
        "command_argvs": {},
        "private_groups": [],
    }
    if failure is None and manifest is not None and expected is not None:
        try:
            wire.update(
                manifest=_plain(manifest, 1, _MAX_MANIFEST_DEPTH),
                expected=dict(expected),
                **_interpreter_spellings(manifest),
            )
            return wire
        except _UnrepresentableError:
            failure = _MANIFEST_INVALID
        except CodexHookIntegrityError as exc:
            failure = (exc.reason, exc.message)
    reason, message = failure or (_UNAVAILABLE_REASON, _UNAVAILABLE_MESSAGE)
    wire["failure"] = {"reason": reason, "message": message}
    return wire


def _interpreter_spellings(manifest: Mapping[str, object]) -> dict[str, object]:
    paths: list[str] = []
    packaged = manifest.get("packaged_files")
    for item in packaged if isinstance(packaged, list) else ():
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            paths.append(item["path"])
    interpreter = manifest.get("interpreter")
    if isinstance(interpreter, dict):
        target = interpreter.get("target")
        for value in (interpreter.get("invocation_path"), target.get("path") if isinstance(target, dict) else None):
            if isinstance(value, str):
                paths.append(value)
    canonical: dict[str, str] = {}
    installed: list[str] = []
    for spelling in dict.fromkeys(paths):
        if not Path(spelling).is_absolute():
            continue
        try:
            canonical[spelling] = integrity.canonical_path(Path(spelling))
        except CodexHookIntegrityError:
            # An exhausted deadline or refused path is the caller's failure,
            # not a spelling the resident can do without.
            raise
        except (OSError, RuntimeError):
            pass
        if integrity._is_installed_python_package_file(Path(spelling)):
            installed.append(spelling)
    argvs: dict[str, list[str] | None] = {}
    events = manifest.get("events")
    for binding in events if isinstance(events, list) else ():
        handler = binding.get("handler") if isinstance(binding, dict) else None
        command = handler.get("command") if isinstance(handler, dict) else None
        if isinstance(command, str) and command not in argvs:
            argvs[command] = split_hook_command(command)
    return {"canonical_paths": canonical, "installed_python_package_files": installed, "command_argvs": argvs}


def _hooks_wire(hooks: object) -> dict[str, object] | None:
    if not isinstance(hooks, dict):
        return None
    wire: dict[str, object] = {}
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        if isinstance(groups, list):
            wire[event_name] = [_plain_or_none(group) for group in groups]
    return wire


def _plain_or_none(group: object) -> object:
    try:
        return _plain(group, 1, _MAX_GROUP_DEPTH)
    except _UnrepresentableError:
        return None


def _plain(value: object, depth: int, limit: int) -> object:
    # A tuple is refused, not sent as a list: Python never finds the two equal.
    if depth > limit:
        raise _UnrepresentableError
    if value is None or isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        if _EXACT_INT_MIN <= value <= _EXACT_INT_MAX:
            return value
        raise _UnrepresentableError
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        raise _UnrepresentableError
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise _UnrepresentableError
        return {key: _plain(item, depth + 1, limit) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item, depth + 1, limit) for item in value]
    raise _UnrepresentableError


def _ask(wire: dict[str, object], home: Path) -> dict[str, object] | None:
    deadline = active_hook_validation_deadline()
    timeout = _TIMEOUT_SECONDS
    if deadline is not None:
        # The resident gets only what is left of the caller's budget; a spent
        # budget leaves the installation unverified.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        timeout = min(_TIMEOUT_SECONDS, remaining)
    try:
        response = _resident_request(
            operation="codex_hook_manifest_verify",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout,
            required_feature=CODEX_HOOK_MANIFEST_VERIFY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        return None
    return _payload(response, wire, home, failure_reason="native_codex_hook_manifest_verify_binding")


def _unavailable_state() -> dict[str, object]:
    return {
        "event_matches": dict.fromkeys(MANAGED_CODEX_HOOK_EVENTS, False),
        "foreign_hook_entries_present": False,
        "foreign_hook_group_count": 0,
        "integrity_message": _UNAVAILABLE_MESSAGE,
        "integrity_reason": _UNAVAILABLE_REASON,
        "integrity_status": "tampered",
        "manifest_schema_version": None,
        "manifest_package_version": None,
        "manifest_generated_at": None,
        "bridge_sha256": None,
        "interpreter_sha256": None,
    }


__all__ = ["CODEX_HOOK_MANIFEST_VERIFY_FEATURE", "native_codex_hook_manifest_verify"]
