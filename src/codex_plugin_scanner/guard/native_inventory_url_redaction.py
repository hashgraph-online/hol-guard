"""Typed client for the native inventory redaction; no Python composition."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "inventory-url-redaction-v1"
_REQUEST_SCHEMA = "guard-inventory-url-redaction-request.v1"
_RESULT_SCHEMA = "guard-inventory-url-redaction-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "answers"})
_MAX_TASKS = 4096
# The resident accepts a canonical request up to 4 MiB; the wire envelope
# carries the same material plus framing, so leave room for both -- and no more
# than the transport will frame. Twice the op's bound is past that ceiling, so
# a request between the two was refused as a broken runtime rather than as one
# that asked for too much.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_WIRE_BYTES = 6 * 1024 * 1024 - 64 * 1024
# A prefetch chunk stays well inside the request budget even when every
# character of a value needs a JSON escape.
_MAX_CHUNK_TEXT_BYTES = _MAX_REQUEST_BYTES // 8
_HOST_CLASSES = frozenset({"none", "local_loopback", "local_private", "remote_public"})
# Tasks whose answer is the one redacted string under the ``value`` field.
_VALUE_KINDS = frozenset({"redact_url", "redact_command_value", "redact_known_path"})
# Tasks whose answer depends on the caller's home, workspace and working
# directories as well as on the value.
_ROOTED_KINDS = frozenset({"redact_command_value", "redact_known_path"})

_TaskKey = tuple[str, object]
# Answers already read in the current export pass, keyed by task. ``None``
# outside a pass, where every lookup is its own request.
_PASS_ANSWERS: ContextVar[dict[_TaskKey, Any] | None] = ContextVar("inventory_url_redaction_pass", default=None)


class NativeInventoryUrlRedactionError(RuntimeError):
    """The native owner could not supply a complete, request-bound redaction."""


@contextmanager
def redaction_pass() -> Iterator[None]:
    """Remember every answer read until the pass ends.

    One export repeats the same URLs across items, tools and commands; inside a
    pass each distinct value costs at most one resident answer, and ``prefetch``
    can collect them all into batched requests up front.
    """

    if _PASS_ANSWERS.get() is not None:
        yield
        return
    token = _PASS_ANSWERS.set({})
    try:
        yield
    finally:
        _PASS_ANSWERS.reset(token)


def prefetch(
    urls: Iterable[str],
    hosts: Iterable[str] = (),
    *,
    paths: Iterable[str] = (),
    commands: Iterable[str] = (),
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    guard_home: Path | None = None,
) -> None:
    """Answer every redaction an export will ask for, in batched requests.

    A snapshot redacts far more paths and command strings than URLs: every
    string in an artifact's metadata is a path until it proves to be a URL.
    Left to the per-value calls below, each distinct one would be its own
    round trip, so they are collected here with the URLs and asked together.

    ``paths`` and ``commands`` need the roots their answers depend on, and are
    ignored without a ``home_dir``. Outside a pass there is nowhere to keep
    the answers, so this does nothing.
    """

    cache = _PASS_ANSWERS.get()
    if cache is None:
        return
    tasks: list[dict[str, object]] = []
    seen: set[_TaskKey] = set()

    def collect(task: dict[str, object]) -> None:
        key = _task_key(task)
        if key in cache or key in seen:
            return
        seen.add(key)
        tasks.append(task)

    for kind, values in (("redact_url", urls), ("classify_endpoint_host", hosts)):
        for value in values:
            collect({"kind": kind, "value": value})
    if home_dir is not None:
        for kind, values in (("redact_known_path", paths), ("redact_command_value", commands)):
            for value in values:
                collect(_rooted(kind, value, home_dir, workspace_dir))
    for chunk in _chunks(tasks):
        for task, answer in zip(chunk, _answers(chunk, guard_home=guard_home), strict=True):
            cache[_task_key(task)] = answer


def redact_url(value: str, *, guard_home: Path | None = None) -> str:
    """Return the exported form of one URL."""

    return _answer_for({"kind": "redact_url", "value": value}, guard_home=guard_home)


def redact_headers(header_names: list[str], *, guard_home: Path | None = None) -> dict[str, str]:
    """Return presence per header name, lowercased, in the order they were given."""

    return dict(_answer_for({"kind": "redact_headers", "header_names": header_names}, guard_home=guard_home))


def classify_endpoint_host(value: str | None, *, guard_home: Path | None = None) -> str:
    """Return where an endpoint points, decided without a network request."""

    return _answer_for({"kind": "classify_endpoint_host", "value": value}, guard_home=guard_home)


def redact_command_value(
    value: str,
    home_dir: Path,
    workspace_dir: Path | None,
    *,
    guard_home: Path | None = None,
) -> str:
    """Return the exported form of one command string."""

    return _answer_for(_rooted("redact_command_value", value, home_dir, workspace_dir), guard_home=guard_home)


def redact_known_path(
    value: str,
    home_dir: Path,
    workspace_dir: Path | None,
    *,
    guard_home: Path | None = None,
) -> str:
    """Return the exported form of one path."""

    return _answer_for(_rooted("redact_known_path", value, home_dir, workspace_dir), guard_home=guard_home)


def _rooted(kind: str, value: str, home_dir: Path, workspace_dir: Path | None) -> dict[str, object]:
    """Describe a task whose answer depends on the caller's directories.

    The resident resolves a relative path against its own process directory,
    which is not this one, so the working directory travels with the task
    rather than being left to whichever process answers it.
    """

    return {
        "kind": kind,
        "value": value,
        "home_dir": str(home_dir),
        "workspace_dir": None if workspace_dir is None else str(workspace_dir),
        "cwd": _cwd(),
    }


def _cwd() -> str:
    """The directory a relative value in the task is resolved against.

    ``os.getcwd()`` raises once the process's own directory has been deleted,
    and an export that reaches this for a value it never needed a root for
    would abort on its first metadata string. An absolute value does not need
    one, and a relative value whose root is gone is the unresolvable path the
    caller already exports as a bare file name, so the empty root travels and
    the resident answers with that same bare name.
    """

    try:
        return os.getcwd()
    except OSError:
        return ""


def _task_key(task: dict[str, object]) -> _TaskKey:
    kind = str(task["kind"])
    if kind == "redact_headers":
        names = task["header_names"]
        return kind, tuple(names) if isinstance(names, list) else names
    if kind in _ROOTED_KINDS:
        # Two identical strings redact differently under different roots, so
        # the roots are part of what the cached answer belongs to.
        return kind, (task["value"], task["home_dir"], task["workspace_dir"], task["cwd"])
    return kind, task["value"]


def _answer_for(task: dict[str, object], *, guard_home: Path | None) -> Any:
    cache = _PASS_ANSWERS.get()
    key = _task_key(task)
    if cache is not None and key in cache:
        return cache[key]
    answer = _answers([task], guard_home=guard_home)[0]
    if cache is not None:
        cache[key] = answer
    return answer


def _chunks(tasks: list[dict[str, object]]) -> Iterator[list[dict[str, object]]]:
    """Split tasks into requests that fit both the task and the size limit."""

    chunk: list[dict[str, object]] = []
    size = 0
    for task in tasks:
        value = task.get("value")
        cost = len(value.encode("utf-8")) if isinstance(value, str) else 0
        if chunk and (len(chunk) >= _MAX_TASKS or size + cost > _MAX_CHUNK_TEXT_BYTES):
            yield chunk
            chunk, size = [], 0
        chunk.append(task)
        size += cost
    if chunk:
        yield chunk


def _unusable() -> NativeInventoryUrlRedactionError:
    return NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid_result")


def _headers(answer: dict[str, Any]) -> dict[str, str]:
    """Read a header answer as the presence it reports per name."""

    pairs = answer.get("headers")
    if not isinstance(pairs, list):
        raise _unusable()
    redacted: dict[str, str] = {}
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise _unusable()
        name, presence = pair
        if not isinstance(name, str) or not isinstance(presence, str):
            raise _unusable()
        redacted[name] = presence
    return redacted


def _text(answer: dict[str, Any], field: str) -> str:
    """Read the one string a non-header answer carries."""

    value = answer.get(field)
    if not isinstance(value, str):
        raise _unusable()
    return value


def _answer(answer: object, task: dict[str, object]) -> Any:
    """Read the answer the resident gave for this task, or refuse the reply.

    The shape is checked before the reply counts as usable, so an answer the
    caller cannot read records the resident as failing rather than succeeding.
    """

    kind = task["kind"]
    if not isinstance(answer, dict) or answer.get("kind") != kind:
        raise _unusable()
    if kind == "redact_headers":
        return _headers(answer)
    if kind in _VALUE_KINDS:
        return _text(answer, "value")
    host_class = _text(answer, "host_class")
    # A class outside the contract would read as a safe endpoint downstream.
    if host_class not in _HOST_CLASSES:
        raise _unusable()
    return host_class


def _answers(
    tasks: list[dict[str, object]],
    *,
    guard_home: Path | None,
    timeout_seconds: float = 10.0,
) -> list[Any]:
    """Ask the resident for one redaction pass and verify it answers this request.

    The redaction is what keeps an operator's credentials and private hosts out
    of an exported inventory, so it has exactly one composition and the resident
    owns it. Every outcome other than a well-formed, request-bound ``ok`` reply
    raises ``NativeInventoryUrlRedactionError``; a caller must not fall back to
    a local redaction, which would be a second place an export can be declared
    safe.
    """

    if len(tasks) > _MAX_TASKS:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid")
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("inventory_url_redaction"),
        "tasks": tasks,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
        # The resident answers with the prefixed token, so bind against the same form.
        request_sha256 = "sha256:" + _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="inventory_url_redaction",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except NativeInventoryUrlRedactionError:
        raise
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        # A home that cannot be resolved raises a plain RuntimeError.
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable") from error
    if decoded is None:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    try:
        answers = _validated_answers(decoded, wire, request_sha256, tasks)
    except NativeInventoryUrlRedactionError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return answers


def _validated_answers(
    decoded: dict[str, Any],
    wire: dict[str, object],
    request_sha256: str,
    tasks: list[dict[str, object]],
) -> list[Any]:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok" or decoded.get("status") != "ok":
        raise _unusable()
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_request_mismatch")
    answers: Any = decoded.get("answers")
    # One answer per task, or the caller cannot tell which string it holds.
    if not isinstance(answers, list) or len(answers) != len(tasks):
        raise _unusable()
    return [_answer(answer, task) for answer, task in zip(answers, tasks, strict=True)]


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_inventory_url_redaction_result")
