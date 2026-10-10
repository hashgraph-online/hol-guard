"""Per-harness hook payload handling answered by the native runtime.

Python forwards the raw harness hook payload plus the host facts the resident
may not read (home, cwd, ``PATH``); the resident prepares the payload, builds the
typed action envelope, and derives command text views. There is no Python
implementation behind this module: anything but a bound, strictly decoded ``ok``
answer raises ``NativeHookAdapterError`` (infrastructure) or the same
``ValueError`` family the in-process adapters raised (payload rejection).

Payload values travel in an order-preserving tagged form (``["d", key, value,
...]`` objects, ``["l", item, ...]`` lists, raw scalars) because the envelope
depends on key order.

Size policy. The resident always sees the complete payload: nothing it parses
is ever replaced, shortened, or elided. A request that cannot fit the transport
cap fails closed with ``native_hook_adapter_request_too_large``; an answer that
cannot fit the response cap fails closed with the resident's
``native_hook_adapter_response_too_large``. The one exception is a pure
pass-through blob: when an ``action_envelope`` request is over the cap, root
output blobs the envelope redacts wholesale are replaced by the string the
resident would have produced for them. Oversize strings the resident echoes
byte-for-byte come back as ``["r", sha256]`` references into the request, so
large payloads round-trip without raising either cap.
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from uuid import uuid4

from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    bind_context_digest_home,
    ensure_resident_prerequisite,
    reset_context_digest_home,
)
from .native_execution import _resident_request
from .native_hook_adapter_wire import _Tagger, _TooLargeError, _UnrepresentableError

HOOK_ADAPTER_FEATURE = "hook-adapter-v1"
_REQUEST_SCHEMA = "guard-hook-adapter-request.v1"
_RESULT_SCHEMA = "guard-hook-adapter-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_adapter_[a-z_]{1,64}$")
_UNAVAILABLE = "native_hook_adapter_unavailable"
_INVALID = "native_hook_adapter_payload_invalid"
_DEADLINE = "native_hook_adapter_deadline_expired"
_REQUEST_TOO_LARGE = "native_hook_adapter_request_too_large"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# Transport framing around ``request`` (operation name, deadline budget).
_ENVELOPE_OVERHEAD_BYTES = 256
_MAX_PLAIN_BYTES = 1024 * 1024
_MAX_PLAIN_CHARS = _MAX_PLAIN_BYTES // 4
# Root keys the envelope redacts wholesale (``[redacted]``) and never parses.
_PASS_THROUGH_ROOT_KEYS = frozenset({"output", "stderr", "stdout", "tool_response"})
_REDACTED = "[redacted]"

_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "action_id",
        "harness",
        "event_name",
        "action_type",
        "workspace",
        "workspace_hash",
        "tool_name",
        "command",
        "prompt_excerpt",
        "prompt_text",
        "target_paths",
        "network_hosts",
        "mcp_server",
        "mcp_tool",
        "package_manager",
        "package_name",
        "command_category",
        "package_intent_kind",
        "package_targets",
        "pre_execution_result",
        "script_name",
        "raw_payload_redacted",
    }
)


class NativeHookAdapterError(RuntimeError):
    """No authoritative adapter answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ClinePayloadError(ValueError):
    """The Cline hook payload is not a supported hook event."""


_Built = tuple[dict[str, object], _Tagger]
_Builder = Callable[[bool], _Built | None]
_MEMO: ContextVar[dict[str, object] | None] = ContextVar("native_hook_adapter_memo", default=None)


@contextmanager
def hook_adapter_memo(guard_home: Path | str | None = None) -> Iterator[None]:
    """Answer repeated identical queries once within one hook invocation.

    Every query is a pure function of its request, so a hook that derives the
    same view several times pays one resident round trip, not one per call.
    Failures are never remembered, and nothing outlives the ``with`` block.

    ``guard_home`` binds the hook's own guard home for ambient adapter calls
    (presentation helpers pass no home), so they reach the resident the hook
    was routed to rather than whichever home the process happens to default to.
    """

    if _MEMO.get() is not None:
        yield
        return
    token = _MEMO.set({})
    home_token = bind_context_digest_home(Path(guard_home), remember=False) if guard_home is not None else None
    try:
        yield
    finally:
        if home_token is not None:
            reset_context_digest_home(home_token)
        _MEMO.reset(token)


def _host_facts() -> dict[str, object]:
    """The process facts Rust must not observe itself (never read from the resident)."""

    tilde_home = os.path.expanduser("~")
    resolved_home = None if tilde_home.startswith("~") else tilde_home
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        cwd = None
    return {"tilde_home": resolved_home, "default_home": resolved_home, "cwd": cwd}


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _request_bytes(request: Mapping[str, object]) -> int:
    try:
        return len(json.dumps(request).encode("utf-8")) + _ENVELOPE_OVERHEAD_BYTES
    except (TypeError, ValueError):
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None


def _remaining_seconds(deadline: float | None) -> float:
    if deadline is None:
        return _TIMEOUT_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativeHookAdapterError(_DEADLINE)
    return min(_TIMEOUT_SECONDS, remaining)


def _build_request(build: _Builder) -> tuple[dict[str, object], _Tagger]:
    """Build the request, shrinking pass-through blobs only when it is over the cap."""

    built = build(False)
    if built is None:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid")
    query, tagger = built
    request: dict[str, object] = {"schema": _REQUEST_SCHEMA, "request_id": "", "query": query}
    if _request_bytes(request) <= _MAX_REQUEST_BYTES:
        return request, tagger
    shrunk = build(True)
    if shrunk is None:
        raise NativeHookAdapterError(_REQUEST_TOO_LARGE)
    query, tagger = shrunk
    request = {"schema": _REQUEST_SCHEMA, "request_id": "", "query": query}
    if _request_bytes(request) > _MAX_REQUEST_BYTES:
        raise NativeHookAdapterError(_REQUEST_TOO_LARGE)
    return request, tagger


def _call(
    build: _Builder,
    *,
    guard_home: Path | str | None,
    deadline: float | None,
    shape: str,
) -> object:
    try:
        home = _resolve_digest_home(Path(guard_home) if guard_home is not None else None)
    except (OSError, RuntimeError, ValueError):
        raise NativeHookAdapterError("native_hook_adapter_home_unbound") from None
    _remaining_seconds(deadline)
    request, tagger = _build_request(build)
    query = request["query"]
    memo = _MEMO.get()
    memo_key: str | None = None
    if memo is not None:
        try:
            memo_key = _canonical_request_sha256({"shape": shape, "query": query})
        except (TypeError, ValueError):
            raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
        if memo_key in memo:
            return copy.deepcopy(memo[memo_key])
    request["request_id"] = f"hook-adapter-{uuid4().hex}"
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
    if not ensure_resident_prerequisite(home):
        raise NativeHookAdapterError(_UNAVAILABLE)
    response = _resident_request(
        operation="hook_adapter",
        request=request,
        guard_home=home,
        timeout_seconds=_remaining_seconds(deadline),
        required_feature=HOOK_ADAPTER_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
    if deadline is not None and time.monotonic() > deadline:
        # A late answer is as unusable as none: the caller's budget is spent.
        raise NativeHookAdapterError(_DEADLINE)
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise NativeHookAdapterError(_UNAVAILABLE)
    status, code, payload = response.get("status"), response.get("code"), response.get("payload")
    if status == "error":
        _raise_rejection(code, payload, query)
    if status != "ok" or code != "ok" or payload is None:
        raise NativeHookAdapterError(_INVALID)
    try:
        if shape in {"prepare", "envelope"}:
            decoded = tagger.untag(payload)
        elif shape == "text" and isinstance(payload, dict) and set(payload) == {"text"}:
            decoded = {"text": tagger.untag(payload["text"])}
        else:
            decoded = payload
    except _UnrepresentableError:
        raise NativeHookAdapterError(_INVALID) from None
    if memo is not None and memo_key is not None:
        memo[memo_key] = copy.deepcopy(decoded)
    return decoded


def _raise_rejection(code: object, payload: object, query: object) -> None:
    if code == "native_hook_adapter_cline_payload" and isinstance(payload, dict) and set(payload) == {"message"}:
        message = payload["message"]
        if isinstance(message, str):
            raise ClinePayloadError(message)
    if code == "native_hook_adapter_unsupported_harness" and isinstance(payload, dict) and set(payload) == {"harness"}:
        harness = payload["harness"]
        if isinstance(harness, str) and isinstance(query, Mapping) and harness == query.get("harness"):
            raise ValueError(f"Unsupported Guard harness for action normalization: {harness}")
    reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
    raise NativeHookAdapterError(reason)


def _tagged(tagger: _Tagger, value: object) -> object:
    try:
        return tagger.tag(value)
    except _TooLargeError:
        raise NativeHookAdapterError(_REQUEST_TOO_LARGE) from None
    except _UnrepresentableError:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None


def _without_pass_through_blobs(payload: Mapping[str, object]) -> dict[str, object] | None:
    """The payload with root output blobs replaced by what the envelope emits for them."""

    if not any(key in payload for key in _PASS_THROUGH_ROOT_KEYS):
        return None
    return {key: _REDACTED if key in _PASS_THROUGH_ROOT_KEYS else value for key, value in payload.items()}


def native_prepare_payload(
    harness: str,
    payload: Mapping[str, object],
    *,
    guard_home: Path | str | None = None,
) -> dict[str, object]:
    """Return the resident's prepared copy of one harness hook payload."""

    def build(shrunk: bool) -> _Built | None:
        if shrunk:
            return None  # the prepared copy echoes the payload; nothing is safely elidable
        tagger = _Tagger()
        query: dict[str, object] = {
            "kind": "prepare_payload",
            "harness": harness,
            "payload": _tagged(tagger, payload),
            "devin_project_dir": os.environ.get("DEVIN_PROJECT_DIR") or None,
        }
        return query, tagger

    result = _call(build, guard_home=guard_home, deadline=None, shape="prepare")
    if not isinstance(result, dict):
        raise NativeHookAdapterError(_INVALID)
    return result


def native_action_envelope(
    harness: str,
    event_name: str,
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None,
    home_dir: Path | str | None,
    guard_home: Path | str | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Return the resident's typed action envelope (``GuardActionEnvelope.to_dict`` shape)."""

    def build(shrunk: bool) -> _Built | None:
        source: Mapping[str, object] | None = _without_pass_through_blobs(payload) if shrunk else payload
        if source is None:
            return None
        tagger = _Tagger()
        query: dict[str, object] = {
            "kind": "action_envelope",
            "harness": harness,
            "event_name": event_name,
            "payload": _tagged(tagger, source),
            "workspace": _optional_text(workspace),
            "home_dir": _optional_text(home_dir),
            "devin_project_dir": os.environ.get("DEVIN_PROJECT_DIR") or None,
            "path_env": os.environ.get("PATH") or None,
            "host": _host_facts(),
        }
        return query, tagger

    result = _call(build, guard_home=guard_home, deadline=deadline, shape="envelope")
    if not isinstance(result, dict) or set(result) != _ENVELOPE_KEYS:
        raise NativeHookAdapterError(_INVALID)
    return result


def _plain(query: dict[str, object]) -> _Builder:
    # Typed string fields cannot be chunked; one that exceeds the resident's
    # string slot is refused here with the explicit size code, never cut.
    for field in query.values():
        if (
            isinstance(field, str)
            and len(field) > _MAX_PLAIN_CHARS
            and len(field.encode("utf-8", "replace")) > _MAX_PLAIN_BYTES
        ):
            raise NativeHookAdapterError(_REQUEST_TOO_LARGE)

    def build(shrunk: bool) -> _Built | None:
        return None if shrunk else (query, _Tagger())

    return build


def native_command_detail(text: str, *, home_dir: Path | str | None, guard_home: Path | str | None = None) -> str:
    """Return the redacted command text (secrets and absolute-path mentions)."""

    query: dict[str, object] = {
        "kind": "command_detail",
        "text": text,
        "home_dir": _optional_text(home_dir),
        "host": _host_facts(),
    }
    result = _call(_plain(query), guard_home=guard_home, deadline=None, shape="plain")
    if not isinstance(result, dict) or set(result) != {"text"} or not isinstance(result["text"], str):
        raise NativeHookAdapterError(_INVALID)
    return result["text"]


def native_command_text(
    tool_name: object,
    tool_input: object,
    *,
    guard_home: Path | str | None = None,
) -> str | None:
    """Return the command text a tool payload carries, or ``None``."""

    if not isinstance(tool_input, Mapping):
        return None
    name = tool_name if isinstance(tool_name, str) else None

    def build(shrunk: bool) -> _Built | None:
        if shrunk:
            return None
        tagger = _Tagger()
        query: dict[str, object] = {
            "kind": "command_text",
            "tool_name": name,
            "tool_input": _tagged(tagger, tool_input),
        }
        return query, tagger

    result = _call(build, guard_home=guard_home, deadline=None, shape="text")
    if not isinstance(result, dict) or set(result) != {"text"}:
        raise NativeHookAdapterError(_INVALID)
    text = result["text"]
    if text is not None and not isinstance(text, str):
        raise NativeHookAdapterError(_INVALID)
    return text


def native_workspace_label(
    workspace: Path | str,
    *,
    home_dir: Path | str | None,
    guard_home: Path | str | None = None,
) -> str:
    """Return the home-relative, path-safe label for ``workspace``."""

    query: dict[str, object] = {
        "kind": "workspace_label",
        "workspace": str(workspace),
        "home_dir": _optional_text(home_dir),
        "host": _host_facts(),
    }
    result = _call(_plain(query), guard_home=guard_home, deadline=None, shape="plain")
    if not isinstance(result, dict) or set(result) != {"text"} or not isinstance(result["text"], str):
        raise NativeHookAdapterError(_INVALID)
    return result["text"]


def native_apply_patch_paths(tool_input: object, *, guard_home: Path | str | None = None) -> tuple[str, ...]:
    """Return the target paths named by an apply-patch tool input."""

    if not isinstance(tool_input, Mapping):
        return ()

    def build(shrunk: bool) -> _Built | None:
        if shrunk:
            return None
        tagger = _Tagger()
        query: dict[str, object] = {"kind": "apply_patch_paths", "tool_input": _tagged(tagger, tool_input)}
        return query, tagger

    result = _call(build, guard_home=guard_home, deadline=None, shape="plain")
    paths = result.get("paths") if isinstance(result, dict) and set(result) == {"paths"} else None
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise NativeHookAdapterError(_INVALID)
    return tuple(paths)


__all__ = [
    "HOOK_ADAPTER_FEATURE",
    "ClinePayloadError",
    "NativeHookAdapterError",
    "hook_adapter_memo",
    "native_action_envelope",
    "native_apply_patch_paths",
    "native_command_detail",
    "native_command_text",
    "native_prepare_payload",
    "native_workspace_label",
]
