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
"""

from __future__ import annotations

import math
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

HOOK_ADAPTER_FEATURE = "hook-adapter-v1"
_REQUEST_SCHEMA = "guard-hook-adapter-request.v1"
_RESULT_SCHEMA = "guard-hook-adapter-result.v1"
_RESIDENT_CODE = re.compile(r"^native_hook_adapter_[a-z_]{1,64}$")
_UNAVAILABLE = "native_hook_adapter_unavailable"
_INVALID = "native_hook_adapter_payload_invalid"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_ELIDE_STRING_BYTES = 256 * 1024
# Keys the envelope redacts wholesale; their values never need to cross the wire.
_ELIDABLE_KEYS = frozenset({"content", "output", "stdout", "stderr", "tool_response"})
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


class _UnrepresentableError(ValueError):
    pass


class _Wire:
    """Tags a payload for the wire, eliding or sentinel-swapping oversize values."""

    def __init__(self, mode: str) -> None:
        self.mode = mode  # "envelope": redact elidable values; "prepare": restore after
        self.nonce = uuid4().hex
        self.restore: dict[str, object] = {}

    def _sentinel(self, value: object) -> str:
        token = f"\x01guard-elided:{self.nonce}:{len(self.restore)}"
        self.restore[token] = value
        return token

    def tag(self, value: object, *, key: str | None = None, depth: int = 0) -> object:
        if depth > 30:
            raise _UnrepresentableError("depth")
        if key in _ELIDABLE_KEYS and (isinstance(value, (Mapping, list, tuple)) or self._oversize(value)):
            return "[redacted]" if self.mode == "envelope" else self._sentinel(value)
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise _UnrepresentableError("float")
            return value
        if isinstance(value, str):
            return self._tag_string(value)
        if isinstance(value, Mapping):
            tagged: list[object] = ["d"]
            for child_key, child in value.items():
                if not isinstance(child_key, str):
                    raise _UnrepresentableError("key")
                tagged.extend((self._tag_string(child_key), self.tag(child, key=child_key, depth=depth + 1)))
            return tagged
        if isinstance(value, (list, tuple)):
            return ["l", *(self.tag(item, depth=depth + 1) for item in value)]
        raise _UnrepresentableError(type(value).__name__)

    @staticmethod
    def _oversize(value: object) -> bool:
        if not isinstance(value, str) or len(value) <= _ELIDE_STRING_BYTES // 4:
            return False
        return _utf8_len(value) > _ELIDE_STRING_BYTES

    def _tag_string(self, value: str) -> str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise _UnrepresentableError("surrogate") from None
        if self.mode == "prepare" and self._oversize(value):
            return self._sentinel(value)
        return value

    def untag(self, value: object) -> object:
        if isinstance(value, list):
            if not value or value[0] not in ("d", "l"):
                raise _UnrepresentableError("tag")
            if value[0] == "l":
                return [self.untag(item) for item in value[1:]]
            body = value[1:]
            if len(body) % 2 or any(not isinstance(body[i], str) for i in range(0, len(body), 2)):
                raise _UnrepresentableError("dict")
            return {body[i]: self.untag(body[i + 1]) for i in range(0, len(body), 2)}
        if isinstance(value, str) and value in self.restore:
            return self.restore[value]
        return value


def _utf8_len(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise _UnrepresentableError("surrogate") from None


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


def _call(
    query: dict[str, object],
    *,
    guard_home: Path | str | None,
    deadline: float | None,
    wire: _Wire,
    shape: str,
) -> object:
    try:
        home = _resolve_digest_home(Path(guard_home) if guard_home is not None else None)
    except (OSError, RuntimeError, ValueError):
        raise NativeHookAdapterError("native_hook_adapter_home_unbound") from None
    timeout = _TIMEOUT_SECONDS
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise NativeHookAdapterError("native_hook_adapter_deadline_expired")
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-adapter-{uuid4().hex}",
        "query": query,
    }
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
        timeout_seconds=timeout,
        required_feature=HOOK_ADAPTER_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
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
        decoded = wire.untag(payload) if shape in {"prepare", "envelope"} else payload
    except _UnrepresentableError:
        raise NativeHookAdapterError(_INVALID) from None
    return decoded


def _raise_rejection(code: object, payload: object, query: Mapping[str, object]) -> None:
    if code == "native_hook_adapter_cline_payload" and isinstance(payload, dict) and set(payload) == {"message"}:
        message = payload["message"]
        if isinstance(message, str):
            raise ClinePayloadError(message)
    if code == "native_hook_adapter_unsupported_harness" and isinstance(payload, dict) and set(payload) == {"harness"}:
        harness = payload["harness"]
        if isinstance(harness, str) and harness == query.get("harness"):
            raise ValueError(f"Unsupported Guard harness for action normalization: {harness}")
    reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
    raise NativeHookAdapterError(reason)


def native_prepare_payload(
    harness: str,
    payload: Mapping[str, object],
    *,
    guard_home: Path | str | None = None,
) -> dict[str, object]:
    """Return the resident's prepared copy of one harness hook payload."""

    wire = _Wire("prepare")
    try:
        tagged = wire.tag(payload)
    except _UnrepresentableError:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
    query = {
        "kind": "prepare_payload",
        "harness": harness,
        "payload": tagged,
        "devin_project_dir": os.environ.get("DEVIN_PROJECT_DIR") or None,
    }
    result = _call(query, guard_home=guard_home, deadline=None, wire=wire, shape="prepare")
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

    wire = _Wire("envelope")
    try:
        tagged = wire.tag(payload)
    except _UnrepresentableError:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
    query = {
        "kind": "action_envelope",
        "harness": harness,
        "event_name": event_name,
        "payload": tagged,
        "workspace": _optional_text(workspace),
        "home_dir": _optional_text(home_dir),
        "devin_project_dir": os.environ.get("DEVIN_PROJECT_DIR") or None,
        "path_env": os.environ.get("PATH") or None,
        "host": _host_facts(),
    }
    result = _call(query, guard_home=guard_home, deadline=deadline, wire=wire, shape="envelope")
    if not isinstance(result, dict) or set(result) != _ENVELOPE_KEYS:
        raise NativeHookAdapterError(_INVALID)
    return result


def native_command_detail(text: str, *, home_dir: Path | str | None, guard_home: Path | str | None = None) -> str:
    """Return the redacted command text (secrets and absolute-path mentions)."""

    query = {"kind": "command_detail", "text": text, "home_dir": _optional_text(home_dir), "host": _host_facts()}
    result = _call(query, guard_home=guard_home, deadline=None, wire=_Wire("plain"), shape="plain")
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
    wire = _Wire("envelope")
    try:
        tagged_input = wire.tag(tool_input)
    except _UnrepresentableError:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
    name = tool_name if isinstance(tool_name, str) else None
    query = {"kind": "command_text", "tool_name": name, "tool_input": tagged_input}
    result = _call(query, guard_home=guard_home, deadline=None, wire=wire, shape="plain")
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

    query = {
        "kind": "workspace_label",
        "workspace": str(workspace),
        "home_dir": _optional_text(home_dir),
        "host": _host_facts(),
    }
    result = _call(query, guard_home=guard_home, deadline=None, wire=_Wire("plain"), shape="plain")
    if not isinstance(result, dict) or set(result) != {"text"} or not isinstance(result["text"], str):
        raise NativeHookAdapterError(_INVALID)
    return result["text"]


def native_apply_patch_paths(tool_input: object, *, guard_home: Path | str | None = None) -> tuple[str, ...]:
    """Return the target paths named by an apply-patch tool input."""

    if not isinstance(tool_input, Mapping):
        return ()
    wire = _Wire("envelope")
    try:
        tagged = wire.tag(tool_input)
    except _UnrepresentableError:
        raise NativeHookAdapterError("native_hook_adapter_request_invalid") from None
    query = {"kind": "apply_patch_paths", "tool_input": tagged}
    result = _call(query, guard_home=guard_home, deadline=None, wire=wire, shape="plain")
    paths = result.get("paths") if isinstance(result, dict) and set(result) == {"paths"} else None
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise NativeHookAdapterError(_INVALID)
    return tuple(paths)


__all__ = [
    "HOOK_ADAPTER_FEATURE",
    "ClinePayloadError",
    "NativeHookAdapterError",
    "native_action_envelope",
    "native_apply_patch_paths",
    "native_command_detail",
    "native_command_text",
    "native_prepare_payload",
    "native_workspace_label",
]
