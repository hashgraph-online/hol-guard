"""Observe existing native-edge return values inside a private fixture.

The wrappers call each original operation exactly once. They never inspect the
runtime again, decode a response again, refresh health, retry, or change a
deadline. Only bounded facts about values already computed by production cross
the fixture control pipe; request bytes and response bodies are never retained.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from typing import Any
from unittest.mock import patch

from codex_plugin_scanner.guard.native_approval_errors import (
    NATIVE_APPROVAL_ERROR_CODES,
    NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES,
)

_TRACE: ContextVar[dict[str, object] | None] = ContextVar("qualification_native_edge_stages", default=None)
_LOCK = threading.RLock()
_users = 0
_patches: ExitStack | None = None
_CODES = (
    NATIVE_APPROVAL_ERROR_CODES
    | NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
    | {
        "native_hook_edge_unavailable",
        "native_hook_edge_invalid_response",
        "ready",
        "native_ready",
    }
)
_MAX_CALLS = 4


def _code(value: object) -> dict[str, object]:
    if value is None:
        return {"state": "absent"}
    if type(value) is not str:
        return {"state": "invalid_type"}
    known = len(value) <= 128 and value in _CODES
    result: dict[str, object] = {
        "state": "known" if known else "unlisted",
        "digest": hashlib.sha256(value[:128].encode("utf-8", errors="replace")).hexdigest(),
        "digest_complete": len(value) <= 128,
    }
    if known:
        result["value"] = value
    return result


def _status(value: Any, _args: tuple[Any, ...], _kwargs: dict[str, Any]) -> dict[str, object]:
    capabilities = value.capabilities
    features = capabilities.features if capabilities is not None else ()
    return {
        "mode": value.mode if value.mode in {"auto", "force", "off", "shadow"} else "unclassified",
        "available": value.available is True,
        "compatible": value.compatible is True,
        "identity_present": value.identity is not None,
        "capabilities_present": capabilities is not None,
        "hook_envelope_feature": "hook-envelope-v2" in features,
        "resident_client_feature": "native-resident-client-v1" in features,
        "pre_tool_feature": "pre-tool-generic-authority-v1" in features,
        **{"reason_" + key: item for key, item in _code(value.reason).items()},
    }


def _bytes(value: object, _args: tuple[Any, ...], _kwargs: dict[str, Any]) -> dict[str, object]:
    return {
        "returned_bytes": type(value) is bytes,
        "returned_none": value is None,
        "byte_count": min(len(value), 6 * 1024 * 1024 + 1) if type(value) is bytes else None,
    }


def _decode(value: object, args: tuple[Any, ...], _kwargs: dict[str, Any]) -> dict[str, object]:
    payload = args[0] if args else None
    result: dict[str, object] = {"accepted": type(value) is dict, "input_object": type(payload) is dict}
    if type(payload) is dict:
        schema = payload.get("schema")
        result["edge_schema"] = schema == "guard-hook-edge-result.v2"
        result["error_present"] = "error" in payload
        result["receipt_present"] = type(payload.get("receipt")) is dict
        result.update(("error_" + key, item) for key, item in _code(payload.get("error")).items())
    return result


def _receipt(value: object, _args: tuple[Any, ...], _kwargs: dict[str, Any]) -> dict[str, object]:
    return {"matched": value is True}


def _failure(_value: object, _args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, object]:
    return {"reason_" + key: item for key, item in _code(kwargs.get("reason")).items()}


def _wrapper(
    original: Callable[..., Any], name: str, summarize: Callable[..., dict[str, object]]
) -> Callable[..., Any]:
    def observed(*args: Any, **kwargs: Any) -> Any:
        # Production exceptions propagate unchanged. There is no diagnostic
        # operation before the actual call or on its exception path.
        value = original(*args, **kwargs)
        trace = _TRACE.get()
        if trace is not None:
            try:
                previous = trace.get(name)
                calls = previous.get("calls", 0) if type(previous) is dict else 0
                if type(calls) is int and calls < _MAX_CALLS:
                    trace[name] = {"calls": calls + 1, **summarize(value, args, kwargs)}
                else:
                    trace["stage_count_limit_reached"] = True
            except Exception:
                trace["collection_failed"] = True
        return value

    return observed


@contextmanager
def capture_native_edge_stages() -> Iterator[None]:
    """Install once per fixture lifetime; concurrent workers keep own traces."""
    global _users, _patches
    from codex_plugin_scanner.guard import native_hook_edge

    with _LOCK:
        if _users == 0:
            stack = ExitStack()
            try:
                for name, label, summarize in (
                    ("native_runtime_status", "runtime_status", _status),
                    ("_encode_hook_envelope", "envelope", _bytes),
                    ("native_resident_client_request", "client", _bytes),
                    ("_decode_edge", "decoder", _decode),
                    ("receipt_matches_edge", "receipt", _receipt),
                    ("native_record_resident_failure", "resident_failure", _failure),
                ):
                    original = getattr(native_hook_edge, name)
                    stack.enter_context(patch.object(native_hook_edge, name, _wrapper(original, label, summarize)))
            except BaseException:
                stack.close()
                raise
            _patches = stack
        _users += 1
    try:
        yield
    finally:
        with _LOCK:
            _users -= 1
            if _users == 0:
                assert _patches is not None
                _patches.close()
                _patches = None


@contextmanager
def collect_native_edge_stages() -> Iterator[dict[str, object]]:
    """Associate existing stage returns with this worker operation only."""
    trace: dict[str, object] = {"wrappers_installed": _users > 0}
    token = _TRACE.set(trace)
    try:
        yield trace
    finally:
        _TRACE.reset(token)
