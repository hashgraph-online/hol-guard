"""Bound native transport for restricted execution preparation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_request_context import NativeRequestContextFailure, _call
from .runtime.restricted_pytest_model import (
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
)

_REASONS = {
    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_INVALID_WORKSPACE_REASON_CODE,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
}


def _wire(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value.expanduser().absolute())
    if isinstance(value, Mapping):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_wire(item) for item in value]
    return value


def restricted_native(operation: str, fields: Mapping[str, Any], expected: type) -> Any:
    # Lexical anchoring preserves the caller's cwd/home; the resident owns
    # existence, symlink, workspace and executable admission.
    inputs = dict(fields)
    if operation == "prepare" and inputs.get("command") and inputs["command"][0].startswith("~"):
        inputs["command"] = [str(Path(inputs["command"][0]).expanduser()), *inputs["command"][1:]]
    if operation == "environment":
        source = dict(inputs["source"])
        if "PYTHONPATH" in source:
            source["PYTHONPATH"] = os.pathsep.join(
                str(Path(item).expanduser()) if item else "" for item in source["PYTHONPATH"].split(os.pathsep)
            )
        if "VIRTUAL_ENV" in source:
            source["VIRTUAL_ENV"] = str(Path(source["VIRTUAL_ENV"]).expanduser())
        inputs["source"] = source
    search_path = os.pathsep.join(
        str(Path(item).absolute()) for item in os.environ.get("PATH", os.defpath).split(os.pathsep)
    )
    try:
        payload = _call(
            {
                "kind": "restricted_pytest",
                "body": {"operation": operation, "input": {**_wire(inputs), "search_path": search_path}},
            },
            source="direct_command",
            guard_home=None,
            budget_ms=9_000,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        payload = NativeRequestContextFailure("native_request_context_transport_failed")
    if isinstance(payload, dict):
        if set(payload) == {"reason_code", "message"}:
            reason, message = payload["reason_code"], payload["message"]
            if isinstance(reason, str) and reason in _REASONS and isinstance(message, str) and len(message) <= 4096:
                raise RestrictedPytestError(reason, message)
        if set(payload) == {"value"}:
            value = payload["value"]
            if type(value) is expected:
                if (expected is list and not all(isinstance(item, str) for item in value)) or (
                    expected is dict and not all(isinstance(key, str) for key in value)
                ):
                    pass
                else:
                    return value
    code = payload.code if isinstance(payload, NativeRequestContextFailure) else "invalid_reply"
    raise RestrictedPytestError(
        PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
        f"Native restricted execution preparation is unavailable ({code}); execution was not started.",
    )
