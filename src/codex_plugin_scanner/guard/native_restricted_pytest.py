"""Bound native transport for restricted execution preparation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
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
    "node_test_restricted_invalid_command",
    "node_test_restricted_sandbox_unavailable",
    "vitest_restricted_invalid_command",
    "vitest_restricted_dependency_unavailable",
    "inline_eval_invalid_command",
    "linux_mapping_unavailable",
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


def restricted_native(operation: str, fields: Mapping[str, Any], expected: type | tuple[type, ...]) -> Any:
    # Lexical anchoring preserves the caller's cwd/home; the resident owns
    # existence, symlink, workspace and executable admission.
    inputs = dict(fields)
    if operation in {"prepare_node", "prepare_vitest", "prepare_inline", "approved_node"}:
        inputs["home"] = Path.home()
    if operation.startswith("prepare") and inputs.get("command") and inputs["command"][0].startswith("~"):
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
    wire_input = {**_wire(inputs), "search_path": search_path}
    if operation == "mapping_evidence":
        raw = json.dumps(wire_input, separators=(",", ":")).encode()
        if len(raw) > 256 * 1024 * 1024:
            raise RestrictedPytestError(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Mapping index exceeds its wire budget."
            )
        try:
            with tempfile.TemporaryDirectory(prefix="hol-guard-mapping-") as directory:
                snapshot = Path(directory).resolve() / "mapping-index.json"
                descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
                envelope = _request(
                    operation,
                    {
                        "mapping_snapshot": str(snapshot),
                        "decoded_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    },
                    dict,
                )
                if (
                    set(envelope) != {"decoded_bytes", "sha256"}
                    or type(envelope["decoded_bytes"]) is not int
                    or not 0 <= envelope["decoded_bytes"] <= 32 * 1024 * 1024
                ):
                    raise ValueError("Invalid mapping result envelope.")
                descriptor = os.open(
                    snapshot.with_name("mapping-result.json"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                )
                with os.fdopen(descriptor, "rb") as stream:
                    status = os.fstat(stream.fileno())
                    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid() or status.st_mode & 0o077:
                        raise ValueError("Invalid mapping result snapshot.")
                    raw = stream.read(envelope["decoded_bytes"] + 1)
                if len(raw) != envelope["decoded_bytes"] or hashlib.sha256(raw).hexdigest() != envelope["sha256"]:
                    raise ValueError("Invalid mapping result envelope.")
                value = json.loads(raw)
                if type(value) not in (expected if isinstance(expected, tuple) else (expected,)):
                    raise ValueError("Invalid mapping result reply.")
                return value
        except (OSError, ValueError, TypeError) as error:
            raise RestrictedPytestError(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Mapping snapshot transport is unavailable."
            ) from error
    return _request(operation, wire_input, expected)


def _request(operation: str, wire_input: Mapping[str, Any], expected: type | tuple[type, ...]) -> Any:
    try:
        payload = _call(
            {
                "kind": "restricted_pytest",
                "body": {"operation": operation, "input": wire_input},
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
            if type(value) in (expected if isinstance(expected, tuple) else (expected,)):
                if (
                    type(value) is list
                    and operation
                    not in {"bun_vitest_invocation", "tsx_test_invocation", "mapping_evidence", "mapping_elf"}
                    and not all(isinstance(item, str) for item in value)
                ) or (expected is dict and not all(isinstance(key, str) for key in value)):
                    pass
                else:
                    return value
    code = payload.code if isinstance(payload, NativeRequestContextFailure) else "invalid_reply"
    raise RestrictedPytestError(
        PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
        f"Native restricted execution preparation is unavailable ({code}); execution was not started.",
    )


def native_launch_plan(
    operation: str,
    command,
    *,
    workspace: Path,
    cwd: Path,
    platform: str,
    backend_executable: Path | None,
    profile: str | tuple[str, ...],
):
    """Decode a profile-bound native plan without recalculating admission."""
    result = restricted_native(
        operation,
        {
            "command": [str(item) for item in command],
            "workspace": workspace,
            "cwd": cwd,
            "platform": platform,
            "backend_executable": backend_executable,
        },
        dict,
    )
    return decode_native_plan(result, (profile,) if isinstance(profile, str) else profile)


def decode_native_plan(result: dict[str, Any], profiles: tuple[str, ...]):
    """Decode one profile-bound native DTO for every contained runner."""
    from .runtime.restricted_pytest_model import RestrictedPytestPlan

    scalars = {"profile_version", "backend", "backend_executable", "workspace", "cwd", "executable"}
    arrays = {"command", "allowed_executables", "denied_capabilities"}
    if (
        set(result) != scalars | arrays
        or any(not isinstance(result[key], str) for key in scalars)
        or any(not isinstance(result[key], list) or not all(isinstance(v, str) for v in result[key]) for key in arrays)
        or result["profile_version"] not in profiles
        or not (
            result["backend"] in {"macos-seatbelt", "linux-bubblewrap"}
            # The Windows runner contains only an installed Python interpreter.
            or (
                result["backend"] == "windows-appcontainer"
                and sys.platform == "win32"
                and result["profile_version"] == "python-eval-readonly-v1"
            )
        )
        or not result["command"]
        or not result["allowed_executables"]
    ):
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Invalid native restricted launch plan.")
    return RestrictedPytestPlan(
        profile_version=result["profile_version"],
        backend=result["backend"],
        backend_executable=Path(result["backend_executable"]),
        workspace=Path(result["workspace"]),
        cwd=Path(result["cwd"]),
        executable=Path(result["executable"]),
        command=tuple(result["command"]),
        allowed_executables=tuple(Path(v) for v in result["allowed_executables"]),
        denied_capabilities=tuple(result["denied_capabilities"]),
    )
