"""Execution sink for native-required, read-only repository test runs."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
from collections.abc import Callable, Mapping
from pathlib import Path

from .restricted_pytest import RestrictedPytestError, prepare_restricted_pytest, run_restricted_pytest
from .restricted_pytest_model import PYTEST_READ_ONLY_PROFILE_VERSION

_MAX_REQUEST_BYTES = 1_048_576
_FAILURE = "contained_test_authorization_failed"


def _reject() -> RestrictedPytestError:
    return RestrictedPytestError(_FAILURE, "Guard could not authorize this protected test execution.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _reject()
        result[key] = value
    return result


def read_contained_test_request(path: Path, expected_sha256: str, *, workspace: Path) -> dict[str, object]:
    """Read one bounded private adapter snapshot, without following its leaf."""
    if (
        os.name != "posix"
        or path.name != "request.json"
        or not path.parent.name.startswith("hol-guard-contained-test-")
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise _reject()
    try:
        parent_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            parent = os.fstat(parent_descriptor)
            if stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid():
                raise _reject()
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.getuid()
                or metadata.st_size > _MAX_REQUEST_BYTES
            ):
                raise _reject()
            raw = stream.read(_MAX_REQUEST_BYTES + 1)
        if len(raw) > _MAX_REQUEST_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise _reject()
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "workspace", "payload"}
            or value["schema"] != "guard-contained-test-request.v1"
            or not isinstance(value["workspace"], str)
            or Path(value["workspace"]).resolve(strict=True) != workspace.resolve(strict=True)
            or not isinstance(value["payload"], dict)
        ):
            raise _reject()
        payload = value["payload"]
        tool_input = payload.get("tool_input")
        if (
            payload.get("hook_event_name") != "PreToolUse"
            or payload.get("tool_name") != "bash"
            or not isinstance(tool_input, dict)
            or not isinstance(tool_input.get("command"), str)
        ):
            raise _reject()
        return payload
    except (OSError, ValueError, RuntimeError, RecursionError) as error:
        if isinstance(error, RestrictedPytestError):
            raise
        raise _reject() from error


def run_authorized_contained_test(
    payload: dict[str, object],
    *,
    workspace: Path,
    authorize: Callable[[dict[str, object]], object],
    timeout_seconds: int,
) -> int:
    """Recheck native authority for the original input before protected execution."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise _reject()
    try:
        command = shlex.split(tool_input["command"], posix=True)
    except ValueError as error:
        raise _reject() from error
    # Fail before the authority request if the backend cannot enforce the profile.
    prepare_restricted_pytest(command, workspace=workspace, cwd=workspace, read_only_workspace=True)
    response = authorize(payload)
    if not (
        isinstance(response, Mapping)
        and response.get("decision") == "deny"
        and response.get("policy_action") == "sandbox-required"
        and response.get("reason_code") == "native_pytest_readonly_containment_required"
        and response.get("required_execution_profile") == PYTEST_READ_ONLY_PROFILE_VERSION
        and response.get("observe_mode") is not True
    ):
        raise _reject()
    # No shell and no unsandboxed retry: the required profile is the actual sink.
    return run_restricted_pytest(
        command,
        workspace=workspace,
        cwd=workspace,
        timeout_seconds=timeout_seconds,
        read_only_workspace=True,
    )
