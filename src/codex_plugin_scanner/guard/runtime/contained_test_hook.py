"""Execution sink for native-required, read-only repository test runs."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
from collections.abc import Callable, Mapping
from pathlib import Path

from . import restricted_git, restricted_node_test, restricted_node_tool, restricted_vitest
from .restricted_inline_eval import is_inline_eval, prepare_restricted_inline_eval, run_restricted_inline_eval
from .restricted_package_test import (
    PACKAGE_TEST_PROFILE,
    PACKAGE_TEST_REASON,
    is_package_test,
    resolve_package_test,
)
from .restricted_pytest import RestrictedPytestError, prepare_restricted_pytest, run_restricted_pytest
from .restricted_pytest_model import (
    GIT_READ_ONLY_PROFILE_VERSION,
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TEST_READ_ONLY_PROFILE_VERSION,
    PYTEST_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
)

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
        if "cwd" in payload and (
            not isinstance(payload["cwd"], str)
            or Path(payload["cwd"]).resolve(strict=True) != workspace.resolve(strict=True)
        ):
            raise _reject()
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
    package_test = is_package_test(command)
    if package_test:
        command = list(resolve_package_test(command, workspace=workspace))
    inline_eval = is_inline_eval(command)
    # Fail before the authority request if the backend cannot enforce the profile.
    node_test = len(command) > 1 and Path(command[0]).name in {"node", "nodejs"} and command[1] == "--test"
    vitest = bool(command) and (
        Path(command[0]).name in {"bunx", "npx", "vitest"}
        or restricted_vitest.bun_vitest_invocation(command) is not None
        or (
            len(command) > 1
            and Path(command[0]).name in {"node", "nodejs"}
            and command[1].endswith("/node_modules/vitest/vitest.mjs")
        )
    )
    git = bool(command) and Path(command[0]).name == "git"
    node_tool = (
        restricted_vitest.bun_vitest_invocation(command) is None
        and bool(command)
        and (
            Path(command[0]).name in {"eslint", "tsc", "vite", "bun", "npm", "pnpm"}
            or (
                Path(command[0]).name in {"bunx", "npx"}
                and any(arg in {"eslint", "tsc", "vite"} for arg in command[1:3])
            )
            or (
                len(command) > 1
                and Path(command[0]).name in {"node", "nodejs"}
                and any(
                    argument.endswith(
                        (
                            "/node_modules/eslint/bin/eslint.js",
                            "/node_modules/typescript/bin/tsc",
                            "/node_modules/vite/bin/vite.js",
                        )
                    )
                    for argument in command[1:3]
                )
            )
        )
    )
    inline_plan = node_tool_plan = git_plan = vitest_plan = node_test_plan = None
    if inline_eval:
        inline_plan = prepare_restricted_inline_eval(command, workspace=workspace)
    elif node_tool:
        node_tool_plan = restricted_node_tool.prepare_restricted_node_tool(command, workspace=workspace, cwd=workspace)
    elif git:
        git_plan = restricted_git.prepare_restricted_git(command, workspace=workspace, cwd=workspace)
    elif vitest:
        vitest_plan = restricted_vitest.prepare_restricted_vitest(command, workspace=workspace, cwd=workspace)
    elif node_test:
        node_test_plan = restricted_node_test.prepare_restricted_node_test(command, workspace=workspace, cwd=workspace)
    else:
        prepare_restricted_pytest(command, workspace=workspace, cwd=workspace, read_only_workspace=True)
    if inline_plan is not None:
        profile = inline_plan.profile_version
        if profile == "node-eval-readonly-v1":
            reason = "native_node_eval_readonly_containment_required"
        else:
            reason = "native_python_eval_readonly_containment_required"
    elif node_tool_plan is not None:
        profile = node_tool_plan.profile_version
        if profile == NODE_BUILD_OUTPUT_PROFILE_VERSION:
            reason = "native_node_build_output_containment_required"
        else:
            reason = "native_node_tool_readonly_containment_required"
    elif git:
        reason, profile = "native_git_readonly_containment_required", GIT_READ_ONLY_PROFILE_VERSION
    elif vitest:
        reason, profile = "native_vitest_readonly_containment_required", VITEST_READ_ONLY_PROFILE_VERSION
    elif node_test:
        reason, profile = "native_node_test_readonly_containment_required", NODE_TEST_READ_ONLY_PROFILE_VERSION
    else:
        reason, profile = "native_pytest_readonly_containment_required", PYTEST_READ_ONLY_PROFILE_VERSION

    def required(response: object, *, expected_reason: str = reason, expected_profile: str = profile) -> bool:
        return (
            isinstance(response, Mapping)
            and response.get("decision") == "deny"
            and response.get("policy_action") == "sandbox-required"
            and response.get("reason_code") == expected_reason
            and response.get("required_execution_profile") == expected_profile
            and response.get("observe_mode") is not True
        )

    if not required(
        authorize(payload),
        expected_reason=PACKAGE_TEST_REASON if package_test else reason,
        expected_profile=PACKAGE_TEST_PROFILE if package_test else profile,
    ):
        raise _reject()
    if package_test:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(command)}}
        if not required(authorize(underlying)):
            raise _reject()

    def authorize_capability(argv: tuple[str, ...]) -> None:
        capability = {**payload, "tool_input": {**tool_input, "command": shlex.join(argv)}}
        contexts = [workspace]
        if vitest_plan is not None and vitest_plan.cwd != workspace:
            contexts.append(vitest_plan.cwd)
        for directory in contexts:
            response = authorize({**capability, "cwd": str(directory)})
            if (
                not isinstance(response, Mapping)
                or not (
                    (response.get("decision") == "allow" and response.get("policy_action") == "allow")
                    or (vitest_plan is not None and required(response))
                )
                or response.get("observe_mode") is True
            ):
                raise _reject()

    # No shell and no unsandboxed retry: the required profile is the actual sink.
    if inline_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(inline_plan.command)}}
        if not required(authorize(underlying)):
            raise _reject()
        return run_restricted_inline_eval(
            inline_plan, timeout_seconds=timeout_seconds, authorize_capability=authorize_capability
        )
    if node_tool_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(node_tool_plan.command)}}
        if not required(authorize(underlying)):
            raise _reject()
        return restricted_node_tool.run_restricted_node_tool(
            node_tool_plan, timeout_seconds=timeout_seconds, authorize_capability=authorize_capability
        )
    if git_plan is not None:
        return restricted_git.run_restricted_git(git_plan, timeout_seconds=timeout_seconds)
    if vitest_plan is not None:
        # Check the resolved Node/script action too: wrapper consent must not
        # override an extension deny for the underlying executable.
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(vitest_plan.command)}}
        # Selecting another directory cannot shed the original project's denies.
        for directory in dict.fromkeys((workspace, vitest_plan.cwd)):
            if not required(authorize({**underlying, "cwd": str(directory)})):
                raise _reject()
        return restricted_vitest.run_restricted_vitest(
            command,
            workspace=workspace,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            prepared_plan=vitest_plan,
            authorize_capability=authorize_capability,
        )
    if node_test_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(node_test_plan.command)}}
        if not required(authorize(underlying)):
            raise _reject()
        return restricted_node_test.run_restricted_node_test(
            command,
            workspace=workspace,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            prepared_plan=node_test_plan,
            authorize_capability=authorize_capability,
        )
    return run_restricted_pytest(
        command,
        workspace=workspace,
        cwd=workspace,
        timeout_seconds=timeout_seconds,
        read_only_workspace=True,
    )
