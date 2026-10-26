"""Execution sink for native-required, read-only repository test runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from ..desktop_core_currency import OUT_OF_SYNC_REASON, superseded_desktop_core
from ..native_restricted_pytest import contained_target
from ..windows_paths import trusted_windows_local_temp
from . import restricted_git, restricted_node_test, restricted_node_tool, restricted_vitest
from .contained_authority import authority_unavailable, settled_authority
from .contained_command_prefix import (
    _assignments_applied,
    _peel_for_receipt,
    _split_command_prefix,
    peel_run_prefixes,
)
from .contained_run_directory import as_directory_change, as_run_root
from .contained_wrapper import anchored_sibling_root, bounded_output, peel_contained_wrapper, sibling_project_root
from .restricted_inline_eval import prepare_restricted_inline_eval, run_restricted_inline_eval
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
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
)
from .restricted_pytest_validation import _path_is_within
from .restricted_workspace import receipt_matches, run_workspace_contained

_MAX_REQUEST_BYTES = 1_048_576
_FAILURE = "contained_run_authorization_failed"
_PYTEST_EXECUTABLE_NAMES = frozenset({"pytest", "py.test", "pytest.exe", "py.test.exe"})
_PYTHON_EXECUTABLE = re.compile(r"(?i)^(?:python|pythonw)(?:\d+(?:\.\d+)*)?(?:\.exe)?$")


def _reject(response: object = None) -> RestrictedPytestError:
    # Only an unavailable *rejected receipt* may change the error wording.
    # Shape validation and unrelated later rejections must not inherit state
    # from a previous native authority call in this process.
    if authority_unavailable(response) and isinstance(response, Mapping):
        superseded = superseded_desktop_core()
        if superseded is not None:
            return RestrictedPytestError(OUT_OF_SYNC_REASON, superseded.message())
        reason = response.get("reason_code")
        return RestrictedPytestError(
            _FAILURE,
            f"Guard's native policy runtime did not answer ({reason}), so this command was not run. "
            "Try it again; if it keeps failing, run `hol-guard repair`.",
        )
    return RestrictedPytestError(_FAILURE, "Guard could not authorize this contained run.")


def _command_names_pytest(command: list[str]) -> bool:
    """Whether `command` is a pytest executable or a `python -m pytest` form."""
    if not command:
        return False
    name = command[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in _PYTEST_EXECUTABLE_NAMES:
        return True
    if _PYTHON_EXECUTABLE.fullmatch(name) is None:
        return False
    return _python_args_name_pytest(command[1:])


def _python_args_name_pytest(args: list[str]) -> bool:
    """Match the native planner's `python -m pytest` recognition, flags included."""
    index = 0
    while index < len(args):
        item = args[index]
        if item == "--":
            return False
        if item in {"-c", "--command"} or item.startswith("-c") or item.startswith("--command="):
            return False
        if item == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return module.split(".", 1)[0] == "pytest"
        if item.startswith("-m") and len(item) > 2:
            return item[2:].split(".", 1)[0] == "pytest"
        if item in {"-W", "-X", "--check-hash-based-pycs"}:
            index += 2
            continue
        if item.startswith(("-W", "-X")) or item.startswith("--check-hash-based-pycs="):
            index += 1
            continue
        if not item.startswith("-"):
            return False
        index += 1
    return False


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _reject()
        result[key] = value
    return result


def read_contained_test_request(path: Path, expected_sha256: str, *, workspace: Path) -> dict[str, object]:
    """Read one bounded private adapter snapshot, without following its leaf."""
    if os.name == "nt":
        return _read_windows_request(path, expected_sha256, workspace=workspace)
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
        return _decode_request(raw, expected_sha256, workspace=workspace)
    except (OSError, ValueError, RuntimeError, RecursionError) as error:
        if isinstance(error, RestrictedPytestError):
            raise
        raise _reject() from error


def _read_windows_request(path: Path, expected_sha256: str, *, workspace: Path) -> dict[str, object]:
    """Windows has no owner-mode bits; the snapshot must sit directly in this
    user's temporary directory, reached without links or junctions. The
    directory comes from the profile, not TEMP, which the hook that wrote the
    snapshot and the shell that runs this sink may set differently."""
    if (
        path.name != "request.json"
        or not path.parent.name.startswith("hol-guard-contained-test-")
        or not path.is_absolute()
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise _reject()
    try:
        temporary = trusted_windows_local_temp()
        if os.path.normcase(path.parent.parent) != os.path.normcase(temporary):
            raise _reject()
        for candidate, regular in ((path.parent, False), (path, True)):
            metadata = os.lstat(candidate)
            if (
                getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or (stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)) is not True
            ):
                raise _reject()
        if metadata.st_nlink != 1 or metadata.st_size > _MAX_REQUEST_BYTES:
            raise _reject()
        with open(path, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise _reject()
            raw = stream.read(_MAX_REQUEST_BYTES + 1)
        return _decode_request(raw, expected_sha256, workspace=workspace)
    except (OSError, ValueError, RuntimeError, RecursionError) as error:
        if isinstance(error, RestrictedPytestError):
            raise
        raise _reject() from error


def _decode_request(raw: bytes, expected_sha256: str, *, workspace: Path) -> dict[str, object]:
    if len(raw) > _MAX_REQUEST_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _reject()
    try:
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


def _contained_receipt(receipt: object) -> bool:
    return (
        isinstance(receipt, Mapping)
        and receipt.get("decision") == "deny"
        and receipt.get("policy_action") == "sandbox-required"
        and isinstance(receipt.get("required_execution_profile"), str)
        and receipt.get("observe_mode") is not True
    )


def run_authorized_contained_test(
    payload: dict[str, object],
    *,
    workspace: Path,
    authorize: Callable[[dict[str, object]], object],
    timeout_seconds: int,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    merge_stderr: bool = False,
) -> int:
    """Recheck native authority for the original input before protected execution.

    `workspace` stays the approved root for dependency and profile resolution;
    `cwd` is only the directory a peeled `cd` selected to run in. A `cd` into a
    sibling repository moves the approved root to that repository.
    """
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise _reject()
    if cwd is None:
        cwd = workspace
    if "cwd" in tool_input:
        # Oh My Pi runs the command in its `cwd` argument. The call as issued
        # must carry the receipt; the explicit `cd` form is then authorized
        # and run by the wrapper path below.
        receipt = settled_authority(authorize, payload)
        if not _contained_receipt(receipt):
            raise _reject(receipt)
        if receipt_matches(receipt):
            # The `cd` form is judged from the session folder and can lose
            # the workspace sandbox native authority chose inside `cwd` (a
            # setting such as `REPORT_DIR=... vitest` in a linked worktree).
            # Ask again rooted at that directory and, when the answer is the
            # same sandbox, run the command as issued there.
            # Only a directory the `cd` form could also root the sandbox at
            # is asked about: inside the workspace, or a sibling repository's
            # own root. Any other `cwd` keeps the directory change below.
            root, rooted = as_run_root(payload, workspace=workspace, home=home_dir)
            bounded = _path_is_within(root, workspace.resolve(strict=True)) or (
                sibling_project_root(root, home=home_dir) == root
            )
            first = settled_authority(authorize, rooted) if bounded else None
            if receipt_matches(first) and isinstance(first, Mapping):
                return run_workspace_contained(
                    rooted,
                    workspace=root,
                    cwd=root,
                    authorize=authorize,
                    first_receipt=first,
                    home_dir=home_dir,
                    timeout_seconds=timeout_seconds,
                    merge_stderr=merge_stderr,
                )
        return run_authorized_contained_test(
            as_directory_change(payload, workspace=workspace, home=home_dir),
            workspace=workspace,
            authorize=authorize,
            timeout_seconds=timeout_seconds,
            cwd=cwd,
            home_dir=home_dir,
            merge_stderr=merge_stderr,
        )

    projected = contained_target(tool_input["command"], cwd=cwd, home_dir=home_dir)
    if projected is not None:
        # A trailing group runs the command list inside it, and a virtualenv
        # activation hands its verdict to the command after it; the pre-tool
        # pass answered for that command. The call as issued must carry the
        # receipt; the projected command is then re-authorized on its own and
        # planned from the text the answer named.
        receipt = settled_authority(authorize, payload)
        if not _contained_receipt(receipt):
            raise _reject(receipt)
        return run_authorized_contained_test(
            {**payload, "tool_input": {**tool_input, "command": projected}},
            workspace=workspace,
            authorize=authorize,
            timeout_seconds=timeout_seconds,
            cwd=cwd,
            home_dir=home_dir,
            merge_stderr=merge_stderr,
        )

    def run_workspace(receipt: object) -> int | None:
        """Run in the workspace sandbox when Rust issued that profile, else None."""
        if not receipt_matches(receipt) or not isinstance(receipt, Mapping):
            return None
        return run_workspace_contained(
            payload,
            workspace=workspace,
            cwd=cwd,
            authorize=authorize,
            first_receipt=receipt,
            home_dir=home_dir,
            timeout_seconds=timeout_seconds,
            merge_stderr=merge_stderr,
        )

    try:
        peeled = peel_contained_wrapper(tool_input["command"], workspace=workspace, home=home_dir, cwd=cwd)
    except (OSError, RuntimeError, ValueError) as error:
        # Pipelines and lists the wrapper cannot peel (`| sort`, `&&`) still
        # run as issued when Rust chose the workspace sandbox for them.
        receipt = settled_authority(authorize, payload)
        exit_code = run_workspace(receipt)
        if exit_code is None:
            raise _reject(receipt) from error
        return exit_code
    if peeled is not None:
        # The wrapped original must carry the receipt; the core is then
        # re-authorized in its resolved directory by the recursive call.
        receipt = settled_authority(authorize, payload)
        if not _contained_receipt(receipt):
            raise _reject(receipt)
        core, directory, output = peeled
        if not _path_is_within(directory, workspace.resolve(strict=True)):
            sibling = sibling_project_root(directory, home=home_dir)
            if sibling is None:
                raise _reject()
            workspace = sibling
        if directory != workspace.resolve(strict=True) and receipt_matches(receipt) and isinstance(receipt, Mapping):
            # The workspace sandbox starts only at its root, where Rust
            # classified the whole text, so the `cd` runs inside it as issued.
            return run_workspace_contained(
                payload,
                workspace=workspace,
                cwd=workspace,
                authorize=authorize,
                first_receipt=receipt,
                home_dir=home_dir,
                timeout_seconds=timeout_seconds,
                merge_stderr=merge_stderr,
            )
        with bounded_output(output):
            exit_code = run_authorized_contained_test(
                {**payload, "cwd": str(directory), "tool_input": {**tool_input, "command": core}},
                workspace=workspace,
                authorize=authorize,
                timeout_seconds=timeout_seconds,
                cwd=directory,
                home_dir=home_dir,
                merge_stderr=output is not None and output.merge_stderr,
            )
        status_line = output.status_line(exit_code) if output is not None else None
        if status_line is None:
            return exit_code
        # The shell's status is the echo's own.
        sys.stdout.write(status_line)
        sys.stdout.flush()
        return 0

    anchored = anchored_sibling_root(tool_input["command"], workspace=workspace, cwd=cwd, home=home_dir)
    receipt = settled_authority(authorize, payload) if anchored is not None else None
    if anchored is not None and receipt_matches(receipt) and isinstance(receipt, Mapping):
        # An absolute script in a sibling repository runs from that root, as
        # after `cd <root> &&`; any other receipt takes the paths below.
        return run_workspace_contained(
            payload,
            workspace=anchored,
            cwd=anchored,
            authorize=authorize,
            first_receipt=receipt,
            home_dir=home_dir,
            timeout_seconds=timeout_seconds,
            merge_stderr=merge_stderr,
        )
    try:
        core, assignments, dropped = _peel_for_receipt(shlex.split(tool_input["command"], posix=True))
    # The peel asks native authority for the prefixes it reads, so a transport
    # failure or a resident too old to know the operation raises here, before
    # any receipt is drawn. Nothing is peeled then, and the command goes on to
    # the guarded planner block, which already answers a native failure the
    # same way it does for `launcher_program`.
    except (ValueError, RestrictedPytestError):
        core, assignments, dropped = [], {}, False
    if assignments or dropped:
        # Like a wrapper: the original carries the receipt, then the core is
        # authorized again and runs with the assignments exported (a dropped
        # data setting too). A workspace receipt runs the original as issued.
        receipt = settled_authority(authorize, payload)
        exit_code = run_workspace(receipt)
        if exit_code is not None:
            return exit_code
        if not core or not _contained_receipt(receipt):
            raise _reject(receipt if core else None)
        with _assignments_applied(assignments):
            return run_authorized_contained_test(
                {**payload, "tool_input": {**tool_input, "command": shlex.join(core)}},
                workspace=workspace,
                authorize=authorize,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                home_dir=home_dir,
                merge_stderr=merge_stderr,
            )

    names_pytest = False
    try:
        try:
            command, _ = _split_command_prefix(shlex.split(tool_input["command"], posix=True))
        except ValueError as error:
            raise _reject() from error
        # Native authority reads a system `timeout` and each launcher it
        # knows through to the program they run, so the planners below are
        # handed that program. A clock still bounds this run: it only ever
        # shortens the deadline.
        command, clock = peel_run_prefixes(command)
        if clock is not None:
            timeout_seconds = min(timeout_seconds, clock)
        package_test = is_package_test(command)
        if package_test:
            command = list(resolve_package_test(command, workspace=workspace, cwd=cwd))
        names_pytest = _command_names_pytest(command)
        from ..native_restricted_pytest import restricted_native

        kinds = restricted_native("contained_kind", {"command": command}, dict)
        if set(kinds) != {"inline_eval", "node_test", "vitest", "git", "node_tool"} or any(
            type(value) is not bool for value in kinds.values()
        ):
            raise _reject()
        inline_eval, node_test, vitest, git, node_tool = (
            kinds[key] for key in ("inline_eval", "node_test", "vitest", "git", "node_tool")
        )
        inline_plan = node_tool_plan = git_plan = vitest_plan = node_test_plan = None
        if inline_eval:
            inline_plan = prepare_restricted_inline_eval(command, workspace=workspace, cwd=cwd, home_dir=home_dir)
        elif node_tool:
            node_tool_plan = restricted_node_tool.prepare_restricted_node_tool(
                command, workspace=workspace, cwd=cwd, home_dir=home_dir
            )
        elif git:
            git_plan = restricted_git.prepare_restricted_git(command, workspace=workspace, cwd=cwd, home_dir=home_dir)
        elif vitest:
            vitest_plan = restricted_vitest.prepare_restricted_vitest(
                command, workspace=workspace, cwd=cwd, home_dir=home_dir
            )
        elif node_test:
            node_test_plan = restricted_node_test.prepare_restricted_node_test(
                command, workspace=workspace, cwd=cwd, home_dir=home_dir
            )
        else:
            prepare_restricted_pytest(
                command,
                workspace=workspace,
                cwd=cwd,
                home_dir=home_dir,
                read_only_workspace=True,
            )
    except RestrictedPytestError as error:
        # The read-only planners reject the mutating shapes (`git add && git
        # commit`, `node -e`, `./todo.py`) that Rust sends to the workspace
        # sandbox. Only a live workspace receipt runs them; anything else fails.
        receipt = settled_authority(authorize, payload)
        exit_code = run_workspace(receipt)
        if exit_code is None:
            # This planner is the last shape tried. Its "accepts only a pytest
            # executable" message would point at an invocation that was never
            # in the command, so a command that did not name pytest reports
            # the authorization that failed. A command that did name pytest
            # keeps the planner error, including a refused flag or argument.
            if error.reason_code == PYTEST_INVALID_COMMAND_REASON_CODE and not names_pytest:
                raise _reject(receipt) from error
            raise
        return exit_code
    if inline_plan is not None:
        profile = inline_plan.profile_version
        if profile == "node-eval-readonly-v1" and Path(command[0]).name == "bun":
            reason = "native_bun_eval_readonly_containment_required"
        elif profile == "node-eval-readonly-v1":
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

    # Authorize after planning so the live decision follows every file the
    # planner read. Rust may still pick the workspace sandbox for this shape.
    receipt = settled_authority(authorize, payload)
    exit_code = run_workspace(receipt)
    if exit_code is not None:
        return exit_code
    if not required(
        receipt,
        expected_reason=PACKAGE_TEST_REASON if package_test else reason,
        expected_profile=PACKAGE_TEST_PROFILE if package_test else profile,
    ):
        raise _reject(receipt)
    if package_test:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(command)}}
        underlying_receipt = settled_authority(authorize, underlying)
        if not required(underlying_receipt):
            raise _reject(underlying_receipt)

    def authorize_capability(argv: tuple[str, ...]) -> None:
        capability = {**payload, "tool_input": {**tool_input, "command": shlex.join(argv)}}
        # The approved workspace root stays in scope so a subdirectory cannot shed its denies.
        build = node_tool_plan is not None and node_tool_plan.profile_version == NODE_BUILD_OUTPUT_PROFILE_VERSION
        transform_plan = vitest_plan or (node_tool_plan if build else None)
        contexts = (workspace, cwd, *((transform_plan.cwd,) if transform_plan is not None else ()))
        for directory in dict.fromkeys(contexts):
            response = settled_authority(authorize, {**capability, "cwd": str(directory)})
            if (
                not isinstance(response, Mapping)
                or not (
                    (response.get("decision") == "allow" and response.get("policy_action") == "allow")
                    # Native classifies the transform image as a read-only
                    # Vitest capability; it runs inside the Vitest run's or the
                    # Vite build's own profile.
                    or (
                        transform_plan is not None
                        and required(
                            response,
                            expected_reason="native_vitest_readonly_containment_required",
                            expected_profile=VITEST_READ_ONLY_PROFILE_VERSION,
                        )
                    )
                )
                or response.get("observe_mode") is True
            ):
                raise _reject(response)

    # No shell and no unsandboxed retry: the required profile is the actual sink.
    if inline_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(inline_plan.command)}}
        underlying_receipt = settled_authority(authorize, underlying)
        if not required(underlying_receipt):
            raise _reject(underlying_receipt)
        return run_restricted_inline_eval(
            inline_plan,
            timeout_seconds=timeout_seconds,
            authorize_capability=authorize_capability,
            merge_stderr=merge_stderr,
        )
    if node_tool_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(node_tool_plan.command)}}
        underlying_receipt = settled_authority(authorize, underlying)
        if not required(underlying_receipt):
            raise _reject(underlying_receipt)
        return restricted_node_tool.run_restricted_node_tool(
            node_tool_plan,
            timeout_seconds=timeout_seconds,
            authorize_capability=authorize_capability,
            merge_stderr=merge_stderr,
        )
    if git_plan is not None:
        return restricted_git.run_restricted_git(git_plan, timeout_seconds=timeout_seconds, merge_stderr=merge_stderr)
    if vitest_plan is not None:
        # Check the resolved Node/script action too: wrapper consent must not
        # override an extension deny for the underlying executable.
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(vitest_plan.command)}}
        # Selecting another directory cannot shed the original project's denies.
        for directory in dict.fromkeys((workspace, cwd, vitest_plan.cwd)):
            directory_receipt = settled_authority(authorize, {**underlying, "cwd": str(directory)})
            if not required(directory_receipt):
                raise _reject(directory_receipt)
        return restricted_vitest.run_restricted_vitest(
            command,
            workspace=workspace,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            prepared_plan=vitest_plan,
            authorize_capability=authorize_capability,
            merge_stderr=merge_stderr,
        )
    if node_test_plan is not None:
        underlying = {**payload, "tool_input": {**tool_input, "command": shlex.join(node_test_plan.command)}}
        underlying_receipt = settled_authority(authorize, underlying)
        if not required(underlying_receipt):
            raise _reject(underlying_receipt)
        return restricted_node_test.run_restricted_node_test(
            command,
            workspace=workspace,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            prepared_plan=node_test_plan,
            authorize_capability=authorize_capability,
            merge_stderr=merge_stderr,
        )
    return run_restricted_pytest(
        command,
        workspace=workspace,
        cwd=cwd,
        home_dir=home_dir,
        timeout_seconds=timeout_seconds,
        read_only_workspace=True,
        merge_stderr=merge_stderr,
    )
