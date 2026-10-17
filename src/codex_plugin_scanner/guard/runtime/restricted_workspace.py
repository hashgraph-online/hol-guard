"""Run a confidently parsed local command in the workspace sandbox profile."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path

from ..native_restricted_pytest import restricted_native
from .contained_authority import settled_authority
from .git_execution_safety import trusted_git_binary_for_cwd
from .restricted_pytest_model import (
    _DEFAULT_TIMEOUT_SECONDS,
    PYTEST_INVALID_COMMAND_REASON_CODE,
    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
    RestrictedPytestError,
)
from .restricted_pytest_sandbox import _restricted_environment, _run_backend_process
from .restricted_workspace_grants import read_grants_valid

WORKSPACE_REASON = "native_workspace_containment_required"
WORKSPACE_PROFILE = "workspace-contained-v1"
# The reason Rust gives a chain whose checks run contained and whose trailing
# Git steps run after them, once proven again. It must match Rust exactly.
WORKSPACE_PUBLISH_REASON = (
    "HOL Guard runs the checks in this command in a protected workspace sandbox "
    "(no network, no home access), then runs the Git steps that follow once it "
    "proves them again."
)
# Appended when a contained run fails after printing a denied operation.
WORKSPACE_WRITE_DENIAL_NOTE = (
    "This run hit a denied operation (EPERM or EROFS). HOL Guard runs this command in a "
    "workspace sandbox: the workspace and $TMPDIR are writable, except a few protected paths "
    "such as Git configuration, and there is no network or home access. Keep files the command "
    "writes inside the workspace or $TMPDIR and run it again."
)
_PLAN_FIELDS = frozenset(
    {
        "profile_version",
        "backend",
        "backend_executable",
        "workspace",
        "cwd",
        "executable",
        "command",
        "command_sha256",
        "allowed_executables",
        "read_only_roots",
        "exec_roots",
        "write_denials",
        "linked_git",
        "sandbox_path",
        "bootstrap_git",
        "prefix_command",
        "native_suffix",
        "denied_capabilities",
    }
)
_IDENTITY_KEYS = {"user.name": "NAME", "user.email": "EMAIL"}
_BACKENDS = {"darwin": "macos-seatbelt", "linux": "linux-bubblewrap"}
# The Linux overlay probe proves this filesystem, so overlays live here too.
_OVERLAY_PARENT = "/tmp"
_BOOTSTRAP_SECONDS = 30


def receipt_matches(receipt: object) -> bool:
    """Whether `receipt` is a live workspace-sandbox requirement."""
    return (
        isinstance(receipt, Mapping)
        and receipt.get("decision") == "deny"
        and receipt.get("policy_action") == "sandbox-required"
        and receipt.get("reason_code") == WORKSPACE_REASON
        and receipt.get("required_execution_profile") == WORKSPACE_PROFILE
        and receipt.get("observe_mode") is not True
        and isinstance(receipt.get("command_binding_digest"), str)
    )


def _host_backend() -> str | None:
    return _BACKENDS.get(sys.platform)


def _reject(message: str) -> RestrictedPytestError:
    return RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, message)


def _checks(command: str, suffix: object) -> str | None:
    """The checks that `command` runs before `&& suffix`, as Rust split it."""
    body = command.strip()
    if not isinstance(suffix, str) or not suffix or not body.endswith(suffix):
        return None
    head = body[: len(body) - len(suffix)].rstrip()
    if not head.endswith("&&"):
        return None
    return head[:-2].rstrip() or None


def _validated_plan(plan: object, command: str, workspace: Path, *, publish: bool = False) -> dict[str, object]:
    if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS or plan["profile_version"] != WORKSPACE_PROFILE:
        raise _reject("Invalid workspace sandbox plan.")
    argv = plan["command"]
    prefix = plan["prefix_command"]
    if publish:
        checks = _checks(command, plan["native_suffix"])
        if checks is None or prefix is not None or plan["bootstrap_git"] is not None:
            raise _reject("The workspace sandbox plan does not match the authorized command.")
        command = checks
    elif plan["native_suffix"] is not None:
        raise _reject("The workspace sandbox plan does not match the authorized command.")
    if (
        plan["backend"] != _host_backend()
        or not isinstance(argv, list)
        or len(argv) != 3
        or argv[:2] != ["/bin/sh", "-c"]
        or not isinstance(argv[2], str)
        or plan["command_sha256"] != hashlib.sha256(argv[2].encode()).hexdigest()
        or not (argv[2] == command if plan["bootstrap_git"] is None else command.endswith(argv[2]))
        or not (
            prefix is None
            or (
                isinstance(prefix, str)
                and plan["bootstrap_git"] is not None
                and command.startswith(prefix)
                and len(prefix) + len(argv[2]) < len(command)
            )
        )
        or Path(str(plan["workspace"])) != workspace.resolve(strict=True)
        or plan["allowed_executables"] != []
        or not read_grants_valid(plan["read_only_roots"], command)
        or not (plan["linked_git"] is None or _linked_git(plan["linked_git"]))
    ):
        raise _reject("The workspace sandbox plan does not match the authorized command.")
    return plan


def _linked_git(value: object) -> dict[str, str] | None:
    """A linked worktree's shared `.git` and admin entry, as the plan names them."""
    if (
        isinstance(value, dict)
        and set(value) == {"common", "admin"}
        and all(isinstance(item, str) and Path(item).is_absolute() for item in value.values())
    ):
        return value
    return None


def _plan_paths(value: object) -> list[Path]:
    if not isinstance(value, list):
        raise _reject("Invalid workspace sandbox plan.")
    return [Path(str(item)) for item in value]


def _identity(cwd: Path, git: Path) -> dict[str, str]:
    """Author and committer from the host's global Git configuration."""
    result: dict[str, str] = {}
    for key, part in _IDENTITY_KEYS.items():
        completed = subprocess.run(
            [str(git), "config", "--global", "--get", key],
            cwd=cwd,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "GIT_CONFIG_NOSYSTEM": "1"},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        value = completed.stdout.strip()
        if completed.returncode == 0 and value and "\n" not in value and "\0" not in value:
            result[f"GIT_AUTHOR_{part}"] = value
            result[f"GIT_COMMITTER_{part}"] = value
    return result


def _bootstrap_init(arguments: object, *, workspace: Path, private_root: Path) -> None:
    """Run `git init` outside the sandbox: it rewrites the write-denied `.git/config`."""
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        raise _reject("Invalid workspace sandbox bootstrap.")
    git = trusted_git_binary_for_cwd(workspace)
    if git is None or (workspace / ".git").is_symlink() or (workspace / ".git").exists():
        raise RestrictedPytestError(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE, "Git initialization is unavailable.")
    template = private_root / "template"
    template.mkdir(mode=0o700)
    home = private_root / "init-home"
    home.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(git), "init", f"--template={template}", *arguments],
        cwd=workspace,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=_BOOTSTRAP_SECONDS,
        check=False,
    )
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    if completed.returncode != 0:
        raise RestrictedPytestError(
            "pytest_restricted_git_init_failed", "git init failed.", exit_code=completed.returncode
        )


def run_workspace_contained(
    payload: dict[str, object],
    *,
    workspace: Path,
    cwd: Path,
    authorize: Callable[[dict[str, object]], object],
    first_receipt: Mapping[str, object],
    home_dir: Path | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    merge_stderr: bool = False,
) -> int:
    """Run the authorized command in `workspace-contained-v1`, with no fallback."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise _reject("Invalid workspace sandbox request.")
    command = tool_input["command"]
    publish = first_receipt.get("reason") == WORKSPACE_PUBLISH_REASON
    if cwd.resolve(strict=True) != workspace.resolve(strict=True):
        raise _reject("The workspace sandbox runs only from the workspace root.")
    plan = _validated_plan(
        restricted_native(
            "prepare_workspace_contained",
            {
                "text": command,
                "workspace": workspace,
                "cwd": cwd,
                "platform": sys.platform,
                "home": home_dir or Path.home(),
                # The resident's own environment is not what a later host Git sees.
                "git_environment": {
                    name: value
                    for name, value in os.environ.items()
                    if name.startswith("GIT_CONFIG") or name == "XDG_CONFIG_HOME"
                },
                "publish_suffix": publish,
            },
            dict,
        ),
        command,
        workspace,
        publish=publish,
    )
    # A second receipt taken after planning must still bind the same evidence.
    second = settled_authority(authorize, payload)
    if not receipt_matches(second) or not isinstance(second, Mapping):
        raise _reject("Guard could not re-authorize this workspace sandbox execution.")
    if second.get("command_binding_digest") != first_receipt.get("command_binding_digest") or (
        (second.get("reason") == WORKSPACE_PUBLISH_REASON) != publish
    ):
        raise _reject("The command evidence changed before launch.")
    sandbox_command = plan["command"]
    prefix = plan["prefix_command"]
    if not isinstance(sandbox_command, list):
        raise _reject("Invalid workspace sandbox plan.")
    sandbox_argv = [str(item) for item in sandbox_command]
    exec_roots = _plan_paths(plan["exec_roots"])
    read_files = _plan_paths(plan["read_only_roots"])
    write_denials = _plan_paths(plan["write_denials"])
    with tempfile.TemporaryDirectory(prefix="hol-guard-workspace-") as temporary_directory:
        private_root = Path(temporary_directory).resolve()
        private_home = private_root / "home"
        private_tmp = private_root / "tmp"
        private_home.mkdir(mode=0o700)
        private_tmp.mkdir(mode=0o700)

        def contained(argv_to_run: list[str]) -> int:
            launch_env = _restricted_environment(
                os.environ,
                workspace=workspace,
                cwd=cwd,
                private_home=private_home,
                private_tmp=private_tmp,
                allowed_executables=(),
            )
            empty_config = private_root / "gitconfig"
            empty_config.write_text("", encoding="utf-8")
            launch_env["PATH"] = str(plan["sandbox_path"])
            launch_env["GIT_CONFIG_NOSYSTEM"] = "1"
            launch_env["GIT_CONFIG_GLOBAL"] = str(empty_config)
            launch_env["GIT_TERMINAL_PROMPT"] = "0"
            git = trusted_git_binary_for_cwd(workspace)
            if git is not None:
                launch_env.update(_identity(workspace, git))
            if plan["backend"] == "linux-bubblewrap":
                return _run_overlay(
                    plan,
                    workspace=workspace,
                    private_root=private_root,
                    exec_roots=exec_roots,
                    read_files=read_files,
                    write_denials=write_denials,
                    command=argv_to_run,
                    env=launch_env,
                    timeout_seconds=timeout_seconds,
                    merge_stderr=merge_stderr,
                )
            profile = restricted_native(
                "macos_profile",
                {
                    "profile_version": WORKSPACE_PROFILE,
                    "workspace": workspace,
                    "cwd": cwd,
                    "private_root": private_root,
                    "allowed_executables": [],
                    "read_only_roots": read_files,
                    "output_roots": [],
                    "exec_roots": exec_roots,
                    "write_denials": write_denials,
                    "linked_git": plan["linked_git"],
                    "command": argv_to_run,
                    "backend_executable": Path(str(plan["backend_executable"])),
                },
                str,
            )
            argv = [str(plan["backend_executable"]), "-p", profile, "--", *argv_to_run]
            return _run_backend_process(
                argv,
                env=launch_env,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                merge_stderr=merge_stderr,
                write_denial_note=WORKSPACE_WRITE_DENIAL_NOTE,
            )

        if isinstance(prefix, str):
            # `prefix && git init && rest`: a failed prefix ends the command.
            exit_code = contained(["/bin/sh", "-c", prefix])
            if exit_code != 0:
                return exit_code
        if plan["bootstrap_git"] is not None:
            _bootstrap_init(plan["bootstrap_git"], workspace=workspace, private_root=private_root)
            if not sandbox_argv[2]:
                return 0
        exit_code = contained(sandbox_argv)
    suffix = plan["native_suffix"]
    if exit_code != 0 or not isinstance(suffix, str):
        return exit_code
    return _run_publish_steps(
        payload,
        suffix,
        workspace=workspace,
        authorize=authorize,
        timeout_seconds=timeout_seconds,
        merge_stderr=merge_stderr,
    )


def _run_publish_steps(
    payload: dict[str, object],
    suffix: str,
    *,
    workspace: Path,
    authorize: Callable[[dict[str, object]], object],
    timeout_seconds: int,
    merge_stderr: bool,
) -> int:
    """Run the Git steps after the contained checks, once Guard proves them again.

    The checks may have changed the repository, so the steps are judged on
    their own now rather than trusting the verdict taken before the checks ran.
    They run outside the sandbox because a push needs the network and the
    user's own credentials.
    """
    tool_input = payload["tool_input"]
    if not isinstance(tool_input, dict):
        raise _reject("Invalid workspace sandbox request.")
    response = settled_authority(authorize, {**payload, "tool_input": {**tool_input, "command": suffix}})
    if (
        not isinstance(response, Mapping)
        or response.get("decision") != "allow"
        or response.get("policy_action") != "allow"
        or response.get("observe_mode") is True
    ):
        raise _reject("Guard could not prove the Git steps again after the checks ran; they did not run.")
    sys.stdout.flush()
    sys.stderr.flush()
    process = subprocess.Popen(
        ["/bin/sh", "-c", suffix],
        cwd=workspace,
        env={**os.environ, "PATH": _outside_search_path(os.environ.get("PATH", ""), workspace)},
        stdin=subprocess.DEVNULL,
        stderr=subprocess.STDOUT if merge_stderr else None,
        start_new_session=True,
    )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise RestrictedPytestError(
            "pytest_restricted_timeout",
            f"The Git steps exceeded their {timeout_seconds}-second execution deadline.",
            exit_code=124,
        ) from error
    return return_code if return_code >= 0 else 128 + abs(return_code)


def _outside_search_path(search_path: str, workspace: Path) -> str:
    """`search_path` without entries the contained checks could have written.

    The checks could plant a `git` or `gh` in a relative or workspace entry,
    which the Git steps would then run unsandboxed, as the sandbox's own
    PATH filter anticipates.
    """
    root = workspace.resolve()
    kept: list[str] = []
    for entry in search_path.split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        resolved = Path(entry).resolve()
        if resolved != root and not resolved.is_relative_to(root):
            kept.append(entry)
    return os.pathsep.join(kept)


def _remove_overlay(root: Path) -> None:
    for inner in (root / "work" / "work", root / "shared" / "work" / "work"):
        if inner.is_dir() and not inner.is_symlink():
            inner.chmod(0o700)
    shutil.rmtree(root, ignore_errors=True)


def _run_overlay(
    plan: Mapping[str, object],
    *,
    workspace: Path,
    private_root: Path,
    exec_roots: list[Path],
    read_files: list[Path],
    write_denials: list[Path],
    command: list[str],
    env: Mapping[str, str],
    timeout_seconds: int,
    merge_stderr: bool,
) -> int:
    """Run in a bubblewrap overlay, then apply the changes Guard admits."""
    overlay_root = Path(tempfile.mkdtemp(prefix="hol-guard-overlay-", dir=_OVERLAY_PARENT))
    try:
        upper = overlay_root / "upper"
        work = overlay_root / "work"
        upper.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        # A linked worktree's shared `.git` gets its own overlay layers.
        linked: dict[str, object] = {}
        if plan["linked_git"] is not None:
            shared = overlay_root / "shared"
            shared.mkdir(mode=0o700)
            (shared / "upper").mkdir(mode=0o700)
            (shared / "work").mkdir(mode=0o700)
            linked = {"linked_git": plan["linked_git"], "shared_upper": shared / "upper"}
        argv = restricted_native(
            "workspace_bubblewrap_argv",
            {
                "backend_executable": Path(str(plan["backend_executable"])),
                "workspace": workspace.resolve(strict=True),
                "private_root": private_root,
                "upper": upper,
                "work": work,
                "exec_roots": exec_roots,
                "read_files": read_files,
                "command": command,
                **({**linked, "shared_work": overlay_root / "shared" / "work"} if linked else {}),
            },
            list,
        )
        status = _run_backend_process(
            [str(item) for item in argv],
            env=env,
            timeout_seconds=timeout_seconds,
            cwd=workspace,
            merge_stderr=merge_stderr,
            write_denial_note=WORKSPACE_WRITE_DENIAL_NOTE,
        )
        restricted_native(
            "apply_workspace_overlay",
            {"workspace": workspace.resolve(strict=True), "upper": upper, "write_denials": write_denials, **linked},
            dict,
        )
        return status
    finally:
        _remove_overlay(overlay_root)
