"""Create a linked worktree, then run the checks the same command names in it.

Rust answers `git worktree add <checkout> && cd <checkout> && <checks>` with
the workspace sandbox and `WORKTREE_ADD_REASON` only when the add passes as a
command of its own and the checks would pass, or run contained, from the
repository root the checkout copies. The checkout does not exist until the add
runs, so the sandbox cannot take the chain whole. The sink proves the add
again and runs it directly, then judges `cd <checkout> && <checks>` once more
against the real checkout: it runs directly when it passes on its own, and
otherwise goes to the ordinary contained route, which judges it again. Nothing
in the checkout runs unless that judgement holds.
"""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from ..native_contained_wrapper_plan import native_contained_wrapper_plan
from .contained_authority import settled_authority
from .host_steps import run_on_host
from .restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE, RestrictedPytestError

# The reason Rust gives this chain. It must match Rust exactly.
WORKTREE_ADD_REASON = (
    "HOL Guard creates this linked worktree directly, outside the sandbox, once it "
    "proves the `git worktree add` again, then judges the rest of the command again "
    "against the new checkout and runs it there: directly when it passes on its own, "
    "otherwise inside a protected workspace sandbox (no network, no home access, no "
    "PTY or Docker socket), where every program it starts, including children of an "
    "interpreter, runs contained and can write only the checkout, $TMPDIR and a "
    "private scratch $HOME."
)


def _reject(message: str) -> RestrictedPytestError:
    return RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, message)


def worktree_add_parts(command: str, *, workspace: Path, home: Path | None) -> tuple[str, str] | None:
    """The add and the `cd <checkout> && <checks>` after it, as Rust split them."""
    answer = native_contained_wrapper_plan(command, workspace=workspace, cwd=workspace, home=home)
    parts = answer.get("worktree_add")
    if not isinstance(parts, Mapping):
        return None
    add, entered = parts.get("add"), parts.get("entered")
    if not isinstance(add, str) or not isinstance(entered, str) or not add or not entered:
        return None
    return add, entered


def checkout_of(entered: str, *, workspace: Path, home: Path | None) -> Path | None:
    """The directory `cd <checkout> && <checks>` enters, resolved from `workspace`."""
    lexer = shlex.shlex(entered, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    # The shell reads `#` inside a word as part of it, as in `../app#fix`.
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    if len(tokens) < 4 or tokens[0] != "cd" or tokens[2] != "&&" or not tokens[1]:
        return None
    target = tokens[1]
    # The shell expands only an unquoted `~`.
    if target.startswith("~") and not entered[2:].lstrip().startswith("~"):
        return None
    if target == "~" or target.startswith("~/"):
        if home is None:
            return None
        target = str(home) + target[1:]
    elif target.startswith("~"):
        return None
    return Path(os.path.normpath(workspace / target))


def _same_chain(receipt: object, first: Mapping[str, object]) -> bool:
    return (
        isinstance(receipt, Mapping)
        and receipt.get("decision") == "deny"
        and receipt.get("policy_action") == "sandbox-required"
        and receipt.get("reason") == WORKTREE_ADD_REASON
        and receipt.get("observe_mode") is not True
        and isinstance(receipt.get("command_binding_digest"), str)
        and receipt.get("command_binding_digest") == first.get("command_binding_digest")
    )


def _allowed(verdict: object) -> bool:
    return (
        isinstance(verdict, Mapping)
        and verdict.get("decision") == "allow"
        and verdict.get("policy_action") == "allow"
        and verdict.get("observe_mode") is not True
    )


def run_worktree_add(
    payload: dict[str, object],
    *,
    workspace: Path,
    authorize: Callable[[dict[str, object]], object],
    first_receipt: Mapping[str, object],
    home_dir: Path | None,
    timeout_seconds: int,
    merge_stderr: bool,
) -> int:
    """Run the proven add on the host, then the rest in the new checkout as judged again."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
        raise _reject("Invalid workspace sandbox request.")
    if sys.platform not in {"darwin", "linux"}:
        raise _reject("Guard creates a worktree before contained checks only on macOS and Linux.")
    try:
        parts = worktree_add_parts(tool_input["command"], workspace=workspace, home=home_dir)
    except (OSError, RuntimeError, ValueError) as error:
        raise _reject("Guard could not split this command again; nothing ran.") from error
    if parts is None:
        raise _reject("Guard could not split this command again; nothing ran.")
    add, entered = parts
    checkout = checkout_of(entered, workspace=workspace, home=home_dir)
    if checkout is None:
        raise _reject("Guard could not read the new checkout from this command; nothing ran.")
    # The chain must still carry the receipt it was routed here with.
    if not _same_chain(settled_authority(authorize, payload), first_receipt):
        raise _reject("The command evidence changed before launch.")
    if not _allowed(settled_authority(authorize, {**payload, "tool_input": {**tool_input, "command": add}})):
        raise _reject("Guard could not prove the `git worktree add` again; nothing ran.")
    exit_code = run_on_host(
        add,
        cwd=workspace,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        merge_stderr=merge_stderr,
        label="The `git worktree add`",
        excluded=(checkout,),
    )
    if exit_code != 0:
        return exit_code
    rest = {**payload, "tool_input": {**tool_input, "command": entered}}
    if _allowed(settled_authority(authorize, rest)):
        return run_on_host(
            entered,
            cwd=workspace,
            workspace=workspace,
            timeout_seconds=timeout_seconds,
            merge_stderr=merge_stderr,
            label="The rest of the command",
            excluded=(checkout,),
        )
    # Imported here: the contained route imports the sink that calls this.
    from .contained_test_hook import run_authorized_contained_test

    try:
        return run_authorized_contained_test(
            rest,
            workspace=workspace,
            authorize=authorize,
            timeout_seconds=timeout_seconds,
            cwd=workspace,
            home_dir=home_dir,
            merge_stderr=merge_stderr,
        )
    except RestrictedPytestError as error:
        raise RestrictedPytestError(
            error.reason_code,
            f"{error} The worktree was created first; run `{entered}` as a command of its own to retry the rest.",
            exit_code=error.exit_code,
        ) from error
