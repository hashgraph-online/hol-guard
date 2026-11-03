"""Let the person at the terminal approve a paused package install on the spot.

A package shim runs ``hol-guard protect --package-shim-ui`` with the terminal's
stdin and a duplicate of its stderr (``HOL_GUARD_PACKAGE_SHIM_STATUS_FD``). When
both are terminals and no AI harness marker is present, Guard asks there instead
of sending the person to a separate inbox, then resolves the queued request
through the same path as ``hol-guard approvals approve``. A decision made in the
approval center or desktop app while the prompt is open ends the prompt too.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import select
import shlex
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..package_shim_status import PACKAGE_SHIM_STATUS_FD_ENV_VAR
from ..runtime.self_approval import approval_resolution_invoked_from_agent

if TYPE_CHECKING:
    from ..store import GuardStore

_POLL_SECONDS = 0.5
_URL = re.compile(r"https?://[^\s<>\"'`]+")
_ANSWERS: dict[str, tuple[str, bool] | None] = {
    "y": ("once", False),
    "yes": ("once", False),
    "o": ("once", False),
    "once": ("once", False),
    "a": ("always", True),
    "always": ("always", True),
    "n": None,
    "no": None,
    "": None,
}


def pending_protect_request_ids(payload: Mapping[str, object]) -> list[str]:
    """Return the approval request ids this protect run queued, in either approval mode."""

    queued_ids = payload.get("approval_request_ids")
    if isinstance(queued_ids, list):
        ids = [item for item in queued_ids if isinstance(item, str) and item]
        if ids:
            return ids
    resume = payload.get("approval_resume")
    request_id = resume.get("request_id") if isinstance(resume, Mapping) else None
    return [request_id] if isinstance(request_id, str) and request_id else []


def terminal_status_fd(env: Mapping[str, str] | None = None) -> int | None:
    """The shim's real stderr when it is an interactive terminal."""

    value = (env if env is not None else os.environ).get(PACKAGE_SHIM_STATUS_FD_ENV_VAR)
    if not value:
        return None
    try:
        descriptor = int(value)
        return descriptor if os.isatty(descriptor) else None
    except (OSError, OverflowError, ValueError):
        return None


def _terminal_safe(text: str) -> str:
    """Show control characters from request text as ``?`` so they cannot restyle the prompt."""

    return "".join(character if character.isprintable() else "?" for character in text)


def protect_command_text(payload: Mapping[str, object]) -> str:
    """The install as a person would type it again, quoted for a POSIX shell.

    The manager is named by its basename: an external-archive shim sends the
    resolved real manager's path, and typing that would skip the shim.
    """

    request = payload.get("request")
    command = request.get("command") if isinstance(request, Mapping) else None
    if isinstance(command, str):
        return _terminal_safe(command.strip())
    if not isinstance(command, list):
        return ""
    argv = [part for part in command if isinstance(part, str)]
    if not argv:
        return ""
    argv[0] = os.path.basename(argv[0]) or argv[0]
    return _terminal_safe(shlex.join(argv))


def _reason(payload: Mapping[str, object]) -> str:
    verdict = payload.get("verdict")
    reason = verdict.get("reason") if isinstance(verdict, Mapping) else None
    return _terminal_safe(reason.strip()) if isinstance(reason, str) else ""


def _prompt_text(payload: Mapping[str, object], *, emphasis: bool) -> str:
    title = "HOL Guard paused this install before it ran."
    if emphasis:
        title = f"\033[1m{title}\033[0m"
    lines = ["", title]
    command = protect_command_text(payload)
    if command:
        lines.append(f"  {command}")
    reason = _reason(payload)
    if reason:
        lines.append(f"  {reason}")
    lines.extend(
        [
            "",
            "  y  Allow once",
            "  a  Always allow this exact install (Guard asks again if the package changes)",
            "  n  Keep it blocked",
            "",
            "Allow this install? [y/a/N] ",
        ]
    )
    return "\n".join(lines)


def _write(descriptor: int, text: str) -> None:
    with contextlib.suppress(OSError):
        os.write(descriptor, text.encode("utf-8"))


def _read_answer(
    *,
    stdin: TextIO,
    request_id: str,
    store: GuardStore,
    timeout_seconds: float,
    clock: Callable[[], float],
) -> tuple[str, str | None]:
    """Wait for a typed answer or a decision recorded elsewhere, whichever comes first."""

    deadline = clock() + timeout_seconds
    while True:
        item = store.get_approval_request(request_id)
        if isinstance(item, Mapping) and str(item.get("status") or "") == "resolved":
            return "elsewhere", str(item.get("resolution_action") or "")
        remaining = deadline - clock()
        if remaining <= 0:
            return "timeout", None
        try:
            ready, _, _ = select.select([stdin], [], [], min(_POLL_SECONDS, remaining))
        except (OSError, ValueError):
            return "unreadable", None
        if ready:
            line = stdin.readline()
            if line == "":
                return "unreadable", None
            return "typed", line.strip().lower()


def _approve(
    request_id: str,
    *,
    remember: bool,
    store: GuardStore,
    workspace: Path,
) -> dict[str, object]:
    from .approval_commands import run_approval_command

    args = argparse.Namespace(
        approvals_command="approve",
        request_id=request_id,
        approval_action="allow",
        scope="artifact",
        reason="Approved in the terminal that ran the install.",
        remember=remember,
        trust_local_tool=False,
    )
    return run_approval_command(args, store=store, workspace=workspace)


def _kept_blocked(request_id: str) -> dict[str, object]:
    return {"resolved": False, "items": [{"request_id": request_id, "resolution_action": "pending"}]}


def _resolved_elsewhere(descriptor: int, request_id: str, resolution: str) -> dict[str, object]:
    if resolution == "block":
        _write(descriptor, "\nBlocked in HOL Guard.\n")
        return _kept_blocked(request_id)
    _write(descriptor, "\nApproved in HOL Guard. Running the install.\n")
    return {"resolved": True, "items": [{"request_id": request_id, "resolution_action": resolution or "allow"}]}


def inline_package_approval(
    payload: Mapping[str, object],
    *,
    store: GuardStore,
    workspace: Path,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object] | None:
    """Ask at the terminal and return an approval-wait result.

    Returns ``None`` without prompting when the run is not interactive, came from
    an AI harness, or queued anything other than exactly one request; the caller
    then falls back to its own wait. Once the person was asked, the result says
    whether the request was approved.
    """

    source_env = env if env is not None else os.environ
    if approval_resolution_invoked_from_agent(source_env):
        return None
    request_ids = pending_protect_request_ids(payload)
    if len(request_ids) != 1:
        return None
    descriptor = terminal_status_fd(source_env)
    input_stream = stdin if stdin is not None else sys.stdin
    try:
        interactive = input_stream.isatty()
    except (AttributeError, OSError, ValueError):
        interactive = False
    if descriptor is None or not interactive:
        return None
    request_id = request_ids[0]
    _write(descriptor, _prompt_text(payload, emphasis="NO_COLOR" not in source_env))
    outcome, value = _read_answer(
        stdin=input_stream,
        request_id=request_id,
        store=store,
        timeout_seconds=max(timeout_seconds, 1.0),
        clock=clock,
    )
    if outcome == "elsewhere":
        return _resolved_elsewhere(descriptor, request_id, value or "")
    if outcome != "typed":
        _write(descriptor, "\nNo answer, so the install stays blocked.\n")
        return _kept_blocked(request_id)
    answer = value or ""
    if answer not in _ANSWERS:
        _write(descriptor, "Not a choice, so the install stays blocked.\n")
        return _kept_blocked(request_id)
    choice = _ANSWERS[answer]
    if choice is None:
        _write(descriptor, "Kept blocked.\n")
        return _kept_blocked(request_id)
    label, remember = choice
    result = _approve(request_id, remember=remember, store=store, workspace=workspace)
    if result.get("resolved") is not True:
        current = store.get_approval_request(request_id)
        if isinstance(current, Mapping) and str(current.get("status") or "") == "resolved":
            # Someone decided in the approval center between the last check and this answer.
            return _resolved_elsewhere(descriptor, request_id, str(current.get("resolution_action") or ""))
        detail = result.get("message") or result.get("error") or "unknown error"
        _write(descriptor, f"Guard could not record the approval ({detail}). The install stays blocked.\n")
        return _kept_blocked(request_id)
    if label == "always":
        _write(descriptor, "Always allowed. Running the install.\n")
    else:
        _write(descriptor, "Allowed once. Running the install.\n")
    return {"resolved": True, "items": [{"request_id": request_id, "resolution_action": "allow"}]}


def approval_step_lines(payload: Mapping[str, object], *, env: Mapping[str, str] | None = None) -> list[str]:
    """Commands that approve a paused install later, for output nobody could answer inline."""

    if approval_resolution_invoked_from_agent(env if env is not None else os.environ):
        return []
    request_ids = pending_protect_request_ids(payload)
    if len(request_ids) != 1:
        return []
    verdict = payload.get("verdict")
    action = verdict.get("action") if isinstance(verdict, Mapping) else None
    if action not in {"review", "require-reapproval"}:
        return []
    request_id = request_ids[0]
    lines = [
        f"Approve once:   hol-guard approvals approve {request_id}",
        f"Always allow:   hol-guard approvals approve {request_id} --remember",
        "Or decide in the approval center: hol-guard approvals",
    ]
    command = protect_command_text(payload)
    if command:
        lines.append(f"Then run it again: {command}")
    supply_chain = payload.get("supply_chain")
    bundle = supply_chain.get("bundle") if isinstance(supply_chain, Mapping) else None
    if isinstance(supply_chain, Mapping) and not (isinstance(bundle, Mapping) and bundle.get("workspace_id")):
        lines.append("Sign in to Guard Cloud for package intelligence and phone approvals: hol-guard connect")
    return lines


def human_protect_guidance(
    payload: Mapping[str, object],
    guidance: list[str],
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[str, list[str]]:
    """Panel title and lines: approval steps for a person, the agent guidance otherwise.

    The agent guidance tells a harness to wait and not retry, which reads as a dead
    end to a person at a terminal. The approval page link from it is kept, first.
    """

    steps = approval_step_lines(payload, env=env)
    if not steps:
        return "Guard guidance", guidance
    link = _approval_link(guidance)
    return "Approve this install", [*([f"Approve in the browser: {link}"] if link else []), *steps]


def _approval_link(guidance: list[str]) -> str:
    """The approval page from the agent guidance, preferring its explicit review link."""

    ordered = sorted(guidance, key=lambda line: not line.startswith("Review: "))
    for line in ordered:
        match = _URL.search(line)
        if match:
            return match.group(0).rstrip(".,;:)]")
    return ""


__all__ = [
    "approval_step_lines",
    "human_protect_guidance",
    "inline_package_approval",
    "pending_protect_request_ids",
    "protect_command_text",
    "terminal_status_fd",
]
