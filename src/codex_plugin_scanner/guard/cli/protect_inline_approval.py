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
import select
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
_GUIDANCE_KEYS = (
    "_ephemeral_signed_approval_url",
    "approval_request_ids",
    "approval_resume",
    "primary_approval_url",
    "request",
    "supply_chain",
    "supply_chain_evaluation",
    "verdict",
)
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


def protect_guidance(
    payload: Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
    emphasis: bool = False,
) -> dict[str, object] | None:
    """Ask the native runtime what a paused install tells the person or agent that ran it.

    The answer carries the queued ``request_ids``, the inline ``prompt``, and the
    guidance panel's ``title`` and ``guidance`` lines. ``None`` without the runtime.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            "protect_guidance",
            {
                "payload": {key: payload.get(key) for key in _GUIDANCE_KEYS},
                "from_agent": approval_resolution_invoked_from_agent(env if env is not None else os.environ),
                "emphasis": emphasis,
            },
        )
    except NativeRunnerAuthorityError:
        return None
    return answer if isinstance(answer, dict) else None


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
    descriptor = terminal_status_fd(source_env)
    input_stream = stdin if stdin is not None else sys.stdin
    try:
        interactive = input_stream.isatty()
    except (AttributeError, OSError, ValueError):
        interactive = False
    if descriptor is None or not interactive:
        return None
    guidance = protect_guidance(payload, env=source_env, emphasis="NO_COLOR" not in source_env) or {}
    request_ids = guidance.get("request_ids")
    prompt = guidance.get("prompt")
    if not isinstance(request_ids, list) or len(request_ids) != 1 or not isinstance(prompt, str):
        return None
    request_id = str(request_ids[0])
    _write(descriptor, prompt)
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


def human_protect_guidance(
    payload: Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
) -> tuple[str, list[str]]:
    """Panel title and lines: approval steps for a person, the agent guidance otherwise.

    The agent guidance tells a harness to wait and not retry, which reads as a dead
    end to a person at a terminal. The approval page link from it is kept, first.
    """

    answer = protect_guidance(payload, env=env) or {}
    title = answer.get("title")
    lines = answer.get("guidance")
    if not isinstance(title, str) or not isinstance(lines, list):
        return "Guard guidance", []
    return title, [line for line in lines if isinstance(line, str)]


__all__ = [
    "human_protect_guidance",
    "inline_package_approval",
    "protect_guidance",
    "terminal_status_fd",
]
