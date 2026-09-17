"""Flow and segment helpers for shell secret-read assessment."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from ._shell_execution_context_support import split_shell_tokens
from ._shell_secret_read_support import (
    _FLOW_OPERATORS,
    _OTHER_READERS,
    _SHELLS,
    _SHORT_CIRCUITING_CD_FAILURES,
    _path_qualified,
    _python_executable,
)
from .command_model import CanonicalCommand, CommandSegment
from .shell_execution_context import ShellExecutionSegment


def _parse_execution_segment(
    execution: ShellExecutionSegment,
    *,
    raw_model: CanonicalCommand,
    raw_segment: CommandSegment | None,
) -> CanonicalCommand | None:
    """Keep source syntax and require agreement with the cwd model.

    Re-quoting decoded tokens changes input redirections into ordinary argv
    and can erase command/exec ambiguity. The raw command parser deliberately
    skips transparent-wrapper normalization for this inspection path.
    """

    if not execution.complete or execution.effective_cwd is None or raw_segment is None:
        return None
    try:
        if split_shell_tokens(raw_segment.text) != execution.tokens:
            return None
    except ValueError:
        return None
    return replace(
        raw_model,
        segments=(raw_segment,),
        redirects=tuple(
            redirect
            for redirect in raw_model.redirects
            if raw_segment.start <= redirect.start and redirect.end <= raw_segment.end
        ),
        embedded_commands=(),
    )


def _segment_may_touch_local_data(execution: ShellExecutionSegment) -> bool:
    """Keep unknown file/code access closed without treating stdout as a file."""

    from .secret_file_request_services.local_read_operands import _shell_segment_file_operand_tokens

    if not execution.tokens:
        return False
    token = execution.tokens[0]
    executable = "." if token == "." else Path(token).name.lower()
    args = list(execution.tokens[1:])
    has_input_redirect = any(re.match(r"^\d*<(?!<)", item) for item in execution.tokens)
    if has_input_redirect or _shell_segment_file_operand_tokens([executable, *args]):
        return True
    if executable in _OTHER_READERS:
        return any(not arg.startswith("-") for arg in args)
    return (
        executable in {*_SHELLS, "command", "exec", "node", "bun", "ruby", "perl"}
        or _python_executable(executable)
        or _path_qualified(token)
    )


def _flow_operator_before(execution: ShellExecutionSegment) -> str | None:
    return next((token for token in reversed(execution.control_before) if token in _FLOW_OPERATORS), None)


def _failed_cd_short_circuit_state(
    execution: ShellExecutionSegment,
    *,
    active: bool,
) -> tuple[bool, bool]:
    """Return the failed-cd state and whether this segment is provably unreachable."""

    operator = _flow_operator_before(execution)
    if operator in {"||", ";", "&", "|"}:
        active = False
    if execution.directory_operation is not None and execution.reason_code in _SHORT_CIRCUITING_CD_FAILURES:
        return True, False
    return active, bool(active and operator == "&&")
