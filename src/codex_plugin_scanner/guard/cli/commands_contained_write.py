"""Production CLI boundary for Guard-owned contained workspace writes."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO, cast

from ..contained_workspace_write_execution import (
    ContainedWriteOperation,
    try_execute_contained_workspace_write,
)

_CLI_OPERATIONS: dict[str, ContainedWriteOperation] = {
    "patch-check": "patch-check",
    "patch-apply": "patch-apply",
    "format": "format-write",
    "copy": "copy-generated",
}


def _run_guard_contained_write_command(
    args: object,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    **_kwargs: object,
) -> int:
    """Execute and promote one exact contained workspace operation."""

    del input_text
    output = output_stream or sys.stdout
    command = cast(object, getattr(args, "contained_write_command", None))
    source = cast(object, getattr(args, "source", None))
    target = cast(object, getattr(args, "target", None))
    if command not in _CLI_OPERATIONS or not isinstance(source, str):
        return 2
    if target is not None and not isinstance(target, str):
        return 2
    if command == "format" and target is None:
        target = source
    if guard_home is None:
        return 2
    result = try_execute_contained_workspace_write(
        _CLI_OPERATIONS[cast(str, command)],
        workspace=(workspace or Path.cwd()).resolve(),
        guard_home=guard_home,
        source=source,
        target=target,
    )
    if result is None:
        print("Guard could not prove this write; request review instead.", file=sys.stderr)
        return 2
    if cast(object, getattr(args, "json", False)) is True:
        print(
            json.dumps(
                {
                    "decision": result.decision.disposition.value,
                    "operation": result.operation_id,
                    "output_digest": result.output_digest,
                    "proof": result.proof.binding_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=output,
        )
    else:
        if result.stdout:
            print(result.stdout, end="", file=output)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    return result.exit_code


__all__ = ["_run_guard_contained_write_command"]
