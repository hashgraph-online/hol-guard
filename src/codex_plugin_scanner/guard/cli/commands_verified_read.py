"""Production CLI boundary for Guard-owned verified reads."""

from __future__ import annotations

import json
import sys
from typing import TextIO, cast

from ..runtime.verified_github_reads import try_read_verified_public_github_pull_request
from ..runtime.verified_read_execution import try_execute_verified_local_read


def _run_guard_verified_read_command(
    args: object,
    *,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    **_kwargs: object,
) -> int:
    """Execute one supported read entirely inside Guard or fail closed."""

    del input_text
    output = output_stream or sys.stdout
    command = cast(object, getattr(args, "verified_read_command", None))
    json_output = cast(object, getattr(args, "json", False)) is True
    if command == "local":
        raw_argv = cast(object, getattr(args, "read_argv", None))
        if not isinstance(raw_argv, list):
            return 2
        untyped_argv = cast(list[object], raw_argv)
        if any(not isinstance(value, str) for value in untyped_argv):
            return 2
        values = tuple(cast(list[str], raw_argv))
        argv = values[1:] if values[:1] == ("--",) else values
        result = try_execute_verified_local_read(argv)
    elif command == "github-pr":
        owner = cast(object, getattr(args, "owner", None))
        repository = cast(object, getattr(args, "repository", None))
        number = cast(object, getattr(args, "number", None))
        raw_fields = cast(object, getattr(args, "field", None))
        if not isinstance(owner, str) or not isinstance(repository, str) or type(number) is not int:
            return 2
        if raw_fields is not None:
            if not isinstance(raw_fields, list):
                return 2
            if any(not isinstance(field, str) for field in cast(list[object], raw_fields)):
                return 2
        fields = cast(list[str] | None, raw_fields)
        result = try_read_verified_public_github_pull_request(
            owner,
            repository,
            number,
            fields=tuple(fields or ("number", "state", "mergeable")),
        )
    else:
        return 2
    if result is None:
        print("Guard could not prove this read; request review instead.", file=sys.stderr)
        return 2
    if json_output:
        print(
            json.dumps(
                {
                    "decision": result.decision.disposition.value,
                    "operation": result.operation_id,
                    "output": result.stdout,
                    "proof": result.proof.binding_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=output,
        )
    else:
        print(result.stdout, end="", file=output)
    return 0


__all__ = ["_run_guard_verified_read_command"]
