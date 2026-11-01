"""Running the output filters native authority classified after a contained core.

`contained_output_filters.rs` decides which chain of `| head`, `| tail`,
`| grep` and `| rg` stages a contained command may carry: at most three, each
reading only standard input, with no file operand, pattern file, recursion or
other output, so a stage can only print part of the text it is given. That
grammar lives there alone. This module carries out the chain it chose.

Head and tail run in-process, bounded by lines (`head`, `N`) or by bytes
(`head`, `-c`, `N`). A matcher stage is the native runtime's: it runs the
installed binary, located by ownership rather than by the caller's `PATH`,
with an environment it builds, on the text the core already produced.
"""

from __future__ import annotations

import base64
import binascii

_MATCH_FEATURE = "native-contained-output-match-v1"
_MATCH_COMMAND = "contained-output-match"
_MATCH_SCHEMA = "contained-output-match.v1"
# The runtime's own matcher deadline is 60 seconds; this leaves it room to
# answer before the call gives up.
_MATCH_TIMEOUT_SECONDS = 70.0
_MATCH_OUTPUT_LIMIT = 192 * 1024 * 1024

Stage = tuple[str, ...]


def keep_lines(lines: list[str], kind: str, count: int) -> list[str]:
    if kind == "head":
        return lines[:count]
    # `max(0, ...)` rather than a bare negative start: a count larger than the
    # text keeps all of it, the way `tail -n` does, instead of counting back
    # from the end and dropping the first lines.
    return lines[max(0, len(lines) - count) :] if count else []


def keep_bytes(text: str, kind: str, count: int) -> str:
    """The first or last `count` bytes of `text`, as `head -c`/`tail -c` cut it.

    The cut is made on the encoded bytes, so it lands exactly where the program
    would even in the middle of a character. `surrogateescape` carries a partial
    character through unchanged, so what the sink writes out is the byte string
    the pipeline would have produced.
    """
    data = text.encode("utf-8", "surrogateescape")
    # `max(0, len(data) - count)` rather than `-count`: a zero count keeps
    # nothing instead of keeping everything, and a count larger than the text
    # keeps all of it instead of counting back from the end.
    cut = data[:count] if kind == "head" else data[max(0, len(data) - count) :]
    return cut.decode("utf-8", "surrogateescape")


def _match_lines(text: str, stage: Stage) -> tuple[str, str, int]:
    from ..mdm.runtime_request import runtime_answer

    program, *arguments = stage
    answer = runtime_answer(
        _MATCH_FEATURE,
        _MATCH_COMMAND,
        {
            "schema": _MATCH_SCHEMA,
            "program": program,
            "arguments": arguments,
            "input": base64.b64encode(text.encode("utf-8", "surrogateescape")).decode("ascii"),
        },
        output_limit=_MATCH_OUTPUT_LIMIT,
        timeout_seconds=_MATCH_TIMEOUT_SECONDS,
    )
    if answer is None:
        # The shape was accepted before the core ran, so the core has already
        # done its work: a missing matcher gets the status a shell gives a
        # missing program, not an exception from the wrapper.
        return "", f"hol-guard: {program}: native runtime unavailable\n", 127
    stdout, stderr, status = answer.get("stdout"), answer.get("stderr"), answer.get("status")
    if not isinstance(stdout, str) or not isinstance(stderr, str) or type(status) is not int:
        return "", f"hol-guard: {program}: the output filter did not finish\n", 2
    try:
        output = base64.b64decode(stdout, validate=True)
    except (binascii.Error, ValueError):
        return "", f"hol-guard: {program}: the output filter did not finish\n", 2
    # `surrogateescape` on the matcher's output as well as its input: a byte
    # bound earlier in the chain can hand the matcher a partial character, and
    # the bytes it prints back are the pipeline's bytes.
    return output.decode("utf-8", "surrogateescape"), stderr, status


def apply_filters(text: str, stages: tuple[Stage, ...]) -> tuple[str, str, int]:
    """Run the chain over `text`: (output, matcher diagnostics, last stage's status)."""
    errors: list[str] = []
    status = 0
    for stage in stages:
        if stage[0] in {"head", "tail"}:
            if len(stage) == 3 and stage[1] == "-c":
                text = keep_bytes(text, stage[0], int(stage[2]))
            else:
                text = "".join(keep_lines(text.splitlines(keepends=True), stage[0], int(stage[1])))
            status = 0
            continue
        text, error, status = _match_lines(text, stage)
        errors.append(error)
    return text, "".join(errors), status
