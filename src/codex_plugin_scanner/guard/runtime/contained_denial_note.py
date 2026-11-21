"""The note a failed workspace-contained run gets when its output names a denial.

The native runtime reads the output (the `contained_denial_note` runner
authority kind) with the reading its own workspace sink uses: the first line
that names what the sandbox blocked picks the note, and a denial with no
clearer cause gets the generic note. A note only explains a failure the run
already has, so when the native runtime cannot answer, the run gets no note.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable

# Two outputs of the 1 MiB a sandbox replays fit the request bound once encoded.
_MAX_OUTPUT_BYTES = 2 * 1_048_576


def denial_answer(outputs: Iterable[bytes]) -> tuple[str | None, bool]:
    """The note for `outputs` read in order, and whether one names a blocked loopback connection."""
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    encoded: list[str] = []
    budget = _MAX_OUTPUT_BYTES
    for output in outputs:
        if budget <= 0:
            break
        encoded.append(base64.b64encode(output[:budget]).decode("ascii"))
        budget -= len(output)
    try:
        answer = native_runner_authority("contained_denial_note", {"outputs": encoded})
    except NativeRunnerAuthorityError:
        return None, False
    note = answer.get("note")
    return (note if isinstance(note, str) else None), answer.get("loopback_denied") is True


def denial_note(outputs: Iterable[bytes]) -> str | None:
    """The note for `outputs`, read in order, or None when none names a denial."""
    return denial_answer(outputs)[0]
