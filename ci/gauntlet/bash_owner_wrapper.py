"""Validate the installed native Bash owner's exact adapter argv for evidence binding."""

from __future__ import annotations

import re
import shlex
from pathlib import Path


def normalized_argv(command: object, call_id: str) -> tuple[list[str] | None, str | None]:
    """Return the common request-binding fields only after checking every owner argument."""
    error = "native Bash wrapper is not the canonical case-owned execution sink"
    if not isinstance(command, str) or len(command) > 32_768:
        return None, error
    try:
        argv = shlex.split(command)
    except ValueError:
        return None, error
    canonical = " ".join("'" + value.replace("'", "'\\''") + "'" for value in argv)
    if len(argv) != 22 or command != canonical:
        return None, error
    flags = {
        1: "execute-bound-bash",
        2: "--harness",
        4: "--operation-id",
        6: "--host-owner-pid",
        8: "--tool-call-id",
        10: "--guard-home",
        12: "--workspace",
        14: "--request-file",
        16: "--request-sha256",
        18: "--timeout-seconds",
        20: "--home",
    }
    request = Path(argv[15])
    if (
        any(argv[index] != flag for index, flag in flags.items())
        or not argv[0].startswith("/")
        or Path(argv[0]).name != "hol-guard"
        or argv[3] != "omp"
        or re.fullmatch(r"bash-operation:[0-9a-f]{64}", argv[5]) is None
        or len(argv[7]) > 10
        or not argv[7].isascii()
        or not argv[7].isdigit()
        or not 1 < int(argv[7]) <= 2**31 - 1
        or argv[9] != call_id
        or argv[11] != "{{fixture}}/guard-home"
        or argv[13] != "{{workspace}}"
        or not request.is_absolute()
        or request.name != "request.json"
        or not request.parent.name.startswith("hol-guard-contained-test-")
        or re.fullmatch(r"[0-9a-f]{64}", argv[17]) is None
        or len(argv[19]) > 3
        or not argv[19].isascii()
        or not argv[19].isdigit()
        or not 1 <= int(argv[19]) <= 120
        or argv[21] != "{{home}}"
    ):
        return None, error
    return [
        argv[0],
        argv[1],
        argv[10],
        argv[11],
        argv[12],
        argv[13],
        argv[14],
        argv[15],
        argv[16],
        argv[17],
        argv[20],
        argv[21],
    ], None
