"""Validate bubblewrap's private execution-status channel."""

from __future__ import annotations

import json
from typing import BinaryIO, cast

_STATUS_LIMIT = 8192


def bwrap_execution_completed(stream: BinaryIO, exit_code: int | None) -> bool:
    """Require the exec-success report, not merely a forked sandbox process.

    Bubblewrap emits child-pid before setup completes. It emits exit-code only
    after a successful exec. The caller owns an unlinked file outside the
    snapshot, and bubblewrap closes this descriptor in the application process.
    Neither application stdout nor a writable snapshot file is evidence.
    """

    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        return False
    _ = stream.seek(0)
    payload = stream.read(_STATUS_LIMIT + 1)
    if len(payload) > _STATUS_LIMIT:
        return False
    child_seen = False
    exit_seen = False
    try:
        for line in payload.splitlines():
            record = cast(object, json.loads(line))
            if not isinstance(record, dict):
                return False
            if "child-pid" in record:
                pid = record["child-pid"]
                if child_seen or exit_seen or type(pid) is not int or pid <= 0:
                    return False
                child_seen = True
            if "exit-code" in record:
                status = record["exit-code"]
                if not child_seen or exit_seen or type(status) is not int or status != exit_code:
                    return False
                exit_seen = True
    except (ValueError, UnicodeError):
        return False
    return child_seen and exit_seen
