"""Reap a resident native client whose stream closed and log unexpected exits."""

from __future__ import annotations

import logging
import subprocess
from contextlib import suppress

logger = logging.getLogger(__name__)

_CLIENT_REAP_TIMEOUT_SECONDS = 2.0


def reap_exited_client(process: subprocess.Popen[bytes], *, retired: bool) -> None:
    """Collect a client's exit status and log it unless Guard retired the client.

    Without this the child stays a zombie until the next request replaces it,
    and an immediate exit (for example a resident identity mismatch) leaves no
    trace in any log. ``retired`` must be decided when the stream closed, before
    any request can observe the failure and start closing the client, so a crash
    is still logged when teardown follows it. A signal exit Guard did not send is
    unexpected and is logged too.
    """

    try:
        code = process.wait(timeout=_CLIENT_REAP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        return
    if retired or code == 0:
        return
    with suppress(Exception):
        logger.warning("native_client_exited returncode=%s", code)
