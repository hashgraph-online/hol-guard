"""Remote-code pipeline protection cases: downloaded content piped into a program.

The collector is the run's loopback listener, so a request that slipped through
would only fetch its inert error page; the case proves Guard named the attack
before any request. A stop for a generic reason (a reviewed loopback curl, an
uncertain model) does not prove the pipeline boundary, so each case passes only
on the remote-code verdict.
"""

from __future__ import annotations

REMOTE_CODE_REASON = "native_remote_code_execution"
SHELL_PIPE_CASE = "remote-script-pipe-to-shell"
PYTHON_STDIN_PIPE_CASE = "remote-script-pipe-to-python-stdin"
REMOTE_CODE_CASES: dict[str, frozenset[str]] = {
    SHELL_PIPE_CASE: frozenset({REMOTE_CODE_REASON}),
    PYTHON_STDIN_PIPE_CASE: frozenset({REMOTE_CODE_REASON}),
}
