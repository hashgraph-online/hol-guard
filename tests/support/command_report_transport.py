"""Send Guard command acks and results over the command queue's request functions in unit tests.

The native ``cloud-event-sync`` command sends each leased job's ack and result
itself, so a test that fakes ``command_queue._exact_json_request`` or
``command_queue._json_request`` would otherwise never see them. This double
replays the native report over those functions: the same paths and bodies.

The native report is tested in
``rust/crates/guard-runtime/src/cloud_command_report_tests.rs``; mark a test
``native_command_report`` to run the real command.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

_EXACT_PROTOCOL_VERSION = 2


def command_report_over_command_queue(
    auth_context: Mapping[str, object],
    *,
    job_id: str,
    exact: bool,
    kind: str,
    lease_id: str | None = None,
    body: bytes | None = None,
) -> dict[str, object]:
    """Report the way the Python command queue did before the native command."""

    from codex_plugin_scanner.guard.runtime import command_queue

    request = command_queue._exact_json_request if exact else command_queue._json_request
    if kind == "ack":
        if lease_id is None or body is not None:
            raise AssertionError("an ack carries its lease id and no body")
        payload: dict[str, object] = {"leaseId": lease_id}
        if exact:
            payload["protocolVersion"] = _EXACT_PROTOCOL_VERSION
        path = f"/{job_id}/ack" if exact else f"/{job_id}/heartbeat"
    elif kind == "result":
        if lease_id is not None or body is None:
            raise AssertionError("a result carries its body and no lease id")
        payload = json.loads(body)
        path = f"/{job_id}/result"
    else:
        raise AssertionError(f"unknown command report kind: {kind}")
    return dict(request(dict(auth_context), method="POST", path=path, payload=payload))
