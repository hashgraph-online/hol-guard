"""Record actual SDK result delivery against authenticated native completion."""

from __future__ import annotations

import time
from pathlib import Path

from .native_bash_protocol import NativeBashError, encode, request_id, runtime_status
from .native_context import _canonical_request_sha256
from .native_execution import _resident_request
from .native_runtime_resilience import native_record_resident_success

FEATURE = "native-bash-invocation-lifetime-v1"
_RETRY_DELAY_SECONDS = 0.05


def acknowledge(
    *, guard_home: Path, store_path: Path, base_id: str, harness: str, project: Path, tool_call_id: str, exit_code: int
) -> bool:
    request: dict[str, object] = {
        "schema": "guard-native-bash-ack-request.v1",
        "request_id": request_id(),
        "guard_home": str(guard_home),
        "store_path": str(store_path),
        "base_id": base_id,
        "harness": harness,
        "project": str(project),
        "tool_call_id": tool_call_id,
        "exit_code": exit_code,
    }
    encode(request)
    status = runtime_status()
    for attempt in range(2):
        result = _resident_request(
            operation="native_bash_ack",
            request=request,
            guard_home=guard_home,
            timeout_seconds=6,
            required_feature=FEATURE,
            response_schema="guard-native-bash-ack-result.v1",
            status=status,
            max_request_bytes=16 * 1024,
            record_success=False,
        )
        if (
            isinstance(result, dict)
            and set(result) == {"schema", "request_id", "request_sha256", "status", "code", "acknowledged"}
            and result.get("schema") == "guard-native-bash-ack-result.v1"
            and result.get("request_id") == request["request_id"]
            and result.get("request_sha256") == "sha256:" + _canonical_request_sha256(request)
            and result.get("status") == "ok"
            and result.get("code") == "ok"
            and type(result.get("acknowledged")) is bool
        ):
            if status.identity is None:
                raise NativeBashError("native_bash_ack_unavailable")
            native_record_resident_success(status.identity.sha256, guard_home)
            return bool(result["acknowledged"])
        if attempt == 0:
            time.sleep(_RETRY_DELAY_SECONDS)
    raise NativeBashError("native_bash_ack_unavailable")
