"""Verify native pending review before the normal approval writer stores consent."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .native_approval_resolution import ApprovalResolutionPlanUnavailableError
from .native_bash_protocol import (
    ARTIFACT_ID,
    ARTIFACT_TYPE,
    LEGACY_ARTIFACT_IDS,
    NativeBashError,
    request_id,
    verify_review_request,
)

if TYPE_CHECKING:
    from .store import GuardStore


def require_verified_bash_review(
    store: GuardStore,
    request: Mapping[str, object],
    *,
    require_execution: bool = True,
) -> None:
    envelope = request.get("action_envelope_json")
    descriptor = envelope.get("native_bash") if isinstance(envelope, Mapping) else None
    reserved = (
        request.get("artifact_id") in (ARTIFACT_ID, *LEGACY_ARTIFACT_IDS)
        or request.get("artifact_type") == ARTIFACT_TYPE
        or (isinstance(envelope, Mapping) and "native_bash" in envelope)
    )
    if not reserved:
        return
    if (
        request.get("artifact_type") != ARTIFACT_TYPE
        or request.get("artifact_id") != ARTIFACT_ID
        or not isinstance(descriptor, dict)
        or not isinstance(request.get("raw_command_text"), str)
        or not isinstance(request.get("request_id"), str)
        or not isinstance(request.get("harness"), str)
        or request.get("artifact_hash") != descriptor.get("artifact_hash")
    ):
        if require_execution:
            raise ApprovalResolutionPlanUnavailableError("execution_binding_unavailable")
        return
    try:
        verify_review_request(
            {
                "schema": "guard-native-bash-review-check-request.v1",
                "request_id": request_id(),
                "guard_home": str(store.guard_home),
                "store_path": str(store.path),
                "approval_request_id": request["request_id"],
                "harness": request["harness"],
                "command": request["raw_command_text"],
                "descriptor": descriptor,
            },
            guard_home=store.guard_home,
        )
    except NativeBashError as error:
        if require_execution:
            raise ApprovalResolutionPlanUnavailableError("execution_binding_unavailable") from error
