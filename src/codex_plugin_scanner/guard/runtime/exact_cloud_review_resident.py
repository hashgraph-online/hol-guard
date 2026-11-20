"""Ask the resident runtime the exact Cloud Review questions a helper would answer.

A Review job asks the runtime several times while it holds the store: the job
identity, the capability check, the capability digest and the apply step.
Spawning an ``exact-cloud-review`` helper for each question costs more than the
question, so a resident this process already talks to answers instead. The
resident runs the helper's own ``answer`` function on the same request.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ..store import GuardStore

RESIDENT_FEATURE = "native-exact-cloud-review-resident-v1"
_REQUEST_SCHEMA = "guard-exact-cloud-review-resident-request.v1"
_RESULT_SCHEMA = "guard-exact-cloud-review-resident-result.v1"


def resident_exact_cloud_review_answer(
    request: dict[str, object], store: GuardStore | None
) -> dict[str, object] | None:
    """The resident's answer, or None when only a spawned helper can answer.

    Only a resident this process already talks to answers: a decision must
    never wait for one to start.
    """

    guard_home = getattr(store, "guard_home", None)
    if guard_home is None:
        return None
    from .. import native_execution
    from ..native_resident_client import native_resident_client_ready

    try:
        status = native_execution.native_runtime_status()
        if status.identity is None or not native_resident_client_ready(status.identity.path, Path(guard_home)):
            return None
        response = native_execution._resident_request(  # pyright: ignore[reportPrivateUsage]
            operation="exact_cloud_review",
            request={"schema": _REQUEST_SCHEMA, "request": request},
            guard_home=Path(guard_home),
            timeout_seconds=10.0,
            required_feature=RESIDENT_FEATURE,
            response_schema=_RESULT_SCHEMA,
            status=status,
        )
    except (OSError, RuntimeError):
        return None
    answer = None if response is None else response.get("answer")
    return cast("dict[str, object]", answer) if isinstance(answer, dict) else None


__all__ = ["RESIDENT_FEATURE", "resident_exact_cloud_review_answer"]
