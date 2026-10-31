"""Resident bridge for the ``package_review_plan`` op.

The resident plans how a package review settles: it reads the command the
hook named (Copilot's ``toolArgs`` included), checks it is one plain JS
package-manager install or exec, parses its intent, proves the npm a plain npm
install runs, and builds the request artifact the package evaluator reads. The
caller forwards the hook payload unchanged, evaluates the artifact and applies
the verdict; it never re-derives any part of the plan.

An unavailable or malformed native answer raises
:class:`NativePackageReviewPlanError`. There is no Python fallback, so a
resident that cannot answer leaves the review queued rather than settled.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .models import GuardArtifact
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_package_authority import (
    _EXTRACT_MAX_REQUEST_BYTES,
    _REQUEST_SCHEMA,
    _RESULT_SCHEMA,
    NativePackageArtifactUnavailableError,
    _artifact_from_wire,
    _request_id,
    _resident_request,
)

_PACKAGE_REVIEW_PLAN_FEATURE = "package-review-plan-v1"
_TIMEOUT_SECONDS = 2.0
# The hook payload rides in the request whole, so it takes the bound of the
# other op that carries a whole tool call. A payload the default bound refused
# would leave a blocked package's review approvable.
_MAX_REQUEST_BYTES = _EXTRACT_MAX_REQUEST_BYTES


class NativePackageReviewPlanError(RuntimeError):
    """No authoritative native package review plan was available."""


def package_review_plan(
    payload: Mapping[str, object],
    *,
    harness: str,
    workspace: Path,
    guard_home: Path,
    review_reason: str,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> tuple[GuardArtifact | None, bool]:
    """The artifact the evaluator reads and whether its verdict may allow.

    A ``None`` artifact means the command is not one the evaluator reads, which
    is an answer, not a failure: the caller keeps the review queued. ``False``
    means only a block verdict applies.
    """

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "guard_home": str(guard_home),
        "workspace": str(workspace),
        "harness": harness,
        "payload": dict(payload),
        "home_dir": None if home_dir is None else str(home_dir),
        "review_reason": review_reason,
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageReviewPlanError("Native package review plan request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise NativePackageReviewPlanError("Native package review plan unavailable")
    response = _resident_request(
        operation="package_review_plan",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        deadline_monotonic=deadline,
        required_features=(_PACKAGE_REVIEW_PLAN_FEATURE,),
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativePackageReviewPlanError("Native package review plan unavailable or invalid")
    answer = response.get("payload")
    if not isinstance(answer, dict) or set(answer) != {"artifact", "may_allow"}:
        raise NativePackageReviewPlanError("Native package review plan invalid")
    may_allow = answer["may_allow"]
    if not isinstance(may_allow, bool) or (answer["artifact"] is None and may_allow):
        raise NativePackageReviewPlanError("Native package review plan invalid")
    if answer["artifact"] is None:
        return None, False
    try:
        artifact = _artifact_from_wire(answer["artifact"])
    except NativePackageArtifactUnavailableError as error:
        raise NativePackageReviewPlanError("Native package review plan invalid") from error
    return artifact, may_allow
