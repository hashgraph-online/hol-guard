"""Present the native owner's unavailable consumer launch-binding capability."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..models import HarnessDetection
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority


def consumer_launch_review_capability(detection: HarnessDetection, evaluation: Mapping[str, Any]) -> dict[str, Any]:
    result = native_runner_authority(
        "consumer_launch_review_capability",
        {
            "artifacts": [artifact.to_dict() for artifact in detection.artifacts],
            "evaluations": [
                {"artifact_id": item.get("artifact_id"), "policy_action": item.get("policy_action")}
                for item in evaluation.get("artifacts", [])
                if isinstance(item, Mapping)
            ],
        },
    )
    if not isinstance(result.get("available"), bool) or not isinstance(result.get("unavailable_artifact_ids"), list):
        raise NativeRunnerAuthorityError("native_runner_authority_result_invalid")
    if result["available"]:
        return {}
    return {
        "approval_capability": result,
        "review_hint": (
            "This platform cannot bind and resume this consumer launch after approval. "
            "No launch approval is available; Allow once and Always allow cannot run the reviewed version. "
            "Use a supported platform for this guarded launch, or inspect the artifacts with "
            f"hol-guard diff {detection.harness}. "
            "Do not disable Guard or remove the review requirement to work around this limitation."
        ),
    }


_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_queue_unavailable",
    "approval_requests",
    "approval_wait",
    "daemon_queue_unavailable",
    "review_hint",
)


def _copy_approval_metadata(target: dict[str, Any], resolved: Mapping[str, Any]) -> None:
    for key in _APPROVAL_METADATA_KEYS:
        if key in resolved:
            target[key] = resolved[key]
