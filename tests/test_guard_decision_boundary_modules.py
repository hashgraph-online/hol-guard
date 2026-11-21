"""Regression coverage for the approval decision projection boundary."""

from __future__ import annotations

import pytest

from tests.decision_boundaries_support import canonical_approval_surfaces_batch

pytestmark = pytest.mark.usefixtures("native_prompt_runtime")


def _decision(action: object, decision: object) -> dict[str, object]:
    (projected,) = canonical_approval_surfaces_batch([(action, decision, None)])
    return projected.decision_v2_json


def test_legacy_review_projects_to_the_exact_review_decision() -> None:
    decision = _decision("review", None)

    assert decision["action"] == "ask"
    assert decision["guard_action"] == "review"


def test_projection_preserves_valid_package_cloud_reason_code() -> None:
    source = _decision("review", None)
    source["package_review_cloud_reason_code"] = "cloud_validation_error"

    assert _decision("review", source)["package_review_cloud_reason_code"] == "cloud_validation_error"


def test_projection_drops_unknown_package_cloud_reason_code() -> None:
    source = _decision("review", None)
    source["package_review_cloud_reason_code"] = "unexpected"

    assert "package_review_cloud_reason_code" not in _decision("review", source)


@pytest.mark.parametrize("malformed_code", ([], {}))
def test_projection_drops_non_string_package_cloud_reason_code(malformed_code: object) -> None:
    source = _decision("review", None)
    source["package_review_cloud_reason_code"] = malformed_code

    assert "package_review_cloud_reason_code" not in _decision("review", source)
