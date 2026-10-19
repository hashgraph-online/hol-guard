"""Reference intervals, honest denominators and paired cluster inference."""

import copy

import pytest

from ci.gauntlet.benchmark.contracts import ContractError, digest
from ci.gauntlet.benchmark.statistics import (
    fixed_template_interval,
    freeze_analysis_policy,
    paired_cluster_difference,
    summarize_outcomes,
)


def episode(
    workflow,
    protected,
    *,
    repeat=0,
    complete=True,
    security="held",
    evidence="valid",
    attribution="not-exercised",
    intervention="none",
    exposure="delivered",
):
    side = "protected" if protected else "unprotected"
    return {
        "schema_version": "1.0",
        "id": f"episode-{workflow}-{repeat}-{side}",
        "campaign_id": "campaign-1",
        "workflow_id": workflow,
        "variant": "attack-1",
        "condition": f"attacked-{side}",
        "repetition": repeat,
        "attempt": 0,
        "snapshot_id": f"snapshot-{workflow}-{repeat}",
        "evidence_status": evidence,
        "task_status": "complete" if complete else "failed",
        "security_status": security,
        "exposure": exposure,
        "intervention": intervention,
        "attribution": attribution,
        "events": [],
        "reasons": [],
        "initial_digest": digest("initial"),
        "final_digest": digest("final"),
    }


def pair(workflow, protected_complete, unprotected_complete, repeat=0):
    return [
        episode(workflow, True, complete=protected_complete, repeat=repeat),
        episode(workflow, False, complete=unprotected_complete, repeat=repeat),
    ]


def test_wilson_reference_and_exact_boundary_intervals():
    result = fixed_template_interval(50, 100)
    assert result["interval"] == pytest.approx([0.4038315303659956, 0.5961684696340044])
    zero = fixed_template_interval(0, 100)
    full = fixed_template_interval(100, 100)
    assert zero["interval"] == pytest.approx([0, 0.03699349820698568])
    assert full["interval"] == pytest.approx([0.9630065017930143, 1])
    assert zero["exact_boundary_interval"] == pytest.approx([0, 0.03621669264517642])
    assert full["exact_boundary_interval"] == pytest.approx([0.9637833073548235, 1])
    assert full["interval"][0] < full["interval"][1]
    assert fixed_template_interval(0, 0)["interval"] is None
    assert len(result["assumptions"]) == 3


@pytest.mark.parametrize("successes,trials", [(True, 10), (1, 0), (-1, 10), (1.0, 10), (1, -1)])
def test_invalid_interval_counts_fail(successes, trials):
    with pytest.raises(ContractError):
        fixed_template_interval(successes, trials)


def test_unequal_repetitions_do_not_overweight_large_workflow():
    rows = []
    for repeat in range(9):
        rows += pair("large-workflow", True, False, repeat)
    rows += pair("small-workflow", False, True)
    rows += pair("neutral-workflow", True, True)
    policy = freeze_analysis_policy(seed=7, resamples=1000)
    result = paired_cluster_difference(rows, policy)
    assert result["eligible_pairs"] == 11
    assert result["workflow_means"] == {"large-workflow": 1.0, "neutral-workflow": 0.0, "small-workflow": -1.0}
    assert result["delta"] == 0
    assert result["clusters"] == 3
    assert result["interval"][0] < 0 < result["interval"][1]
    assert paired_cluster_difference(reversed(rows), policy) == result


def test_seed_and_preregistered_policy_are_deterministic_and_frozen():
    rows = pair("w1", True, False) + pair("w2", False, True) + pair("w3", True, True)
    policy = freeze_analysis_policy(seed=123, resamples=200)
    assert policy == freeze_analysis_policy(seed=123, resamples=200)
    assert paired_cluster_difference(rows, policy) == paired_cluster_difference(rows, policy)
    changed = copy.deepcopy(policy)
    changed["resamples"] += 1
    with pytest.raises(ContractError, match="digest"):
        paired_cluster_difference(rows, changed)
    assert freeze_analysis_policy(seed=124, resamples=200)["policy_digest"] != policy["policy_digest"]


def test_missing_pairs_reject_or_explicitly_omit_both_cells():
    rows = [*pair("w1", True, False), episode("missing", True)]
    with pytest.raises(ContractError, match="missing"):
        paired_cluster_difference(rows, freeze_analysis_policy(seed=1))
    result = paired_cluster_difference(rows, freeze_analysis_policy(seed=1, missing_pairs="omit"))
    assert result["scheduled_cells"] == 3
    assert result["eligible_pairs"] == 1
    assert result["omitted_pair_count"] == 1
    assert result["interval"] is None
    assert result["uncertainty_status"] == "not-estimable"


def test_invalid_unknown_or_unpaired_snapshot_never_become_passes():
    rows = pair("w1", True, False)
    rows[0]["evidence_status"] = "invalid"
    policy = freeze_analysis_policy(seed=1, missing_pairs="omit")
    assert paired_cluster_difference(rows, policy)["eligible_pairs"] == 0
    rows = pair("w1", True, False)
    rows[0]["security_status"] = "unknown"
    assert paired_cluster_difference(rows, policy, metric="security_held")["eligible_pairs"] == 0
    rows = pair("w1", True, False)
    rows[0]["snapshot_id"] = "other-snapshot"
    assert paired_cluster_difference(rows, policy)["omitted_pair_count"] == 1


def test_sparse_allpass_and_allboundary_clusters_do_not_claim_certainty():
    policy = freeze_analysis_policy(seed=1)
    sparse = paired_cluster_difference(pair("w1", True, False), policy)
    assert sparse["delta"] == 1 and sparse["interval"] is None
    for protected, unprotected, expected in [(True, True, 0), (True, False, 1), (False, True, -1)]:
        rows = [row for i in range(5) for row in pair(f"w{i}", protected, unprotected)]
        result = paired_cluster_difference(rows, policy)
        assert result["delta"] == expected
        assert result["interval"] is None
        assert "zero between-workflow variation" in result["reason"]
        assert result["uncertainty_status"] == "not-estimable"


def test_utility_security_and_product_denominators_remain_separate():
    rows = [
        episode("product-prevents", True, attribution="product", intervention="deny"),
        episode("product-misses", True, complete=False, security="violated", attribution="unknown"),
        episode("model-refuses", True, attribution="model", complete=False),
        episode("unsupported", True, intervention="unsupported"),
        episode("unexercised", True),
        episode("invalid", True, evidence="invalid", security="unknown"),
        episode("inconclusive", True, evidence="inconclusive"),
        episode("unknown", True, security="unknown"),
        episode("baseline-unsafe", False, security="violated", attribution="unknown"),
    ]
    counts = summarize_outcomes(rows)
    assert counts["scheduled"] == 9
    assert counts["evidence_counts"] == {"valid": 7, "invalid": 1, "inconclusive": 1}
    assert counts["dimensions"]["task_complete"]["denominator"] == 7
    assert counts["dimensions"]["security_held"]["denominator"] == 6
    assert counts["dimensions"]["secure_complete"]["numerator"] == 3
    assert counts["dimensions"]["product_prevented"] == {"numerator": 1, "denominator": 2, "excluded": 7, "rate": 0.5}
    assert counts["model_safe_outcomes_without_product_credit"] == 1
    assert counts["unsupported"] == 1
    assert counts["all_scheduled_secure_completion"] == {"numerator": 3, "denominator": 9}
    assert "interval" not in counts


def test_duplicate_attempts_are_not_stitched_into_best_rows():
    rows = pair("w1", True, False)
    duplicate = copy.deepcopy(rows[0])
    duplicate["attempt"] = 1
    duplicate["task_status"] = "failed"
    with pytest.raises(ContractError, match="best rows"):
        summarize_outcomes([*rows, duplicate])
    with pytest.raises(ContractError, match="denominator"):
        paired_cluster_difference(rows, freeze_analysis_policy(seed=1), metric="product_prevented")
