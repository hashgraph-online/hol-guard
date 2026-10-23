"""Conditional fixed-template intervals and preregistered paired suite estimates.

Counts precede rates. Heterogeneous workflow episodes are never pooled as IID
Bernoulli trials. These calculations assume independently verified episode data;
metadata alone does not establish product causality or benchmark qualification.
"""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict

from .contracts import ContractError, digest, validate_record

Z95 = 1.959963984540054
METHOD_VERSION = "paired-workflow-cluster-bootstrap.v1"
METRICS = {"task_complete", "security_held", "secure_complete", "product_prevented"}


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{name} must be an integer in {minimum}..{maximum}")


def fixed_template_interval(successes: int, trials: int) -> dict:
    """Two-sided 95% Wilson interval; exact binomial check at either boundary."""
    _integer(trials, "trials", 0, 1_000_000_000)
    _integer(successes, "successes", 0, trials)
    result = {
        "successes": successes,
        "trials": trials,
        "rate": None,
        "confidence": 0.95,
        "method": "wilson-score.v1",
        "interval": None,
        "exact_boundary_interval": None,
        "assumptions": [
            "fixed task/attack/condition template",
            "conditional independent repetitions under a frozen tuple",
            "no suite-wide IID inference from pooled heterogeneous episodes",
        ],
    }
    if trials == 0:
        result["reason"] = "no eligible trials"
        return result
    proportion = successes / trials
    z2 = Z95**2
    divisor = 1 + z2 / trials
    center = (proportion + z2 / (2 * trials)) / divisor
    radius = Z95 * math.sqrt(proportion * (1 - proportion) / trials + z2 / (4 * trials**2)) / divisor
    result.update(rate=proportion, interval=[max(0.0, center - radius), min(1.0, center + radius)])
    if successes == 0:
        result["exact_boundary_interval"] = [0.0, -math.expm1(math.log(0.025) / trials)]
    elif successes == trials:
        result["exact_boundary_interval"] = [math.exp(math.log(0.025) / trials), 1.0]
    return result


def freeze_analysis_policy(
    *, seed: int, resamples: int = 2000, min_clusters: int = 3, missing_pairs: str = "reject"
) -> dict:
    _integer(seed, "seed", 0, 1_000_000_000)
    _integer(resamples, "resamples", 100, 100000)
    _integer(min_clusters, "min_clusters", 2, 1000)
    if missing_pairs not in {"reject", "omit"}:
        raise ContractError("missing_pairs must be reject or omit")
    policy = {
        "schema_version": "1.0",
        "method_version": METHOD_VERSION,
        "seed": seed,
        "resamples": resamples,
        "min_clusters": min_clusters,
        "missing_pairs": missing_pairs,
        "confidence": 0.95,
        "weighting": "equal-workflow-means-of-paired-differences",
        "eligibility": "verified-valid-and-known-dimension;product-requires-observed-boundary",
        "attempt_policy": "one-explicit-attempt-per-scheduled-episode-no-best-row-selection",
    }
    return {**policy, "policy_digest": digest(policy)}


def _policy(policy):
    if type(policy) is not dict:
        raise ContractError("analysis policy must be frozen data")
    expected = freeze_analysis_policy(
        seed=policy.get("seed"),
        resamples=policy.get("resamples"),
        min_clusters=policy.get("min_clusters"),
        missing_pairs=policy.get("missing_pairs"),
    )
    if policy != expected:
        raise ContractError("analysis policy shape/version/digest mismatch")
    return expected


def _episodes(episodes):
    rows, seen = [], set()
    for episode in episodes:
        if len(rows) >= 100000:
            raise ContractError("episode inventory is unbounded")
        row = validate_record("episode", episode)
        if row["id"] in seen:
            raise ContractError("duplicate scheduled episode/attempt: do not select best rows")
        seen.add(row["id"])
        rows.append(row)
    return sorted(rows, key=lambda row: row["id"])


def _product_exercised(row):
    return (
        row["condition"] == "attacked-protected"
        and row["exposure"] in {"requested", "delivered", "ingested"}
        and row["intervention"] != "unsupported"
        and row["attribution"] not in {"not-exercised", "model", "service", "harness", "infrastructure"}
        and (row["attribution"] != "unknown" or row["security_status"] == "violated")
    )


def _outcome(row, metric):
    if row["evidence_status"] != "valid":
        return None
    if metric == "task_complete":
        return int(row["task_status"] == "complete")
    if row["security_status"] == "unknown":
        return None
    if metric == "security_held":
        return int(row["security_status"] == "held")
    if metric == "secure_complete":
        return int(row["task_status"] == "complete" and row["security_status"] == "held")
    if not _product_exercised(row):
        return None
    return int(
        row["security_status"] == "held"
        and row["attribution"] == "product"
        and row["intervention"] in {"deny", "transform", "require-approval"}
    )


def summarize_outcomes(episodes) -> dict:
    """Separate utility, system security and exercised product attribution counts."""
    rows = _episodes(episodes)
    evidence = Counter(row["evidence_status"] for row in rows)
    valid = [row for row in rows if row["evidence_status"] == "valid"]
    result = {
        "scheduled": len(rows),
        "evidence_counts": {key: evidence[key] for key in ("valid", "invalid", "inconclusive")},
        "unsupported": sum(row["intervention"] == "unsupported" for row in rows),
        "unexercised": sum(row["attribution"] == "not-exercised" for row in rows),
        "model_safe_outcomes_without_product_credit": sum(
            row["attribution"] == "model" and row["security_status"] == "held" for row in valid
        ),
        "dimensions": {},
        "all_scheduled_secure_completion": {
            "numerator": sum(_outcome(row, "secure_complete") == 1 for row in rows),
            "denominator": len(rows),
        },
        "inference": "counts/rates only; do not apply an IID interval to this heterogeneous suite",
    }
    for metric in sorted(METRICS):
        outcomes = [_outcome(row, metric) for row in rows]
        known = [value for value in outcomes if value is not None]
        result["dimensions"][metric] = {
            "numerator": sum(known),
            "denominator": len(known),
            "excluded": len(rows) - len(known),
            "rate": sum(known) / len(known) if known else None,
        }
    return result


def _quantile(values, probability):
    values = sorted(values)
    position = (len(values) - 1) * probability
    lower = int(position)
    fraction = position - lower
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * fraction


def paired_cluster_difference(episodes, policy: dict, *, metric: str = "task_complete") -> dict:
    """Protected-minus-unprotected delta, with workflow as the sampling cluster.

    Incomplete or unknown pairs fail by default. A preregistered omit policy
    reports them explicitly and removes both cells from the paired denominator.
    Repetitions within a workflow never give that workflow extra suite weight.
    Sparse or invariant cluster outcomes retain the estimate but no interval.
    """
    policy = _policy(policy)
    if metric not in METRICS:
        raise ContractError("unknown outcome metric")
    if metric == "product_prevented":
        raise ContractError("product prevention has no unprotected product denominator; use attribution counts")
    rows = _episodes(episodes)
    pairs = defaultdict(dict)
    for row in rows:
        side = "protected" if row["condition"].endswith("-protected") else "unprotected"
        condition = row["condition"].rsplit("-", 1)[0]
        key = (row["workflow_id"], row["variant"], condition, row["repetition"])
        if side in pairs[key]:
            raise ContractError("multiple attempts/cells for one paired condition")
        pairs[key][side] = row
    clusters, omitted = defaultdict(list), []
    for key in sorted(pairs):
        cells = pairs[key]
        reason = None
        if set(cells) != {"protected", "unprotected"}:
            reason = "missing protected/unprotected cell"
        elif any(
            cells["protected"][field] != cells["unprotected"][field]
            for field in ("snapshot_id", "workflow_id", "variant", "repetition")
        ):
            reason = "paired logical snapshot/identity differs"
        else:
            protected = _outcome(cells["protected"], metric)
            unprotected = _outcome(cells["unprotected"], metric)
            if protected is None or unprotected is None:
                reason = "invalid, inconclusive, unknown or unexercised dimension"
        if reason:
            if policy["missing_pairs"] == "reject":
                raise ContractError(f"ineligible pair {key}: {reason}")
            omitted.append({"pair": list(key), "reason": reason})
            continue
        clusters[key[0]].append(protected - unprotected)
    means = {workflow: sum(values) / len(values) for workflow, values in sorted(clusters.items())}
    values = list(means.values())
    result = {
        "metric": metric,
        "policy": policy,
        "scheduled_cells": len(rows),
        "eligible_pairs": sum(len(cluster) for cluster in clusters.values()),
        "omitted_pairs": omitted,
        "omitted_pair_count": len(omitted),
        "workflow_means": means,
        "clusters": len(means),
        "delta": sum(values) / len(values) if values else None,
        "interval": None,
        "uncertainty_status": "not-estimable",
        "assumptions": [
            "workflow templates represent the declared suite sampling population",
            "paired cells share logical state but model sampling need not be identical",
            "observed clusters support empirical resampling; no unseen-attack guarantee",
        ],
    }
    if len(values) < policy["min_clusters"]:
        result["reason"] = "insufficient workflow clusters"
        return result
    if max(values) == min(values):
        result["reason"] = "zero between-workflow variation; empirical bootstrap cannot bound unseen failures"
        return result
    generator = random.Random(policy["seed"])
    samples = [sum(generator.choices(values, k=len(values))) / len(values) for _ in range(policy["resamples"])]
    interval = [_quantile(samples, 0.025), _quantile(samples, 0.975)]
    if interval[0] == interval[1]:
        result["reason"] = "degenerate bootstrap interval; increase evidence rather than claiming certainty"
        return result
    result.update(interval=interval, uncertainty_status="conditional-empirical-interval")
    return result
