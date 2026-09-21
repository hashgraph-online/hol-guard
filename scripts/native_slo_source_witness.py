"""Require actual native source review before accepting large-source SLO work."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

from scripts.native_slo_edge_diagnostic import capture_native_edge_stages
from scripts.native_slo_failure import FixtureFailureError
from scripts.native_slo_native_diagnostic import observe_native_call
from scripts.native_slo_observation_failure import verdict_evidence


@contextmanager
def source_review_witness(worker: Any, request: Mapping[str, object]) -> Iterator[None]:
    reference = request.get("guard_source_ref")
    if not isinstance(reference, Mapping):
        yield
        return
    digest = reference.get("output_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise RuntimeError("source SLO reference digest is invalid")
    original = worker._review_raw_hook_native
    observations: list[tuple[object, object, object, object, object, object, bool, dict[str, object]]] = []

    def capture(**kwargs: object) -> object:
        if len(observations) >= 2:
            return original(**kwargs)
        edge, diagnostic = observe_native_call(
            lambda: original(**kwargs),
            worker=worker,
            deadline=kwargs.get("deadline"),
            policy_snapshot=kwargs.get("policy_snapshot"),
        )
        result = edge.get("result") if isinstance(edge, Mapping) else None
        if isinstance(result, Mapping):
            observations.append(
                (
                    edge.get("authority"),
                    result.get("decision"),
                    result.get("model_output_action"),
                    result.get("reviewed_output_sha256"),
                    result.get("reason_code"),
                    result.get("policy_action"),
                    True,
                    diagnostic,
                )
            )
        else:
            observations.append((None, None, None, None, None, None, False, diagnostic))
        return edge

    # The large-source matrix is sequential. This fixture-only wrapper uses
    # the same raw-edge seam as FaultFixture and preserves the real HTTP path.
    # No source bytes or response body are retained in the witness.
    with capture_native_edge_stages(), patch.object(worker, "_review_raw_hook_native", capture):
        yield
    if (
        len(observations) != 1
        or observations[0][:4] != ("rust", "allow", "allow_original", digest)
        or observations[0][4] not in {"source_full_scan_allow", "native_policy_warning"}
    ):
        raise FixtureFailureError(
            {
                "schema": "hol-guard.native-qualification-failure.v1",
                "reason": "reference_review_unproven",
                "stage": "reference_witness",
                "native_observations": [
                    {
                        "verdict": verdict_evidence(
                            native={
                                "decision": item[1],
                                "model_output_action": item[2],
                                "reason_code": item[4],
                                "policy_action": item[5],
                            }
                            if item[6]
                            else None
                        )["native"],
                        "rust_authority": item[0] == "rust",
                        "reference_digest_matches": item[3] == digest,
                        "call_diagnostic": item[7],
                    }
                    for item in observations
                ],
                "observation_count": len(observations),
                "observation_count_is_lower_bound": len(observations) == 2,
                "full_review_qualified": False,
            },
            message="source SLO did not witness one complete native content review",
        )


@contextmanager
def source_reference_denial_witness(worker: Any, request: Mapping[str, object]) -> Iterator[None]:
    """Prove the existing Windows refusal without claiming content review."""
    if not isinstance(request.get("guard_source_ref"), Mapping):
        raise ValueError("source denial witness requires a source reference")
    original = worker._review_raw_hook_native
    observations: list[tuple[object, ...]] = []

    def capture(**kwargs: object) -> object:
        edge = original(**kwargs)
        result = edge.get("result") if isinstance(edge, Mapping) else None
        if len(observations) < 2:
            observations.append(
                (
                    edge.get("authority"),
                    result.get("decision"),
                    result.get("model_output_action"),
                    result.get("policy_action"),
                    result.get("reason_code"),
                    result.get("reviewed_output_sha256"),
                    result.get("reviewed_excerpt"),
                )
                if isinstance(result, Mapping)
                else (None,)
            )
        return edge

    with patch.object(worker, "_review_raw_hook_native", capture):
        yield
    if observations != [("rust", "deny", "block", "block", "no_output_to_review", None, None)]:
        raise RuntimeError("source SLO did not witness the exact platform source-reference denial")
