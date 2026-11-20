"""Credential-free, Guard-owned positive proof for public GitHub reads.

The native runtime (`verified-github-read`) checks what may be read, sends
both GET requests under the machine's managed network policy, reads the
replies and binds the proof.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final, cast

from ..mdm.runtime_request import runtime_answer
from ..native_verified_read_decision import NativeVerifiedReadDecisionError, github_public_read_decision
from .effect_contract import ProofRequirement, ProofRoute
from .effect_decision import EffectDecision, FinalDisposition, PositiveProof

VERIFIED_GITHUB_READ_VERSION: Final = "guard.verified-github-read.v1"
VERIFIED_GITHUB_RULE_VERSION: Final = "guard.verified-read.github-public.v1"
_FEATURE: Final = "native-verified-github-read-v2"
_COMMAND: Final = "verified-github-read"
_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.REMOTE_RESOURCE_IDENTITY,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedGitHubReadResult:
    stdout: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str = "github-public-pull-request-view"


def try_read_verified_public_github_pull_request(
    owner: str,
    repository: str,
    pull_number: int,
    *,
    fields: tuple[str, ...] = ("number", "state", "mergeable"),
    timeout_seconds: float = 15.0,
) -> VerifiedGitHubReadResult | None:
    """Read one public pull request without origin credentials or redirects."""

    raw_timeout = cast(object, timeout_seconds)
    if type(raw_timeout) not in {int, float}:
        return None
    bounded_timeout = float(cast(int | float, raw_timeout))
    if not math.isfinite(bounded_timeout) or not 0 < bounded_timeout <= 30:
        return None
    raw_fields = cast(object, fields)
    raw_number = cast(object, pull_number)
    if not isinstance(raw_fields, tuple) or type(raw_number) is not int:
        return None
    request: dict[str, object] = {
        "op": "read",
        "owner": owner,
        "repository": repository,
        "pull_number": pull_number,
        "fields": list(cast(tuple[object, ...], raw_fields)),
        "timeout_seconds": bounded_timeout,
    }
    try:
        # Two exchanges of up to `bounded_timeout` each, plus the proof.
        composed = runtime_answer(
            _FEATURE,
            _COMMAND,
            request,
            output_limit=64 * 1024,
            timeout_seconds=2 * bounded_timeout + 10.0,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    stdout = None if composed is None else composed.get("stdout")
    binding_digest = None if composed is None else composed.get("binding_digest")
    if not isinstance(stdout, str) or not isinstance(binding_digest, str):
        return None
    proof = PositiveProof(ProofRoute.VERIFIED, binding_digest, _REQUIREMENTS)
    try:
        # Both effect factors and the operation are fixed by the executor that
        # produced the proof, so only the binding digest crosses.
        decision = github_public_read_decision(binding_digest=binding_digest)
    except NativeVerifiedReadDecisionError:
        return None
    if decision.disposition is not FinalDisposition.SILENT_VERIFIED:
        return None
    return VerifiedGitHubReadResult(stdout, proof, decision)


__all__ = (
    "VERIFIED_GITHUB_READ_VERSION",
    "VERIFIED_GITHUB_RULE_VERSION",
    "VerifiedGitHubReadResult",
    "try_read_verified_public_github_pull_request",
)
