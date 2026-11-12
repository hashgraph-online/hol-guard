"""Guard-owned execution for a narrow cohort of bounded workspace reads.

The resident does the whole read (`verified-read-execute-v1`): it plans the
read from the argv, opens the target beneath the working directory's
repository without following a symlink, slices the text, binds the proof and
composes the decision. This side sends the argv and the process's working
directory and prints what comes back. Any resident failure ends the verified
read; there is no Python fallback.
"""

from __future__ import annotations

import functools
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .. import native_execution
from ..native_resident_decision import ResidentOperation, resident_decide, shape_fields
from .effect_contract import ProofRequirement, ProofRoute
from .effect_decision import EffectDecision, FinalDisposition, PositiveProof

VERIFIED_READ_EXECUTION_VERSION: Final = "guard.verified-read-execution.v1"
VERIFIED_READ_POLICY_VERSION: Final = "guard.verified-read-policy.v1"
VERIFIED_READ_RULE_VERSION: Final = "guard.verified-read.local.v1"
_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.WORKSPACE_IDENTITY,
        ProofRequirement.REPOSITORY_IDENTITY,
        ProofRequirement.WORKING_DIRECTORY_IDENTITY,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    }
)


class NativeVerifiedReadExecuteError(RuntimeError):
    """The resident did not perform the read."""


_OPERATION: Final = ResidentOperation(
    operation="verified_read_execute",
    feature="verified-read-execute-v1",
    prefix="native_verified_read_execute",
    request_schema="guard-verified-read-execute-request.v1",
    result_schema="guard-verified-read-execute-result.v1",
    request_id_prefix="verified-read-execute",
    timeout_seconds=10.0,
    error=NativeVerifiedReadExecuteError,
)
# The resident accepts a canonical request up to 16 KiB; the wire envelope
# carries the same material plus framing, so leave room for both.
_MAX_REQUEST_BYTES: Final = 6 * 16 * 1024 + 4096
_PAYLOAD_FIELDS: Final = {"kind": str, "operation_id": str, "stdout": str, "binding_digest": str, "decision": dict}


@dataclass(frozen=True, slots=True)
class VerifiedReadResult:
    exit_code: int
    stdout: str
    stderr: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str


def try_execute_verified_local_read(argv: tuple[str, ...]) -> VerifiedReadResult | None:
    """Have the resident perform one bounded read in this process's working directory."""

    def validate(payload: dict[str, Any]) -> None:
        _ = shape_fields(payload, _PAYLOAD_FIELDS, lambda: _OPERATION.fail(_OPERATION.invalid))

    try:
        query = {"kind": "local", "argv": list(argv), "cwd": os.getcwd(), "home_dir": str(Path.home())}
        payload = resident_decide(
            _OPERATION,
            functools.partial(native_execution._resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
            query,
            None,
            validate,
        )
        decision = native_execution._effect_decision(payload["decision"])
        proof = PositiveProof(ProofRoute.VERIFIED, payload["binding_digest"], _REQUIREMENTS)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if decision.disposition is not FinalDisposition.SILENT_VERIFIED:
        return None
    return VerifiedReadResult(0, payload["stdout"], "", proof, decision, payload["operation_id"])


__all__ = (
    "VERIFIED_READ_EXECUTION_VERSION",
    "VERIFIED_READ_POLICY_VERSION",
    "VERIFIED_READ_RULE_VERSION",
    "VerifiedReadResult",
    "try_execute_verified_local_read",
)
