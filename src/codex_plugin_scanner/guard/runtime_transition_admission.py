"""Functional candidate admission through the actual package-bound Rust edge.

The caller owns the isolated home, worker and their bounded cleanup. These
probes classify fixed payloads; they never execute either shell command.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .daemon.hook_worker import HookWorker
from .native_decision_receipt import validate_native_decision_receipt
from .native_hook_edge import review_raw_hook_native
from .native_runtime import NativeRuntimeIdentity, native_runtime_status
from .runtime_transition import TransitionError

_ADMISSION_SEAL = object()


@dataclass(frozen=True)
class NativeProtectionAdmission:
    operation_id: str
    artifact_generation: str
    # Approved comparison identity, possibly retained outside an extraction.
    # Actual Rust receipts must prove its content digest; this path is never a
    # native launch override or evidence of the loaded process's physical path.
    runtime_identity: NativeRuntimeIdentity
    policy_generation: int
    policy_digest: str
    allow_receipt: dict[str, object]
    deny_receipt: dict[str, object]
    guard_home: Path
    observed_monotonic: float
    installed_hook_evidence: dict[str, object] | None = None
    _seal: object = field(default=None, init=False, repr=False, compare=False)
    _attested_digest: str = field(default="", init=False, repr=False, compare=False)

    def payload(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": "hol-guard.native-protection-admission.v1",
            "operation_id": self.operation_id,
            "generation": self.artifact_generation,
            "runtime_identity": {
                "path": str(self.runtime_identity.path),
                "size": self.runtime_identity.size,
                "mtime_ns": self.runtime_identity.mtime_ns,
                "sha256": self.runtime_identity.sha256,
            },
            "policy_generation": self.policy_generation,
            "policy_digest": self.policy_digest,
            "allow_receipt": self.allow_receipt,
            "deny_receipt": self.deny_receipt,
            "guard_home": str(self.guard_home),
            "observed_monotonic": self.observed_monotonic,
        }
        if self.installed_hook_evidence is not None:
            result["installed_hook_evidence"] = self.installed_hook_evidence
        return result


def _admission_bytes(proof: NativeProtectionAdmission) -> bytes:
    return json.dumps(
        proof.payload(),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _seal_verified_admission(proof: NativeProtectionAdmission) -> NativeProtectionAdmission:
    """Mark only the native producer's fully checked in-process observation."""
    object.__setattr__(proof, "_attested_digest", hashlib.sha256(_admission_bytes(proof)).hexdigest())
    object.__setattr__(proof, "_seal", _ADMISSION_SEAL)
    return proof


def verified_admission_payload(proof: object) -> dict[str, object]:
    """Refuse serialized assertions, constructed results and modified receipts."""
    if type(proof) is not NativeProtectionAdmission or proof._seal is not _ADMISSION_SEAL:
        raise TransitionError("functional_proof_missing")
    try:
        encoded = _admission_bytes(proof)
        digest = hashlib.sha256(encoded).hexdigest()
    except (ValueError, TypeError, RuntimeError):
        raise TransitionError("functional_proof_missing") from None
    if not hmac.compare_digest(digest, proof._attested_digest):
        raise TransitionError("functional_proof_missing")
    # Copy nested receipt data so later caller mutations cannot alter the
    # exact observation stored in the signed transition journal.
    return json.loads(encoded)


def probe_native_protection(
    *,
    worker: HookWorker,
    operation_id: str,
    artifact_generation: str,
    expected_runtime: NativeRuntimeIdentity,
    home_dir: Path,
    workspace: Path,
    deadline_monotonic: float,
) -> NativeProtectionAdmission:
    """Require fresh native allow and deny decisions under one ACKed policy."""
    if not operation_id or not artifact_generation:
        raise TransitionError("admission_identity_invalid")

    def check_runtime() -> None:
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("admission_deadline_expired")
        status = native_runtime_status()
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("admission_deadline_expired")
        if (
            status.mode not in {"auto", "force"}
            or not status.available
            or not status.compatible
            or status.identity != expected_runtime
        ):
            raise TransitionError("admission_runtime_mismatch")

    check_runtime()
    snapshot = worker.prepare_workspace_policy(workspace, deadline=deadline_monotonic)
    if snapshot is None:
        raise TransitionError("admission_policy_unavailable")
    generation, digest = snapshot.get("generation"), snapshot.get("policy_digest")
    if (
        type(generation) is not int
        or generation <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or snapshot.get("mode") != "enforce"
        or snapshot.get("runtime_identity") != expected_runtime.sha256
    ):
        raise TransitionError("admission_policy_mismatch")
    receipts: list[dict[str, object]] = []
    for command, decision in (("pwd", "allow"), ("rm -rf /", "deny")):
        check_runtime()
        request_id = "transition-admission-" + uuid.uuid4().hex
        edge = review_raw_hook_native(
            payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}},
            harness="claude-code",
            event="PreToolUse",
            guard_home=worker.guard_home,
            home_dir=home_dir,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=deadline_monotonic,
            policy_snapshot=snapshot,
            request_id=request_id,
        )
        check_runtime()
        receipt = validate_native_decision_receipt(edge.get("receipt")) if edge is not None else None
        if (
            receipt is None
            or receipt["request_id"] != request_id
            or receipt["decision"] != decision
            or receipt["harness"] != "claude-code"
            or receipt["event_name"] != "PreToolUse"
            or receipt["payload_kind"] != "inline"
            or (decision == "allow" and receipt["policy_action"] not in {"allow", "warn"})
            or receipt["runtime_identity"] != expected_runtime.sha256
            or receipt["policy_generation"] != generation
            or receipt["policy_digest"] != digest
            or receipt["observe_mode"] is not False
        ):
            raise TransitionError("admission_protection_failed")
        receipts.append(receipt)
    if receipts[0]["request_digest"] == receipts[1]["request_digest"]:
        raise TransitionError("admission_request_mismatch")
    return _seal_verified_admission(
        NativeProtectionAdmission(
            operation_id,
            artifact_generation,
            expected_runtime,
            generation,
            digest,
            receipts[0],
            receipts[1],
            worker.guard_home.resolve(strict=False),
            time.monotonic(),
        )
    )
