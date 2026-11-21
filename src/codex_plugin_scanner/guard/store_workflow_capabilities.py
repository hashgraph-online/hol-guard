"""GuardStore boundary for workflow-capability persistence.

The authority (signature checks, the authority ledger, claim, revocation and
lookup rules) runs in the native resident. The control blob lives in the
caller's credential store, so every operation is a plan/commit exchange: the
resident plans the operation in a rolled-back transaction and names each
control write to persist, Python persists them, and the resident then replays
the operation in a real transaction, refusing if it no longer matches the
plan. A write that must follow the database commit is persisted last.
Python never recalculates a verdict.
"""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnnecessaryIsInstance=false

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any, Final
from uuid import uuid4

from .native_guard_store import NativeGuardStoreUnavailable
from .store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .workflow_capabilities import (
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityBinding,
    WorkflowCapabilityClaim,
    WorkflowCapabilityError,
)

_PLAN_STALE_REASON: Final = "native_guard_store_capability_plan_stale"
_MAX_PLAN_ATTEMPTS: Final = 3


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _plan_failure(error: Mapping[str, Any]) -> Exception:
    if error.get("kind") == "capability":
        return WorkflowCapabilityError(str(error["code"]))
    return RuntimeError(str(error.get("message", "workflow_capability_failed")))


class StoreWorkflowCapabilitiesMixin:
    """Persist and atomically consume exact signed workflow capabilities."""

    def hold_workflow_capability_authority_lock(self) -> Any:
        raise NotImplementedError

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        _ = create
        raise NotImplementedError

    def _load_workflow_capability_control(self) -> str | None:
        raise NotImplementedError

    def _store_workflow_capability_control(self, encoded: str) -> bool:
        _ = encoded
        raise NotImplementedError

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any:
        _ = (method, args)
        raise NotImplementedError

    def _persist_workflow_capability_controls(self, writes: Sequence[str]) -> None:
        for encoded in writes:
            if not self._store_workflow_capability_control(encoded):
                raise WorkflowCapabilityError("capability_control_unavailable")

    def _run_workflow_capability(self, operation: str, now: str, arguments: Mapping[str, object]) -> Any:
        """Drive one plan/commit exchange and return the committed result."""

        key, key_id = self._policy_integrity_secret_material(create=False)
        key_b64 = None if key is None or key_id is None else base64.b64encode(key).decode("ascii")
        for _attempt in range(_MAX_PLAN_ATTEMPTS):
            original = self._load_workflow_capability_control()
            wire: dict[str, object] = {
                "op": operation,
                "now": now,
                "control_blob": original,
                "key_b64": key_b64,
                "key_id": key_id if key_b64 is not None else None,
                **arguments,
            }
            plan = self._native_store_call("workflow_capability_plan", wire)
            self._persist_workflow_capability_controls(plan["writes"])
            if plan["ok"] is not True:
                raise _plan_failure(plan["error"])
            if plan["commit"] is not True:
                return plan["result"]
            try:
                committed = self._native_store_call(
                    "workflow_capability_commit",
                    {**wire, "plan_writes": plan["writes"], "plan_post_writes": plan["post_writes"]},
                )
            except NativeGuardStoreUnavailable as error:
                if error.reason != _PLAN_STALE_REASON:
                    raise
                # The plan was never committed, so the pending control it saved
                # has no ledger entry. Put back the last unpended control: the
                # original, or on a first issue the freshly bootstrapped one,
                # which is the first write of the plan. Otherwise the retry
                # would see an unresolved pending sequence and lock authority.
                baseline = original if original is not None else (plan["writes"][0] if plan["writes"] else None)
                if baseline is not None and not self._store_workflow_capability_control(baseline):
                    raise WorkflowCapabilityError("capability_control_unavailable") from error
                continue
            self._persist_workflow_capability_controls(committed["post_writes"])
            return committed["result"]
        raise WorkflowCapabilityError("capability_plan_stale")

    @serialized_workflow_capability_authority
    def issue_workflow_capability(
        self,
        claim: WorkflowCapabilityClaim,
        *,
        approval_provenance_id: str,
    ) -> SignedWorkflowCapability:
        """Issue a claim the resident signs with the capability key."""

        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        if type(claim) is not WorkflowCapabilityClaim:
            raise WorkflowCapabilityError("invalid_capability_claim")
        issued = self._run_workflow_capability(
            "issue",
            now,
            {
                "claim_json": _canonical_json(asdict(claim)),
                "approval_provenance_id": approval_provenance_id,
            },
        )
        if not isinstance(issued, Mapping):
            raise WorkflowCapabilityError("invalid_signed_capability")
        return SignedWorkflowCapability.from_dict(dict(issued))

    @serialized_workflow_capability_authority
    def claim_workflow_capability(
        self,
        capability_id: str,
        *,
        invocation_id: str,
        expected_binding: WorkflowCapabilityBinding,
        expected_subject_id: str,
        expected_task_id: str,
        expected_issuer_id: str,
        expected_approval_provenance_id: str,
    ) -> SignedWorkflowCapabilityReceipt:
        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        if type(expected_binding) is not WorkflowCapabilityBinding:
            raise WorkflowCapabilityError("invalid_expected_capability_binding")
        receipt = self._run_workflow_capability(
            "claim",
            now,
            {
                "capability_id": capability_id,
                "invocation_id": invocation_id,
                "expected_binding": asdict(expected_binding),
                "expected_subject_id": expected_subject_id,
                "expected_task_id": expected_task_id,
                "expected_issuer_id": expected_issuer_id,
                "expected_approval_provenance_id": expected_approval_provenance_id,
                "receipt_id": f"wcr-{uuid4().hex}",
            },
        )
        return SignedWorkflowCapabilityReceipt.from_dict(receipt)

    @serialized_workflow_capability_authority
    def revoke_workflow_capability(self, capability_id: str, *, reason_code: str) -> bool:
        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        return bool(
            self._run_workflow_capability(
                "revoke",
                now,
                {
                    "capability_id": capability_id,
                    "reason_code": reason_code,
                    "revocation_id": f"wcv-{uuid4().hex}",
                },
            )
        )

    @serialized_workflow_capability_authority
    def lookup_workflow_capability(self, capability_id: str) -> SignedWorkflowCapability | None:
        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        signed = self._run_workflow_capability("lookup", now, {"capability_id": capability_id})
        return None if signed is None else SignedWorkflowCapability.from_dict(signed)

    @serialized_workflow_capability_authority
    def lookup_workflow_capability_receipt(
        self,
        *,
        receipt_id: str | None = None,
        invocation_id: str | None = None,
    ) -> SignedWorkflowCapabilityReceipt | None:
        now = WORKFLOW_CAPABILITY_STORE_CLOCK.now()
        signed = self._run_workflow_capability(
            "receipt_lookup",
            now,
            {"receipt_id": receipt_id, "invocation_id": invocation_id},
        )
        return None if signed is None else SignedWorkflowCapabilityReceipt.from_dict(signed)
