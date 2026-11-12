"""Atomic persistence boundary for Cloud Review policy memory."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Protocol

from .approval_gate import ApprovalGateGrant
from .models import PolicyDecision
from .runtime.extension_control_authority import ExtensionControlAuthorityError


class _PolicyMemoryStore(Protocol):
    def _authority_key(self, *, required: bool) -> bytes | None: ...

    def _extension_control_authority_op(self, op: str, *, key: bytes | None, **fields: object) -> dict[str, object]: ...

    def _prepared_remote_policy_rows(
        self,
        decisions: Sequence[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None,
        remote_write_authorized: bool,
        signed_bundle: bool = False,
    ) -> tuple[str, list[tuple[object, ...]]]: ...


class StoreReviewPolicyMemoryMixin:
    def apply_review_policy_memory_state(
        self: _PolicyMemoryStore,
        decisions: Sequence[PolicyDecision],
        *,
        registry: Sequence[Mapping[str, object]],
        version: Mapping[str, object],
        acknowledgement: Mapping[str, object],
        now: str,
    ) -> None:
        """Atomically publish policy-memory rows and their durable cursor state."""

        normalized_now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=None,
            remote_write_authorized=True,
        )
        encoded_state = {
            "guard_review_memory_registry": json.dumps(list(registry), allow_nan=False),
            "guard_review_memory_policy_version": json.dumps(dict(version), allow_nan=False),
            "guard_review_memory_last_ack": json.dumps(dict(acknowledgement), allow_nan=False),
        }
        # The resident replaces the remote decisions and writes the memory
        # state in one transaction.
        reply = self._extension_control_authority_op(
            "apply_review_memory",
            key=self._authority_key(required=False),
            now=normalized_now,
            review_memory={"payloads": encoded_state, "rows": [list(row) for row in rows]},
        )
        if reply.get("applied") is not True:
            raise ExtensionControlAuthorityError("invalid review memory reply")


__all__ = ["StoreReviewPolicyMemoryMixin"]
