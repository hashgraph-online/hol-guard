"""Atomic recovery of authenticated Cloud Review snapshot sequence collisions."""

from __future__ import annotations

from .store_review_event_outbox_binding import normalized_delivery_binding
from .store_review_event_outbox_writes import recover_review_snapshot_sequences as recover_in_transaction

# pyright: reportAttributeAccessIssue=false


class StoreReviewEventSequenceRecoveryMixin:
    def recover_review_snapshot_sequences(
        self,
        *,
        collisions: dict[int, str],
        acknowledged_through: int,
        binding: dict[str, str],
    ) -> dict[int, int]:
        """Atomically rebase only authenticated snapshot collision events."""

        if type(binding) is not dict or set(binding) != {
            "oauth_subject_hash",
            "workspace_id",
            "machine_id",
            "machine_installation_id",
        }:
            return {}
        try:
            normalized_binding = normalized_delivery_binding(
                oauth_subject_hash=binding["oauth_subject_hash"],
                workspace_id=binding["workspace_id"],
                machine_id=binding["machine_id"],
                machine_installation_id=binding["machine_installation_id"],
            )
        except (AttributeError, TypeError, ValueError):
            return {}
        # The canonical connection context owns commit, rollback, and close for every return path.
        with self._connect() as connection:
            return recover_in_transaction(
                connection,
                source=self._guard_source,
                collisions=collisions,
                acknowledged_through=acknowledged_through,
                binding=normalized_binding,
            )
