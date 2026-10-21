"""Atomic recovery of authenticated Cloud Review snapshot sequence collisions."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
from .store_review_event_outbox_binding import normalized_delivery_binding

_BINDING_ORDER = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
_BINDING_KEYS = frozenset(_BINDING_ORDER)


class StoreReviewEventSequenceRecoveryMixin:
    def recover_review_snapshot_sequences(
        self,
        *,
        collisions: dict[int, str],
        acknowledged_through: int,
        binding: dict[str, str],
    ) -> dict[int, int]:
        """Atomically rebase only authenticated snapshot collision events."""

        if type(binding) is not dict or set(binding) != _BINDING_KEYS:
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
        if (
            type(collisions) is not dict
            or type(acknowledged_through) is not int
            or any(type(key) is not int or type(value) is not str for key, value in collisions.items())
        ):
            return {}
        pairs = self._native_store_call(
            "recover_review_snapshot_sequences",
            {
                "collisions": [[sequence, event_id] for sequence, event_id in collisions.items()],
                "acknowledged_through": acknowledged_through,
                "binding": dict(zip(_BINDING_ORDER, normalized_binding, strict=True)),
            },
        )
        return {int(old): int(new) for old, new in pairs}
