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

    def settle_rejected_review_events(
        self,
        *,
        sequences: list[int],
        results: list[dict[str, object]],
        events: list[list[object]],
        acknowledged: list[int],
        acknowledged_through: int | None,
        binding: dict[str, str],
        changed_at: str,
    ) -> tuple[list[int], bool]:
        """Settle one batch's rejected events; returns retained indexes and progress."""

        settled = self._native_store_call(
            "settle_rejected_review_events",
            {
                "sequences": sequences,
                "results": results,
                "events": events,
                "acknowledged": acknowledged,
                "acknowledged_through": acknowledged_through,
                "binding": {key: binding.get(key) for key in _BINDING_ORDER},
                "changed_at": changed_at,
            },
        )
        return [int(index) for index in settled["retained"]], bool(settled["progressed"])

    def forget_review_rejection_counts(self, *, sequences: list[int], changed_at: str) -> None:
        self._native_store_call("forget_review_rejection_counts", {"sequences": sequences, "changed_at": changed_at})
