"""Atomic persistence and current-authority checks for signed Review memory."""

# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import json
import sqlite3
from typing import cast

from .config_mutation import notify_native_policy_mutation
from .policy_integrity import MEMORY_POLICY_SOURCES
from .review_contracts import validate_decision_memory_bundle_target, validated_decision_memory_bundle
from .review_memory_ack import build_decision_memory_ack
from .review_memory_application import MemoryApplicationBinding
from .review_memory_authority import (
    ACK_KEY,
    REGISTRY_KEY,
    VERSION_KEY,
    bound_registry,
    decision_from_memory_rule,
    encode_registry,
    memory_oauth_authority,
    registry_entries,
    text,
)
from .review_memory_mutation_validation import validate_decision_memory_mutation_ids
from .review_oauth_binding import GuardReviewContractError
from .store_base import _canonical_utc_timestamp


def _read_state(connection: sqlite3.Connection, key: str) -> object:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
    try:
        return json.loads(str(row["payload_json"])) if row is not None else None
    except (TypeError, ValueError):
        return None


def _write_state(connection: sqlite3.Connection, key: str, value: object, now: str) -> None:
    connection.execute(
        """insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
           on conflict(state_key) do update set
               payload_json = excluded.payload_json, updated_at = excluded.updated_at""",
        (key, json.dumps(value, allow_nan=False), now),
    )


class StoreReviewPolicyMemoryMixin:
    def apply_review_policy_memory_state(
        self, bundle_payload: dict[str, object], *, now: str, application: MemoryApplicationBinding | None = None
    ) -> dict[str, object]:
        """Validate the current binding/version and merge signed rules under one write lock."""
        normalized_now = _canonical_utc_timestamp(now)
        with self.hold_oauth_credential_lock(), self._connect() as connection:
            connection.execute("begin immediate")
            oauth, binding = memory_oauth_authority(self)
            bundle = validated_decision_memory_bundle(bundle_payload, store=self)
            target_oauth = oauth if application is None else application.target_oauth(oauth, bundle)
            registry = _read_state(connection, REGISTRY_KEY)
            bound = bound_registry(registry, binding, store=self)
            last_version = text(bound.get("policyVersion")) if bound is not None else None
            # A duplicate receipt is a read of its durable result, never a second mutation.
            previous_ack = bound.get("acknowledgement") if bound is not None else None
            if (
                bound is not None
                and isinstance(previous_ack, dict)
                and bound.get("bundleHash") == bundle.get("bundleHash")
                and previous_ack.get("status") == "accepted"
            ):
                if application is not None and not application.matches_ack(previous_ack):
                    raise GuardReviewContractError("decision_memory_application_binding_mismatch")
                return previous_ack
            try:
                validate_decision_memory_bundle_target(
                    bundle=bundle, oauth=target_oauth, last_policy_version=last_version
                )
                validate_decision_memory_mutation_ids(bundle)
            except GuardReviewContractError as error:
                reason = str(error)
                ack = build_decision_memory_ack(
                    bundle=bundle,
                    oauth=target_oauth,
                    status="stale" if reason == "decision_memory_policy_version_stale" else "rejected",
                    applied_rule_count=0,
                    reason=reason,
                    rejected_rule_ids=[],
                )
                _write_state(connection, ACK_KEY, ack, normalized_now)
                return ack
            accepted = {}
            rejected: list[str] = []
            rules = bundle.get("memoryRules")
            for rule in rules if isinstance(rules, list) else []:
                rule_id = text(rule.get("ruleId"))
                if rule_id is None:
                    raise GuardReviewContractError("invalid_decision_memory_rule")
                try:
                    if rule_id in accepted:
                        raise GuardReviewContractError("duplicate_decision_memory_rule")
                    accepted[rule_id] = (
                        bundle,
                        decision_from_memory_rule(bundle=bundle, rule=rule, oauth=target_oauth),
                    )
                except GuardReviewContractError:
                    rejected.append(rule_id)
            if rejected:
                ack = build_decision_memory_ack(
                    bundle=bundle,
                    oauth=target_oauth,
                    status="rejected",
                    applied_rule_count=0,
                    reason="decision_memory_rule_rejected",
                    rejected_rule_ids=rejected,
                )
                _write_state(connection, ACK_KEY, ack, normalized_now)
                return ack
            entries = registry_entries(registry, store=self, oauth=oauth, binding=binding, now=normalized_now)
            revocations = bundle.get("revocations")
            for rule_id in revocations if isinstance(revocations, list) else []:
                if isinstance(rule_id, str):
                    entries.pop(rule_id, None)
            entries.update(accepted)
            ack = build_decision_memory_ack(
                bundle=bundle,
                oauth=target_oauth,
                status="accepted",
                applied_rule_count=len(accepted),
                reason=None,
                rejected_rule_ids=[],
            )
            _, rows = self._prepared_remote_policy_rows(
                [decision for _, decision in entries.values()],
                normalized_now,
                approval_gate_grant=None,
                remote_write_authorized=True,
            )
            self._replace_remote_policy_rows_locked(connection, rows, sources=tuple(MEMORY_POLICY_SOURCES))
            prior_registered = bound.get("registeredInstallations", {}) if bound is not None else {}
            if not isinstance(prior_registered, dict):
                raise GuardReviewContractError("decision_memory_application_binding_invalid")
            registered: dict[str, object] = dict(prior_registered)
            if application is not None:
                registered[str(bundle["bundleHash"])] = target_oauth.installation_id
            _write_state(
                connection,
                REGISTRY_KEY,
                encode_registry(
                    entries,
                    binding,
                    store=self,
                    now=normalized_now,
                    acknowledgement=ack,
                    registered_installations=registered,
                ),
                normalized_now,
            )
            _write_state(
                connection,
                VERSION_KEY,
                {
                    "policyVersion": bundle.get("policyVersion"),
                    "bundleHash": bundle.get("bundleHash"),
                    "acknowledgement": ack,
                },
                normalized_now,
            )
            _write_state(connection, ACK_KEY, ack, normalized_now)
        notify_native_policy_mutation(self.guard_home, require_source_authority=True)
        return ack

    def _cached_review_memory_decision_identities(self, *, now: str) -> frozenset[tuple[object, ...]]:
        from .policy_bundle_row_authority import PolicyBundleRowStore
        from .policy_memory_row_authority import current_review_memory_row_identities

        return current_review_memory_row_identities(cast(PolicyBundleRowStore, cast(object, self)), now=now)

    def clear_review_policy_memory_state(self) -> None:
        """Remove only memory owned by this OAuth source during explicit connection reset."""
        with self._connect() as connection:
            connection.execute("begin immediate")
            registry = _read_state(connection, REGISTRY_KEY)
            binding = registry.get("oauthBinding") if isinstance(registry, dict) else None
            if isinstance(binding, dict) and binding.get("oauthSource") != self._guard_source:
                return
            before_changes = connection.total_changes
            self._replace_remote_policy_rows_locked(connection, (), sources=tuple(MEMORY_POLICY_SOURCES))
            connection.executemany(
                "delete from sync_state where state_key = ?", [(REGISTRY_KEY,), (VERSION_KEY,), (ACK_KEY,)]
            )
            changed = connection.total_changes > before_changes
        if changed:
            notify_native_policy_mutation(self.guard_home, require_source_authority=True)
