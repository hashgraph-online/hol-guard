"""Derive persisted row identities from current authenticated bundle authority."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .models import PolicyDecision
from .policy_bundle_decisions import build_policy_bundle_decisions
from .policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY, verified_policy_materialization_time
from .policy_bundle_staging import prepare_canonical_policy_bundle_staging
from .policy_rule_identity import PolicyRuleIdentity, canonical_rule_identity
from .store_base import _canonical_utc_timestamp
from .synced_policy import SyncPayloadReader, cached_policy_bundle_validation


class PolicyBundleRowStore(SyncPayloadReader, Protocol):
    def get_device_metadata(self) -> Mapping[str, str]: ...

    def _normalized_policy_keys(
        self, decision: PolicyDecision
    ) -> tuple[str | None, str | None, str | None, str | None]: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


def current_policy_bundle_row_authorities(
    store: PolicyBundleRowStore, *, now: float | None = None
) -> dict[tuple[object, ...], PolicyRuleIdentity | None]:
    """Authenticate the source before admitting either legacy or canonical rows."""

    validated_bundle, _reason = cached_policy_bundle_validation(store, store.get_sync_payload("policy_bundle"), now=now)
    if validated_bundle is None:
        return {}
    try:
        device = store.get_device_metadata()
        if validated_bundle.get("contractVersion") == "guard-policy-bundle.v2":
            decisions = prepare_canonical_policy_bundle_staging(
                validated_bundle,
                device_id=str(device["installation_id"]),
                device_name=str(device["device_label"]),
            ).decisions
        else:
            decisions = tuple(
                build_policy_bundle_decisions(
                    validated_bundle,
                    device_id=str(device["installation_id"]),
                    device_name=str(device["device_label"]),
                )
            )
        if not decisions:
            return {}
        key, key_id = store._policy_integrity_secret_material(create=False)
        materialized_at = verified_policy_materialization_time(
            store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY),
            bundle=validated_bundle,
            device_id=str(device["installation_id"]),
            key=key,
            key_id=key_id,
        )
        if materialized_at is None:
            return {}
        identities: dict[tuple[object, ...], PolicyRuleIdentity | None] = {}
        for decision in decisions:
            artifact_id, artifact_hash, workspace, publisher = store._normalized_policy_keys(decision)
            identities[
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.exact_command_sha256,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None,
                    materialized_at,
                )
            ] = canonical_rule_identity(
                validated_bundle, decision.owner, installation_id=str(device["installation_id"])
            )
        return identities
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return {}


def current_policy_bundle_row_identities(
    store: PolicyBundleRowStore, *, now: float | None = None
) -> frozenset[tuple[object, ...]]:
    return frozenset(current_policy_bundle_row_authorities(store, now=now))


__all__ = ["PolicyBundleRowStore", "current_policy_bundle_row_authorities", "current_policy_bundle_row_identities"]
