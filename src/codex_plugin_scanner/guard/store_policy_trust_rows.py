"""Native store methods for the rows a cached policy bundle is judged against."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...


# A sync landing between the deferred bundle read and its confirming snapshot
# is retried this many times before the read gives up.
_DEFERRED_BUNDLE_ATTEMPTS = 3


def _row(value: object) -> dict[str, object] | list[object] | None:
    if isinstance(value, (dict, list)):
        return value
    return None


def _workspace_id(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


@dataclass(frozen=True)
class PolicyBundleTrustRows:
    """The cached bundle, the keyrings and checkpoint that judge it, its workspace and delivery rows.

    Every field holds the stored object or list, or ``None`` when the row is
    absent or malformed, exactly as ``get_sync_payload`` reported it.
    """

    policy_bundle: dict[str, object] | list[object] | None = None
    policy_bundle_keyring: dict[str, object] | list[object] | None = None
    acceptance_checkpoint: dict[str, object] | list[object] | None = None
    managed_keyring_provenance: dict[str, object] | list[object] | None = None
    supply_chain_keyring: dict[str, object] | list[object] | None = None
    review_verification_keyring: dict[str, object] | list[object] | None = None
    policy_bundle_ack: dict[str, object] | list[object] | None = None
    sync_summary: dict[str, object] | list[object] | None = None
    policy_bundle_last_error: dict[str, object] | list[object] | None = None
    workspace_id: str | None = None

    @classmethod
    def from_native(cls, answer: object, *, policy_bundle: object = None) -> PolicyBundleTrustRows:
        """The view from a native answer; ``policy_bundle`` fills in a bundle the answer deferred."""

        if not isinstance(answer, dict):
            raise RuntimeError("native policy_bundle_trust_rows returned no answer")
        bundle = policy_bundle if answer.get("policy_bundle_deferred") is True else answer.get("policy_bundle")
        return cls(
            policy_bundle=_row(bundle),
            policy_bundle_keyring=_row(answer.get("policy_bundle_keyring")),
            acceptance_checkpoint=_row(answer.get("acceptance_checkpoint")),
            managed_keyring_provenance=_row(answer.get("managed_keyring_provenance")),
            supply_chain_keyring=_row(answer.get("supply_chain_keyring")),
            review_verification_keyring=_row(answer.get("review_verification_keyring")),
            policy_bundle_ack=_row(answer.get("policy_bundle_ack")),
            sync_summary=_row(answer.get("sync_summary")),
            policy_bundle_last_error=_row(answer.get("policy_bundle_last_error")),
            workspace_id=_workspace_id(answer.get("workspace_id")),
        )


def _deferred_bundle(store: _NativeStore) -> object:
    """The bundle row read on its own; an unreadable row is absent, as the native reader treats it."""

    try:
        return store.get_sync_payload("policy_bundle")
    except ValueError:
        return None


class StorePolicyTrustRowsMixin:
    """One consistent read of the policy bundle trust rows, and the Review keyring write."""

    def policy_bundle_trust_rows(self: _NativeStore, *, keys_only: bool = False) -> PolicyBundleTrustRows:
        """The bundle and every row it is judged against, read in one snapshot.

        ``keys_only`` leaves the bundle out for readers that need only the
        keyrings. A bundle too large for one native reply is read on its own;
        a second snapshot must then match the first, so the bundle and its
        keyrings, checkpoint and workspace still come from the same sync.
        """

        if keys_only:
            return PolicyBundleTrustRows.from_native(
                self._native_store_call("policy_bundle_trust_rows", {"keys_only": True})
            )
        for _attempt in range(_DEFERRED_BUNDLE_ATTEMPTS):
            answer = self._native_store_call("policy_bundle_trust_rows", {})
            if not isinstance(answer, dict) or answer.get("policy_bundle_deferred") is not True:
                return PolicyBundleTrustRows.from_native(answer)
            bundle = _deferred_bundle(self)
            if self._native_store_call("policy_bundle_trust_rows", {}) == answer:
                return PolicyBundleTrustRows.from_native(answer, policy_bundle=bundle)
        raise RuntimeError("policy bundle trust rows kept changing while the bundle was read")

    def record_review_verification_keyring(self: _NativeStore, keys: Sequence[Mapping[str, object]], now: str) -> None:
        """Store the anchored Review verification keys; an empty list clears the keyring."""

        self._native_store_call(
            "record_review_verification_keyring",
            {"keys": [dict(key) if isinstance(key, Mapping) else key for key in keys], "now": now},
        )


__all__ = ["PolicyBundleTrustRows", "StorePolicyTrustRowsMixin"]
