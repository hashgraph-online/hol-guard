"""Exact accepted native source tokens for off-hook acknowledgement commits."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .native_policy_snapshot_publisher_scoped import ScopedSnapshotBinding, scoped_binding

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


@dataclass(frozen=True, slots=True)
class NativeAcceptedPolicyBundle:
    """A captured publication observation, never an independently trusted grant."""

    epoch: int
    binding: ScopedSnapshotBinding
    source_json: str
    expires_at_ms: int

    @property
    def source(self) -> dict[str, object]:
        return cast(dict[str, object], json.loads(self.source_json))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def accepted_policy_bundle_locked(
    publisher: NativePolicySnapshotPublisher,
    *,
    bundle: Mapping[str, object],
    installation_id: str,
) -> NativeAcceptedPolicyBundle | None:
    """Inspect only immutable accepted state while the publisher condition is held."""
    publisher._mark_expired_locked()
    binding = publisher._v4_binding
    publication = publisher._v4_publication
    if scoped_binding(publisher) is None or binding is None or publication is None:
        return None
    if bundle.get("contractVersion") != "guard-policy-bundle.v2":
        return None
    sources = [source for source in publication.candidate.inputs.sources if source.get("kind") == "signed-bundle"]
    if len(sources) != 1:
        return None
    source = sources[0]
    expected = {
        "revision": bundle.get("bundleVersion"),
        "digest": bundle.get("bundleHash"),
        "workspace_id": bundle.get("workspaceId"),
        "device_id": installation_id,
    }
    if any(type(source.get(key)) is not type(value) or source.get(key) != value for key, value in expected.items()):
        return None
    # Even an expression-only or off-target source needs authenticated recency.
    if not isinstance(source.get("materialized_at"), str):
        return None
    expiry = publication.candidate.snapshot.get("expires_at_ms")
    if type(expiry) is not int or expiry <= int(publisher._wall_clock() * 1000):
        return None
    return NativeAcceptedPolicyBundle(publisher._epoch, binding, _canonical(source), expiry)


def capture_accepted_policy_bundle(
    publisher: NativePolicySnapshotPublisher,
    *,
    bundle: Mapping[str, object],
    installation_id: str,
) -> NativeAcceptedPolicyBundle | None:
    """Capture all six resident binding fields and exact signed source together."""
    with publisher._condition:
        return accepted_policy_bundle_locked(publisher, bundle=bundle, installation_id=installation_id)
