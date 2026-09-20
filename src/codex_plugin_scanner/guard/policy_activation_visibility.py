"""Desired, durable, and resident policy-activation stages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class NativeSnapshotPublisherView(Protocol):
    def is_ready(self) -> bool: ...

    def current_snapshot_binding(self) -> dict[str, object] | None: ...

    @property
    def last_error(self) -> str | None: ...


def _revision(value: object) -> str | int | None:
    if isinstance(value, str) and value.strip():
        return value
    if type(value) is int and value > 0:
        return value
    return None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _same_revision(left: object, right: object) -> bool:
    return _revision(left) is not None and type(left) is type(right) and left == right


def _resident_matches(
    binding: Mapping[str, object] | None,
    expected: Mapping[str, object] | None,
    revision: str | int | None,
    digest: str | None,
) -> bool:
    if not isinstance(binding, Mapping) or not isinstance(expected, Mapping):
        return False
    if not _same_revision(expected.get("bundleVersion"), revision) or expected.get("bundleHash") != digest:
        return False
    generation = expected.get("generation")
    if type(generation) is not int or generation <= 0 or type(binding.get("generation")) is not int:
        return False
    mode = expected.get("mode")
    if not isinstance(mode, str) or mode not in {"observe", "enforce"}:
        return False
    for name in ("policy_digest", "runtime_identity"):
        value = expected.get(name)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            return False
    return all(
        binding.get(name) == expected.get(name) for name in ("generation", "policy_digest", "runtime_identity", "mode")
    )


def policy_activation_visibility(
    *,
    desired_revision: str | int | None,
    desired_digest: str | None = None,
    durable_bundle: Mapping[str, object] | None,
    acknowledgement: Mapping[str, object] | None = None,
    publisher: NativeSnapshotPublisherView | None = None,
    expected_resident_binding: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Require exact source and resident evidence before reporting application.

    The expected binding must come from compiling the desired bundle. A native
    publisher's generic readiness or composite policy digest does not establish
    that connection. Older producers without source-bound evidence remain pending.
    """

    durable = durable_bundle if isinstance(durable_bundle, Mapping) else {}
    ack = acknowledgement if isinstance(acknowledgement, Mapping) else {}
    desired_revision = _revision(desired_revision)
    desired_digest = _text(desired_digest)
    durable_revision = _revision(durable.get("bundleVersion"))
    durable_digest = _text(durable.get("bundleHash"))
    durable_matches = (
        _same_revision(desired_revision, durable_revision)
        and desired_digest is not None
        and desired_digest == durable_digest
    )
    ack_status = ack.get("status")
    acknowledged = (
        durable_matches
        and isinstance(ack_status, str)
        and ack_status in {"synced", "applied"}
        and _same_revision(ack.get("bundleVersion"), durable_revision)
        and ack.get("bundleHash") == durable_digest
    )
    binding = publisher.current_snapshot_binding() if publisher is not None else None
    resident_ready = isinstance(binding, Mapping) and publisher is not None and publisher.is_ready()
    resident_matches = resident_ready and _resident_matches(
        binding,
        expected_resident_binding,
        desired_revision,
        desired_digest,
    )
    applied = acknowledged and resident_matches
    publication_error = None
    if publisher is not None and publisher.last_error:
        publication_error = "native_policy_snapshot_publish_failed"
    elif resident_ready and not resident_matches:
        publication_error = "policy_activation_resident_binding_unavailable"
    return {
        "desired_revision": desired_revision,
        "desired_digest": desired_digest,
        "durable_revision": durable_revision,
        "durable_digest": durable_digest,
        "resident_ready": resident_ready,
        "resident_digest": _text(binding.get("policy_digest")) if isinstance(binding, Mapping) else None,
        "acknowledged": acknowledged,
        "publication_pending": durable_matches and not applied,
        "publication_error": publication_error,
        "applied": applied,
        "deployment_complete": applied,
    }


__all__ = ["policy_activation_visibility"]
