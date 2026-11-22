"""Presence reads a policy lookup takes before it gathers integrity evidence.

The native store answers which kinds of saved rows exist and names the head
of the stored extension-control authority snapshot. Both answers are checked
strictly here: a malformed answer raises instead of being read as "no rows".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

_PRESENCE_FIELDS: Final = frozenset({"local_policy", "remote_policy", "local_once", "policy_bundle"})


class NativePolicyPresenceError(RuntimeError):
    """The native store gave no well-formed presence answer."""


@dataclass(frozen=True, slots=True)
class PolicyRowPresence:
    local_policy: bool
    remote_policy: bool
    local_once: bool
    policy_bundle: bool

    @property
    def any_saved(self) -> bool:
        return self.local_policy or self.remote_policy or self.local_once


def policy_row_presence(store: Any) -> PolicyRowPresence:
    """Which saved policy rows exist: local, remote, local-once and policy-bundle."""

    method = "policy_row_presence"
    answer = store._native_store_call(method, {})
    if not isinstance(answer, dict) or set(answer) != _PRESENCE_FIELDS:
        raise NativePolicyPresenceError(f"native {method} returned no answer")
    if not all(type(answer[name]) is bool for name in _PRESENCE_FIELDS):
        raise NativePolicyPresenceError(f"native {method} returned no answer")
    return PolicyRowPresence(
        local_policy=answer["local_policy"],
        remote_policy=answer["remote_policy"],
        local_once=answer["local_once"],
        policy_bundle=answer["policy_bundle"],
    )


def extension_control_authority_base(store: Any) -> dict[str, object]:
    """The stored authority snapshot a policy clear replaces, or ``{}`` when none is stored."""

    method = "extension_control_authority_head"
    answer = store._native_store_call(method, {})
    if answer is None:
        return {}
    if not isinstance(answer, dict) or set(answer) != {"revision", "snapshot_digest"}:
        raise NativePolicyPresenceError(f"native {method} returned no answer")
    revision, digest = answer["revision"], answer["snapshot_digest"]
    if type(revision) is not int or not isinstance(digest, str):
        raise NativePolicyPresenceError(f"native {method} returned no answer")
    return {"base_revision": revision, "base_snapshot_digest": digest}


__all__ = [
    "NativePolicyPresenceError",
    "PolicyRowPresence",
    "extension_control_authority_base",
    "policy_row_presence",
]
