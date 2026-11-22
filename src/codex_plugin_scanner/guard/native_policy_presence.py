"""Presence reads a policy lookup takes before it gathers integrity evidence.

The native store answers which kinds of saved rows exist and names the head
of the stored extension-control authority snapshot. Both answers are checked
strictly here: a malformed answer raises instead of being read as "no rows".

A native store call first provisions the resident's verifier key, and that
mints policy-integrity key material. A lookup must not mint keys on a home that
was never provisioned, so until the verifier key exists the row presence is
read from SQLite here instead, without touching the keyring.

An operation that already holds the store's shared connection scope (the MCP
tool-call decision does) reads presence on that connection too. A native call
there would add a resident round trip to a hot path whose budget allows none.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NativePolicySnapshotError
from .native_policy_snapshot_windows_support import _runtime_state_directory
from .policy_integrity import REMOTE_POLICY_SOURCES
from .store_connection_scope import owns_scope

_PRESENCE_FIELDS: Final = frozenset({"any_saved", "local_policy", "remote_policy", "local_once", "policy_bundle"})


class NativePolicyPresenceError(RuntimeError):
    """The native store gave no well-formed presence answer."""


@dataclass(frozen=True, slots=True)
class PolicyRowPresence:
    local_policy: bool
    remote_policy: bool
    local_once: bool
    policy_bundle: bool
    any_saved: bool


def policy_row_presence(store: Any) -> PolicyRowPresence:
    """Which saved policy rows exist: local, remote, local-once and policy-bundle."""

    if owns_scope(store) or not _resident_provisioned(store):
        return _sqlite_presence(store)
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
        any_saved=answer["any_saved"],
    )


def _resident_provisioned(store: Any) -> bool:
    try:
        verifier = _runtime_state_directory(Path(store.guard_home)) / NATIVE_POLICY_VERIFIER_KEY_NAME
    except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return verifier.is_file()


def _sqlite_presence(store: Any) -> PolicyRowPresence:
    """The presence read for an unprovisioned home or an open connection scope."""

    remote = tuple(sorted(REMOTE_POLICY_SOURCES))
    marks = ",".join("?" for _ in remote)
    with store._connect() as connection:
        row = connection.execute(
            f"""
            select
              exists(select 1 from policy_decisions where source not in ({marks})),
              exists(select 1 from policy_decisions where source in ({marks})),
              exists(select 1 from guard_local_once_approvals),
              exists(select 1 from policy_decisions where source = 'policy-bundle')
            """,
            (*remote, *remote),
        ).fetchone()
    local_policy, remote_policy, local_once, policy_bundle = (bool(value) for value in row)
    return PolicyRowPresence(
        local_policy=local_policy,
        remote_policy=remote_policy,
        local_once=local_once,
        policy_bundle=policy_bundle,
        any_saved=local_policy or remote_policy or local_once,
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
