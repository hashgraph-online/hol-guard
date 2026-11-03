"""Authenticated browser-to-daemon reconnect proofs for dashboard updates.

The native ``dashboard_reconnect`` kind owns the daemon discovery key, the
signed authorization store and every proof. This module forwards each request
and maps a missing native answer to the reason the daemon reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

DASHBOARD_RECONNECT_PROTOCOL_VERSION = 1
DASHBOARD_RECONNECT_CHALLENGE_TTL_SECONDS = 10
_IDENTITY_UNAVAILABLE = "dashboard_reconnect_identity_unavailable"


def _native(guard_home: Path, op: str, args: dict[str, object]) -> dict[str, Any] | None:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("dashboard_reconnect", {"op": op, **args}, guard_home=guard_home)
    except NativeRunnerAuthorityError:
        return None


def prepare_dashboard_reconnect_authorization(
    guard_home: Path,
    *,
    now_ms: int | None = None,
) -> dict[str, object]:
    """Persist and return one browser-held verifier before an update restart."""

    answer = _native(guard_home, "prepare", {"now_ms": now_ms})
    authorization = None if answer is None else answer.get("authorization")
    if not isinstance(authorization, dict):
        raise RuntimeError("dashboard reconnect authorization is unavailable")
    return authorization


def issue_dashboard_reconnect_challenge(
    guard_home: Path,
    *,
    reconnect_id: object,
    client_nonce: object,
    candidate_origin: object,
    state_id: object,
    now_ms: int | None = None,
) -> tuple[dict[str, object] | None, str]:
    """Issue a short-lived server proof for a prepared browser verifier."""

    answer = _native(
        guard_home,
        "challenge",
        {
            "reconnect_id": reconnect_id,
            "client_nonce": client_nonce,
            "candidate_origin": candidate_origin,
            "state_id": state_id,
            "now_ms": now_ms,
        },
    )
    reason = None if answer is None else answer.get("reason")
    if answer is None or not isinstance(reason, str):
        return None, _IDENTITY_UNAVAILABLE
    challenge = answer.get("challenge")
    return (challenge if isinstance(challenge, dict) else None), reason


def consume_dashboard_reconnect_challenge(
    guard_home: Path,
    *,
    challenge: dict[str, object],
    proof: object,
    expected_candidate_origin: str,
    expected_state_id: str,
    now_ms: int | None = None,
) -> tuple[bool, str]:
    """Verify one browser proof against a prepared reconnect authorization."""

    answer = _native(
        guard_home,
        "consume",
        {
            "challenge": challenge,
            "proof": proof,
            "expected_candidate_origin": expected_candidate_origin,
            "expected_state_id": expected_state_id,
            "now_ms": now_ms,
        },
    )
    reason = None if answer is None else answer.get("reason")
    if answer is None or not isinstance(reason, str):
        return False, _IDENTITY_UNAVAILABLE
    return answer.get("verified") is True, reason


def dashboard_reconnect_challenge_identity(guard_home: Path, challenge: dict[str, object]) -> str | None:
    """Return the replay-cache identity of the normalized authenticated challenge."""

    answer = _native(guard_home, "challenge_identity", {"challenge": challenge})
    identity = None if answer is None else answer.get("identity")
    return identity if isinstance(identity, str) else None
