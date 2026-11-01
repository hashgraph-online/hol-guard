"""Shared fixtures for native policy snapshot tests."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace


def _config() -> dict[str, object]:
    return {
        "mode": "prompt",
        "protection_posture": "protected",
        "security_level": "balanced",
        "default_action": "warn",
        "unknown_publisher_action": "review",
        "changed_hash_action": "require-reapproval",
        "new_network_domain_action": "warn",
        "subprocess_action": "warn",
        "risk_actions": {"prompt_injection": "block"},
        "harness_risk_actions": {},
        "harness_actions": {},
        "publisher_actions": {},
        "artifact_actions": {},
        "sandbox_analysis": "off",
        "receipt_redaction_level": "full",
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(
            rule_digest="b" * 64,
            features=(
                "resident-protocol-v2",
                "policy-snapshot-v3",
                "policy-snapshot-push-v1",
                "policy-snapshot-resident-generation-v1",
                "native-policy-in-memory-v1",
                "native-resident-client-v1",
                "native-command-program-v1",
                "native-command-control-fence-v1",
            ),
        ),
    )


def _resident_generation_for_home(guard_home: object) -> int | None:
    """Return the live resident generation recorded under ``guard_home``.

    The publish path materializes a real managed resident (``generation-<ms>.json``)
    under ``<guard_home>/native-runtime/resident-v3-*`` when native commit/mutation
    hooks run. A fabricated ACK must echo that resident's generation or the
    publisher's post-ACK fingerprint check correctly flags a stale responder.
    """

    if guard_home is None:
        return None
    state_dir = Path(str(guard_home)) / "native-runtime"
    generations: list[int] = []
    try:
        candidates = list(state_dir.glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return None
    for candidate in candidates:
        raw = candidate.name[len("generation-") : -len(".json")]
        if raw.isdigit():
            generations.append(int(raw))
    return max(generations) if generations else None


def _ack(
    payload: bytes,
    *,
    resident_generation: int | None = None,
    guard_home: object = None,
) -> bytes:
    snapshot = json.loads(payload)["request"]["snapshot"]
    if resident_generation is None:
        resident_generation = _resident_generation_for_home(guard_home) or 1
    return json.dumps(
        {
            "status": "accepted",
            "generation": snapshot["generation"],
            "policy_digest": snapshot["policy_digest"],
            "idempotent": False,
            "resident_generation": resident_generation,
        }
    ).encode()


class _DeterministicClock:
    def __init__(self) -> None:
        self.wall = time.time()
        self.monotonic = time.monotonic()

    def wall_time(self) -> float:
        return self.wall

    def monotonic_time(self) -> float:
        return self.monotonic
