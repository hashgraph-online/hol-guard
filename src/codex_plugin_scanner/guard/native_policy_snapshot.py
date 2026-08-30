"""Generation-bound native policy snapshots for PostToolUse envelopes."""

from __future__ import annotations

import hashlib
import json


def native_policy_snapshot(*, rule_digest: str, observe_mode: bool) -> dict[str, object]:
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    generation = int(policy_digest[:16], 16) or 1
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }
