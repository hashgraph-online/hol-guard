"""Freeze pinned Python provider status accept/refuse cases for Rust."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

SOURCE_SHA256 = "69f5d0368f5c763a047c554b2d9a31a63f169fd2bc8d13a14aa96d8a38a274d7"
OUTPUT = Path(__file__).resolve().parents[1] / "crates/gauntlet-evidence/tests/fixtures/python_provider_status_v1.json"


def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from ci.gauntlet.benchmark import ci_runner_preflight

    source = Path(ci_runner_preflight.__file__)
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise SystemExit("provider status source differs from frozen baseline")

    pins = {
        "profile": "owned-mlx-serial.v1",
        "server_sha256": "a" * 64,
        "adapter_sha256": "b" * 64,
        "quota_config_digest": "c" * 64,
        "model_identity_digest": "d" * 64,
        "binding_sha256": "e" * 64,
        "token_cap": 150,
        "maximum_requests": 3,
    }
    status = {
        "adapter": {
            "schema": "gauntlet-mlx-quota-adapter.v1",
            "server_sha256": pins["server_sha256"],
            "adapter_sha256": pins["adapter_sha256"],
            "quota_config_digest": pins["quota_config_digest"],
            "producer_mode": "serial-original-tokenization-and-generation",
            "counting": "full prompt including cached input plus every producer-emitted response token",
            "batching": False,
            "draft": False,
            "qualification_eligible": False,
        },
        "binding_sha256": pins["binding_sha256"],
        "qualification": False,
        "quota": {
            "schema": "gauntlet-provider-quota-status.v1",
            "config_digest": pins["quota_config_digest"],
            "model_identity_digest": pins["model_identity_digest"],
            "token_cap": 150,
            "charged_tokens": 70,
            "known_tokens": 70,
            "reserved_tokens": 0,
            "requests": 1,
            "maximum_requests": 3,
            "pending_requests": 0,
            "halted": False,
            "remaining_tokens": 80,
            "journal_hash": "f" * 64,
            "qualification_eligible": False,
        },
    }
    cases = []

    def record(name: str, changed_status=None, changed_pins=None) -> None:
        actual = deepcopy(status if changed_status is None else changed_status)
        outside = deepcopy(pins if changed_pins is None else changed_pins)
        try:
            result = ci_runner_preflight.verify_provider_status(actual, outside)
            cases.append({"name": name, "status": actual, "pins": outside, "quota": result})
        except ValueError as error:
            cases.append({"name": name, "status": actual, "pins": outside,
                          "python_refusal": str(error)})

    record("idle")
    extended = deepcopy(status)
    extended_pins = deepcopy(pins)
    extended_pins["quota_allowance_digest"] = "1" * 64
    extended["adapter"]["quota_allowance_digest"] = extended_pins["quota_allowance_digest"]
    extended["quota"]["allowance_digest"] = extended_pins["quota_allowance_digest"]
    record("extended-idle", extended, extended_pins)

    changes = [
        ("wrong-binding", ("binding_sha256",), "0" * 64),
        ("wrong-server", ("adapter", "server_sha256"), "0" * 64),
        ("draft-enabled", ("adapter", "draft"), True),
        ("wrong-quota-config", ("quota", "config_digest"), "0" * 64),
        ("wrong-model", ("quota", "model_identity_digest"), "0" * 64),
        ("halted", ("quota", "halted"), True),
        ("pending", ("quota", "pending_requests"), 1),
        ("reserved", ("quota", "reserved_tokens"), 1),
        ("unknown-usage", ("quota", "known_tokens"), 69),
        ("negative-remaining", ("quota", "remaining_tokens"), -1),
        ("boolean-count", ("quota", "requests"), True),
        ("over-request-limit", ("quota", "requests"), 4),
        ("wrong-journal-hash", ("quota", "journal_hash"), "X" * 64),
        ("qualified", ("quota", "qualification_eligible"), True),
    ]
    for name, path, replacement in changes:
        changed = deepcopy(status)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        record(name, changed)

    missing = deepcopy(status)
    del missing["quota"]["journal_hash"]
    record("missing-quota-field", missing)
    allowance_missing = deepcopy(extended)
    del allowance_missing["quota"]["allowance_digest"]
    record("missing-allowance", allowance_missing, extended_pins)

    OUTPUT.write_text(json.dumps({"schema": "gauntlet-provider-status-fixtures.v1",
                                  "source_sha256": SOURCE_SHA256, "cases": cases},
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} Python-verified cases to {OUTPUT}")


if __name__ == "__main__":
    main()
