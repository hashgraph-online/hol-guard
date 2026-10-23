"""Freeze synthetic Python v1 provider-quota journals for the Rust reader."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import uuid
from pathlib import Path

SOURCE_SHA256 = "f9dae71c6caee2a5e2e5727010d247cb5424dbe1b55c7f472a5093e10a72815e"
JSON_DATA_SHA256 = "5d7a9b3b350ac5a7c318f02af8916101551371459f487cc0e5abd037792f817e"
OUTPUT = Path(__file__).resolve().parents[1] / "crates/gauntlet-evidence/tests/fixtures/python_provider_quota_v1.json"


def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from ci.gauntlet.benchmark import provider_quota
    from ci.gauntlet.benchmark import json_data
    from ci.gauntlet.benchmark.json_data import ContractError, canonical_json, digest

    source = Path(provider_quota.__file__)
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise SystemExit("provider quota source differs from frozen baseline")
    if hashlib.sha256(Path(json_data.__file__).read_bytes()).hexdigest() != JSON_DATA_SHA256:
        raise SystemExit("canonical JSON source differs from frozen baseline")
    identifiers = iter(range(1, 10))
    provider_quota.uuid.uuid4 = lambda: uuid.UUID(hex=f"{next(identifiers):032x}")
    cases = []

    with tempfile.TemporaryDirectory(prefix="gauntlet-quota-fixture-") as directory:
        root = (Path(directory) / "quota").resolve()
        quota = provider_quota.ProviderQuota.create(
            root,
            authorization_id="synthetic-authorization",
            total_tokens=100,
            maximum_requests=3,
            model_identity_digest="a" * 64,
        )

        def record(name: str, *, valid: bool = True, events: bytes | None = None,
                   config_digest: str | None = None, allowance_digest: str | None = None) -> None:
            raw = (root / "events.jsonl").read_bytes() if events is None else events
            config = (root / "config.json").read_bytes()
            external_config = quota.expected_config_digest if config_digest is None else config_digest
            external_allowance = quota.expected_allowance_digest if allowance_digest is None else allowance_digest
            original = (root / "events.jsonl").read_bytes()
            (root / "events.jsonl").write_bytes(raw)
            try:
                reader = provider_quota.ProviderQuota(
                    root, expected_config_digest=external_config,
                    expected_allowance_digest=external_allowance,
                )
                result = reader.snapshot()
                if not valid:
                    raise AssertionError(f"{name} unexpectedly accepted")
                cases.append({"name": name, "config": config.decode(), "events": raw.decode(),
                              "config_digest": external_config, "allowance_digest": external_allowance,
                              "snapshot": result})
            except (provider_quota.QuotaDeniedError, ContractError) as error:
                if valid:
                    raise
                cases.append({"name": name, "config": config.decode(), "events": raw.decode(),
                              "config_digest": external_config, "allowance_digest": external_allowance,
                              "python_refusal_type": type(error).__name__,
                              "python_refusal": str(error)})
            finally:
                (root / "events.jsonl").write_bytes(original)

        record("empty")
        first = quota.reserve(prompt_tokens=60, output_limit=20, request_digest="b" * 64)
        record("reserved")
        reserved = (root / "events.jsonl").read_bytes()
        record("interrupted-append", valid=False, events=reserved[:-1])
        record("blank-row", valid=False, events=b"\n")
        first_row = json.loads(reserved.splitlines()[0])
        first_row["previous_hash"] = "c" * 64
        record("wrong-previous", valid=False, events=(canonical_json(first_row) + "\n").encode())
        duplicate = reserved.replace(b'"sequence":0', b'"sequence":0,"sequence":0', 1)
        record("duplicate-key", valid=False, events=duplicate)

        def append(event: dict) -> bytes:
            row = {"sequence": 1, "previous_hash": digest(json.loads(reserved.splitlines()[0])),
                   "config_digest": quota.expected_config_digest, "event": event}
            return reserved + (canonical_json(row) + "\n").encode()

        record("overlap", valid=False, events=append({
            "type": "reserve", "reservation_id": "e" * 32,
            "prompt_tokens": 1, "output_limit": 1, "request_digest": "b" * 64,
        }))
        record("wrong-settlement", valid=False, events=append({
            "type": "settle", "reservation_id": first,
            "prompt_tokens": 59, "output_tokens": 0,
        }))
        record("unknown-event", valid=False, events=append({
            "type": "unknown", "reservation_id": "e" * 32,
        }))
        record("wrong-config-pin", valid=False, config_digest="f" * 64)

        quota.settle(first, prompt_tokens=60, output_tokens=10)
        record("settled")
        state = quota.snapshot()
        quota = quota.extend_allowance(
            total_tokens=150, authorization_digest="d" * 64,
            expected_journal_hash=state["journal_hash"],
        )
        record("extended")
        record("wrong-allowance-pin", valid=False, allowance_digest="f" * 64)
        second = quota.reserve(prompt_tokens=40, output_limit=20, request_digest="b" * 64)
        record("extended-reserved")
        quota.uncertain(second, reason="synthetic transport loss")
        record("uncertain")

    OUTPUT.write_text(json.dumps({
        "source_sha256": SOURCE_SHA256,
        "json_data_sha256": JSON_DATA_SHA256,
        "schema": "gauntlet-provider-quota-fixtures.v1",
        "cases": cases,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} Python-verified cases to {OUTPUT}")


if __name__ == "__main__":
    main()
