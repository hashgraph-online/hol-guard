"""Freeze synthetic Python controller invocation accounting outcomes."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

SOURCE_HASHES = {
    "ci_runner.py": "31f49df403c127986deff9a78eaaa252e4e52c51f6f3cb9018502fe4c5cf4ef5",
    "ci_runner_preflight.py": "69f5d0368f5c763a047c554b2d9a31a63f169fd2bc8d13a14aa96d8a38a274d7",
    "ci_runner_config.py": "90e632c95ee511e048b0803c0a713b11f4ff282aad1c146e1f5ec9e4806e4bc6",
}
OUTPUT = (Path(__file__).resolve().parents[1]
          / "crates/gauntlet-evidence/tests/fixtures/python_controller_invocations_v1.json")
FILES = ("preflight.json", "provider-before.json", "provider-after.json", "controller-result.json")


def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from ci.gauntlet.benchmark import ci_runner
    from ci.gauntlet.benchmark.contracts import canonical_json

    source_dir = Path(ci_runner.__file__).parent
    for name, expected in SOURCE_HASHES.items():
        actual = hashlib.sha256((source_dir / name).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"{name} differs from frozen baseline")
    provider_fixture = json.loads((OUTPUT.parent / "python_provider_status_v1.json").read_text())
    provider_pins = provider_fixture["cases"][0]["pins"]
    before_status = provider_fixture["cases"][0]["status"]
    after_status = deepcopy(before_status)
    after_status["quota"].update(charged_tokens=100, known_tokens=100, remaining_tokens=50,
                                 requests=2, journal_hash="0" * 64)
    config_digest, manifest_digest = "2" * 64, "3" * 64
    loaded = {"config_digest": config_digest, "config": {"provider": provider_pins}}
    manifest = {"shards": [{"index": 0}]}
    cases = []

    def write(path: Path, value: dict) -> None:
        path.write_text(canonical_json(value) + "\n", encoding="utf-8")

    def capture(name: str, *, charged: int = 0, directory: bool = True,
                preflight_failed: bool = False, mutation=None) -> None:
        with tempfile.TemporaryDirectory(prefix="gauntlet-invocations-fixture-") as temporary:
            root = Path(temporary)
            attempts = root / "controller-attempts"
            if directory:
                attempts.mkdir()
                if not name.startswith("empty-"):
                    invocation = attempts / "shard-000-synthetic"
                    invocation.mkdir()
                    diagnosis = {"config_digest": config_digest, "passed": not preflight_failed}
                    write(invocation / "preflight.json", diagnosis)
                    if preflight_failed:
                        write(invocation / "result.json", {"status": "preflight-failed"})
                    else:
                        write(invocation / "provider-before.json", {"status": before_status})
                        write(invocation / "provider-after.json", {"status": after_status})
                        write(invocation / "controller-result.json", {"status": "completed"})
                        file_digests = {file: hashlib.sha256((invocation / file).read_bytes()).hexdigest()
                                        for file in FILES}
                        write(invocation / "result.json", {
                            "status": "passed", "runner_config_digest": config_digest,
                            "manifest_digest": manifest_digest, "shard": 0,
                            "provider_tokens_delta": 30, "ledger_charge_before": 70,
                            "ledger_charge_after": 100, "files": file_digests,
                        })
                    if mutation is not None:
                        mutation(invocation)
            frozen_records = None if not directory else [
                {"name": path.name, "files": {file.name: file.read_text(encoding="utf-8")
                                               for file in sorted(path.iterdir())}}
                for path in sorted(attempts.iterdir())]
            row = {"name": name, "charged_tokens": charged, "records": frozen_records}
            # Only the synthetic temporary directory relaxes Python's Linux Root
            # ownership check; production file readers are not modified.
            with patch.object(ci_runner, "private_state", side_effect=lambda path: Path(path)):
                try:
                    errors = ci_runner.audit_invocations(
                        loaded, root, manifest,
                        expected_manifest_digest=manifest_digest, charged_tokens=charged,
                    )
                    row["errors"] = errors
                except (ValueError, OSError, KeyError, TypeError) as error:
                    row["python_refusal"] = str(error)
            cases.append(row)

    capture("missing-zero", directory=False)
    capture("missing-charged", directory=False, charged=30)
    capture("empty-zero")
    capture("preflight-failed", preflight_failed=True)
    capture("valid-delta", charged=30)
    capture("aggregate-mismatch", charged=29)
    capture("wrong-preflight", charged=30, mutation=lambda path: write(path / "preflight.json", {
        "config_digest": "4" * 64, "passed": True,
    }))
    capture("wrong-manifest", charged=30, mutation=lambda path: change_result(
        path, lambda row: row.update(manifest_digest="4" * 64)))
    capture("altered-provider-file", charged=30, mutation=lambda path: write(
        path / "provider-before.json", {"status": after_status}))
    capture("halted-provider", charged=30, mutation=lambda path: change_provider(
        path, "provider-after.json", lambda row: row["status"]["quota"].update(halted=True)))
    capture("decreasing-provider", charged=30, mutation=lambda path: change_provider(
        path, "provider-after.json", lambda row: row["status"]["quota"].update(
            charged_tokens=60, known_tokens=60, remaining_tokens=90)))
    capture("wrong-ledger-delta", charged=30, mutation=lambda path: change_result(
        path, lambda row: row.update(ledger_charge_after=99)))
    capture("missing-result", charged=30, mutation=lambda path: (path / "result.json").unlink())
    capture("false-preflight-failure", preflight_failed=True, mutation=lambda path: write(
        path / "preflight.json", {"config_digest": config_digest, "passed": True}))

    OUTPUT.write_text(json.dumps({"schema": "gauntlet-controller-invocations-fixtures.v1",
                                  "source_sha256": SOURCE_HASHES, "config_digest": config_digest,
                                  "manifest_digest": manifest_digest, "provider_pins": provider_pins,
                                  "shard_count": 1, "cases": cases},
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} Python-verified cases to {OUTPUT}")


def change_result(path: Path, operation) -> None:
    row = json.loads((path / "result.json").read_text())
    operation(row)
    (path / "result.json").write_text(json.dumps(row, sort_keys=True) + "\n")


def change_provider(path: Path, name: str, operation) -> None:
    row = json.loads((path / name).read_text())
    operation(row)
    write_data = json.dumps(row, sort_keys=True) + "\n"
    (path / name).write_text(write_data)
    change_result(path, lambda result: result["files"].update({
        name: hashlib.sha256(write_data.encode()).hexdigest(),
    }))


if __name__ == "__main__":
    main()
