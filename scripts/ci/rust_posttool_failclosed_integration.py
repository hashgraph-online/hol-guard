#!/usr/bin/env python3
"""Real-binary PostToolUse authority, policy snapshot, and failure probes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def _run(runtime: Path, payload: dict[str, Any] | bytes) -> subprocess.CompletedProcess[bytes]:
    encoded = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"HOME", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR", "USERPROFILE", "SYSTEMROOT", "WINDIR"}
        or key.upper().startswith("LC_")
    }
    return subprocess.run(  # noqa: UP022
        (str(runtime), "hook", "--stdin"),
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=runtime.parent,
        env=environment,
        check=False,
        timeout=5,
    )


def _decode(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any] | None:
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _snapshot(rule_digest: str, generation: int, mode: str = "enforce") -> dict[str, Any]:
    config_digest = hashlib.sha256(json.dumps({"mode": mode}, sort_keys=True).encode()).hexdigest()
    policy_digest = hashlib.sha256(
        json.dumps({"config_digest": config_digest, "rule_digest": rule_digest}, sort_keys=True).encode()
    ).hexdigest()
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }


def _request(workspace: Path, rule_digest: str, output: str, generation: int) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "request_id": f"posttool-{generation}",
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload": {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/example.ts"},
            "tool_response": [{"type": "text", "text": output}],
        },
        "cwd": str(workspace),
        "home_dir": str(workspace),
        "guard_home": str(workspace / ".guard"),
        "source_ref_external_allowed": False,
        "observe_mode": False,
        "deadline_budget_ms": 2_000,
        "policy_snapshot": _snapshot(rule_digest, generation),
    }


def _run_current(runtime: Path, request: dict[str, Any]) -> subprocess.CompletedProcess[bytes]:
    snapshot = request["policy_snapshot"]
    state_path = Path(request["guard_home"]) / "native-policy-generation.json"
    state_path.write_text(
        json.dumps(
            {
                "schema": "hol-guard-native-policy-generation.v1",
                "generation": snapshot["generation"],
                "policy_digest": snapshot["policy_digest"],
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    state_path.chmod(0o600)
    return _run(runtime, request)


def _decision(value: dict[str, Any]) -> str:
    raw = value.get("decision")
    return raw.lower() if isinstance(raw, str) else ""


def _require_native_error(result: subprocess.CompletedProcess[bytes], reason: str) -> None:
    blob = result.stderr.decode("utf-8", "replace") + result.stdout.decode("utf-8", "replace")
    if result.returncode == 0 or reason not in blob:
        raise SystemExit(f"expected native error {reason}, got rc={result.returncode} output={blob[:240]!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.expanduser().resolve(strict=True)
    capabilities_result = subprocess.run(  # noqa: UP022
        (str(runtime), "capabilities", "--json"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=3,
    )
    capabilities = _decode(capabilities_result)
    if capabilities is None:
        raise SystemExit("native capabilities failed")
    rule_digest = capabilities.get("rule_digest")
    features = capabilities.get("features")
    if not isinstance(rule_digest, str) or len(rule_digest) != 64:
        raise SystemExit("native rule digest missing")
    if not isinstance(features, list) or "policy-snapshot-v3" not in features:
        raise SystemExit("native policy snapshot capability missing")

    evidence: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-posttool-") as temporary:
        workspace = Path(temporary)
        (workspace / ".guard").mkdir(mode=0o700)

        safe = _decode(
            _run_current(runtime, _request(workspace, rule_digest, "export const value = 1;\n", time.time_ns()))
        )
        if safe is None or _decision(safe) != "allow":
            raise SystemExit("safe PostToolUse did not produce native allow")
        evidence.append({"case": "safe-inline", "decision": _decision(safe)})

        secret = _decode(
            _run_current(
                runtime,
                _request(
                    workspace,
                    rule_digest,
                    "AKIAAAAAAAAAAAAAAAAA\n",
                    time.time_ns(),
                ),
            )
        )
        if secret is None or _decision(secret) == "allow":
            raise SystemExit("secret-bearing PostToolUse did not fail closed")
        evidence.append({"case": "secret-inline", "decision": "blocked"})

        bad_rule = _request(workspace, rule_digest, "safe\n", time.time_ns())
        bad_rule["policy_snapshot"]["rule_digest"] = "0" * 64
        bad_result = _run_current(runtime, bad_rule)
        _require_native_error(bad_result, "native_policy_snapshot_rule_mismatch")
        evidence.append({"case": "rule-mismatch", "returncode": bad_result.returncode})

        malformed = _run(runtime, b'{"protocol_version":1,"event_name":"PostToolUse",')
        _require_native_error(malformed, "native_request_invalid_json")
        evidence.append({"case": "malformed", "returncode": malformed.returncode})

        oversized_output = "x" * (7 * 1024 * 1024)
        oversized = _run_current(runtime, _request(workspace, rule_digest, oversized_output, time.time_ns()))
        _require_native_error(oversized, "native_request_too_large")
        evidence.append({"case": "oversized", "returncode": oversized.returncode})

    report = {
        "schema": "hol-guard-rust-posttool-authority.v1",
        "runtime": runtime.name,
        "features": sorted(str(item) for item in features if isinstance(item, str)),
        "evidence": evidence,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
