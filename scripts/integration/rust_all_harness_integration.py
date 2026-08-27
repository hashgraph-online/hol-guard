#!/usr/bin/env python3
"""Exercise every supported PostToolUse harness through the real Rust runtime.

This integration starts the product resident transport through `HookWorker`, not
a test double. It verifies that every supported harness receives a Rust allow for
safe content and a Rust block for secret-bearing content, then validates the
privacy-safe aggregate route report. No raw payload is written to evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_route_metrics import (
    flush_native_route_metrics_report_for_tests,
    native_route_metrics_report_path,
    native_route_metrics_snapshot,
    reset_native_route_metrics_for_tests,
)
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes
from codex_plugin_scanner.guard.store import GuardStore

HARNESSES = (
    "codex",
    "claude-code",
    "copilot",
    "cursor",
    "cline",
    "gemini",
    "hermes",
    "openclaw",
    "opencode",
    "kimi",
    "grok",
    "pi",
    "omp",
    "zcode",
)
_SAFE_TEXT = "export const value = 1;\n" * 24
_SECRET_TEXT = "-----BEGIN PRIVATE KEY-----\nsynthetic-integration-value\n"


def _serialized_content_candidates(text: str) -> tuple[str, str]:
    return text, json.dumps(text, ensure_ascii=True)[1:-1]


def _contains_request_content(rendered: str) -> bool:
    return any(
        candidate in rendered
        for text in (_SAFE_TEXT, _SECRET_TEXT)
        for candidate in _serialized_content_candidates(text)
    )


def _payload(text: str, request_id: str) -> dict[str, object]:
    return {
        "request_id": request_id,
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/example.ts"},
        "tool_response": [{"type": "text", "text": text}],
    }


def _assert_safe(harness: str, result: dict[str, object]) -> None:
    if harness in {"pi", "omp"}:
        if result.get("decision") != "allow" or result.get("model_output_action") != "allow_original":
            raise RuntimeError(f"{harness} safe content was not allowed by Rust")
        return
    if result != {
        "policy_action": "allow",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }:
        raise RuntimeError(f"{harness} safe content returned an unexpected harness response")


def _assert_secret(harness: str, result: dict[str, object]) -> None:
    if harness in {"pi", "omp"}:
        if result.get("decision") != "deny" or result.get("model_output_action") != "block":
            raise RuntimeError(f"{harness} secret-bearing content was not blocked by Rust")
    elif result.get("policy_action") != "block" or result.get("model_output_action") != "block":
        raise RuntimeError(f"{harness} secret-bearing content was not blocked by Rust")
    rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)
    if "reviewed_excerpt" in result or _contains_request_content(rendered):
        raise RuntimeError(f"{harness} block response exposed request-derived content")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    if not runtime.is_file() or runtime.is_symlink():
        raise SystemExit("runtime must be a regular non-symlink file")

    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
    started = time.perf_counter()
    reset_native_route_metrics_for_tests()
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-rust-harness-") as temporary:
            root = Path(temporary)
            guard_home = root / "guard-home"
            store = GuardStore(guard_home)
            worker = HookWorker(store=store)
            for harness in HARNESSES:
                safe = worker.review_http_payload(
                    payload=_payload(_SAFE_TEXT, f"{harness}-safe"),
                    params={"runtime-harness": [harness]},
                    default_harness=harness,
                    home_dir=root,
                    guard_home=guard_home,
                    workspace=root,
                    deadline=time.monotonic() + 5.0,
                )
                _assert_safe(harness, safe)
                secret = worker.review_http_payload(
                    payload=_payload(_SECRET_TEXT, f"{harness}-secret"),
                    params={"runtime-harness": [harness]},
                    default_harness=harness,
                    home_dir=root,
                    guard_home=guard_home,
                    workspace=root,
                    deadline=time.monotonic() + 5.0,
                )
                _assert_secret(harness, secret)

            snapshot = native_route_metrics_snapshot()
            expected = len(HARNESSES) * 2
            if snapshot.get("rust_decisions") != expected:
                raise RuntimeError("not every all-harness outcome was produced by Rust")
            if snapshot.get("native_fail_safe_outcomes") != 0 or snapshot.get("python_decisions") != 0:
                raise RuntimeError("all-harness integration observed a fallback outcome")
            if snapshot.get("rust_decision_share") != 1.0:
                raise RuntimeError("all-harness Rust decision share was not 100%")
            if not flush_native_route_metrics_report_for_tests():
                raise RuntimeError("aggregate native route report did not flush")
            report_path = native_route_metrics_report_path(guard_home)
            report_text = report_path.read_text(encoding="utf-8")
            report = json.loads(report_text)
            if report.get("rust_decisions") != expected or report.get("python_decisions") != 0:
                raise RuntimeError("persisted native route report did not match all-harness outcomes")
            if _contains_request_content(report_text) or str(root) in report_text:
                raise RuntimeError("aggregate native route report contained request-derived content")
            if os.name != "nt" and stat.S_IMODE(report_path.stat().st_mode) != 0o600:
                raise RuntimeError("aggregate native route report was not owner-only")
    finally:
        close_resident_native_runtimes()
        os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
        os.environ.pop("HOL_GUARD_NATIVE", None)

    evidence = {
        "schema": "hol-guard-rust-all-harness-integration.v1",
        "harnesses": len(HARNESSES),
        "safe_decisions": len(HARNESSES),
        "secret_blocks": len(HARNESSES),
        "rust_decisions": len(HARNESSES) * 2,
        "native_fail_safe_outcomes": 0,
        "python_decisions": 0,
        "raw_content_persisted": False,
        "elapsed_ms": round((time.perf_counter() - started) * 1_000, 3),
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.json is not None:
        args.json.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
