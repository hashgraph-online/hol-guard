"""Canonical installed ingress corpus, with optional explicit background activity."""

from __future__ import annotations

import importlib.util
import json
import os
import time
from collections.abc import Mapping
from contextlib import nullcontext
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_probe_receipts import receipt_corpus_is_complete, wait_for_receipt_corpus, wait_for_route_corpus
from scripts.native_slo_activity import SloActivity
from scripts.native_slo_adapter import is_allowed
from scripts.native_slo_contract import MAX_READINESS_P95_MS

_REPO_ROOT = Path(__file__).resolve().parents[1]

_HOOK_CLIENT_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_hook_client",
    _REPO_ROOT / "ci/native_runtime/installed_hook_client.py",
)
if _HOOK_CLIENT_SPEC is None or _HOOK_CLIENT_SPEC.loader is None:
    raise RuntimeError("native_default_auto_probe_failed: installed hook client could not be loaded")
_HOOK_CLIENT_MODULE = importlib.util.module_from_spec(_HOOK_CLIENT_SPEC)
_HOOK_CLIENT_SPEC.loader.exec_module(_HOOK_CLIENT_MODULE)
_installed_hook_request = _HOOK_CLIENT_MODULE.installed_hook_request
hook_failure_detail = _HOOK_CLIENT_MODULE.hook_failure_detail


def _require(condition: bool, detail: object) -> None:
    if not condition:
        raise RuntimeError(f"native_default_auto_probe_failed: {detail}")


def _ownership_routes() -> dict[str, dict[str, str]]:
    path = _REPO_ROOT / "docs/guard/contracts/hook-data-plane-ownership.v2.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    routes = payload.get("harness_routes") if isinstance(payload, dict) else None
    if not isinstance(routes, dict):
        raise RuntimeError("native_default_auto_probe_failed: ownership routes missing")
    decoded: dict[str, dict[str, str]] = {}
    for harness, route in routes.items():
        if not isinstance(harness, str) or not isinstance(route, dict):
            raise RuntimeError("native_default_auto_probe_failed: ownership route invalid")
        pre = route.get("pre_tool_use")
        post = route.get("post_tool_use")
        if not isinstance(pre, str) or not isinstance(post, str):
            raise RuntimeError("native_default_auto_probe_failed: ownership route incomplete")
        decoded[harness] = {"pre_tool_use": pre, "post_tool_use": post}
    return decoded


def _exercise_installed_routes(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
    routes: dict[str, dict[str, str]],
    route_receipts: list[dict[str, str]],
    reason_codes: dict[str, int],
) -> None:
    for harness, route in sorted(routes.items()):
        events: list[tuple[str, dict[str, object]]] = []
        if route["pre_tool_use"].startswith("installed_"):
            events.append(
                (
                    "PreToolUse",
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "printf guard"},
                    },
                )
            )
        if route["post_tool_use"].startswith("installed_"):
            events.append(
                (
                    "PostToolUse",
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "Read",
                        "tool_response": [{"type": "text", "text": "guard baseline\n"}],
                    },
                )
            )
        for event, payload in events:
            try:
                response_payload = _installed_hook_request(daemon, guard_home, workspace, harness, event, payload)
            except TimeoutError as error:
                # Report the failed route without exposing tokens or replaying a possibly dispatched request.
                raise RuntimeError(f"installed hook transport timed out: harness={harness} event={event}") from error
            if response_payload is None:
                raise RuntimeError(f"empty response for {harness} {event}")
            _require(
                is_allowed(event, response_payload),
                hook_failure_detail(harness, event, response_payload),
            )
            reason = response_payload.get("reason_code")
            if isinstance(reason, str):
                reason_codes[reason] = reason_codes.get(reason, 0) + 1
            route_receipts.append({"harness": harness, "event": event, "route": "native_resident"})


def _exercise_mode_invariants(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
) -> dict[str, dict[str, object]]:
    mode_invariants: dict[str, dict[str, object]] = {}
    post_tool_payload: dict[str, object] = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": [{"type": "text", "text": "mode invariant\n"}],
    }
    try:
        os.environ.pop("HOL_GUARD_NATIVE", None)
        baseline = _installed_hook_request(
            daemon, guard_home, workspace, "claude-code", "PostToolUse", dict(post_tool_payload)
        )
        if not isinstance(baseline, dict):
            raise RuntimeError(f"native_default_auto_probe_failed: invalid baseline response: {baseline}")
        for mode in ("off", "shadow"):
            os.environ["HOL_GUARD_NATIVE"] = mode
            response = _installed_hook_request(
                daemon, guard_home, workspace, "claude-code", "PostToolUse", dict(post_tool_payload)
            )
            if not isinstance(response, dict):
                raise RuntimeError(f"native_default_auto_probe_failed: invalid mode response: {response}")
            # Legacy values are accepted but resolve to auto: the native
            # resident must decide exactly as it does with the variable unset.
            # Current Claude PostToolUse contract: a non-blocking native
            # outcome carries ``policy_action`` (allow/warn) plus the
            # PostToolUse hook-specific envelope. It carries no ``continue``
            # (that key only appears on terminal block responses) and no
            # ``decision``; any block/stop key would mean the tool output was
            # refused rather than passed through.
            specific = response.get("hookSpecificOutput")
            _require(
                response.get("policy_action") in {"allow", "warn"}
                and isinstance(specific, dict)
                and specific.get("hookEventName") == "PostToolUse"
                and "decision" not in response
                and "continue" not in response
                and "stopReason" not in response
                and all(
                    response.get(key) == baseline.get(key)
                    for key in ("decision", "policy_action", "reason_code", "hookSpecificOutput")
                ),
                {"mode": mode, "response": response, "baseline": baseline},
            )
            mode_invariants[mode] = {
                "decision": response.get("decision"),
                "policy_action": response.get("policy_action"),
                "reason_code": response.get("reason_code"),
                "python_oracle": getattr(daemon._server.hook_worker, "test_oracle", None) is not None,
            }
            _require(mode_invariants[mode]["python_oracle"] is False, mode_invariants[mode])
    finally:
        os.environ.pop("HOL_GUARD_NATIVE", None)
    return mode_invariants


def _installed_hook_corpus(root: Path, *, activity: SloActivity | None = None) -> dict[str, object]:
    guard_home = root / "hook-home"
    workspace = root / "hook-workspace"
    guard_home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    if activity is not None:
        activity.prepare(guard_home, workspace)
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
    )
    # Register the actual installed-hook workspace before timing the readiness
    # barrier. The publisher is already started by HookWorker construction;
    # pre-registering prevents the measured first request from paying for a
    # second workspace-overlay publication and keeps the shared readiness budget
    # meaningful on slower Intel runners.
    register_workspace = getattr(daemon._server.hook_worker.policy_snapshot_publisher, "register_workspace", None)
    if callable(register_workspace):
        _ = register_workspace(workspace)
    reason_codes: dict[str, int] = {}
    route_receipts: list[dict[str, str]] = []
    routes = _ownership_routes()
    daemon.start()
    mode_invariants: dict[str, dict[str, object]] = {}
    worker_stats = evidence_stats = None
    readiness_budget_seconds = MAX_READINESS_P95_MS / 1_000.0
    try:
        readiness_started = time.monotonic()
        prepared_policy = daemon._server.hook_worker.prepare_workspace_policy(
            workspace,
            deadline=readiness_started + readiness_budget_seconds,
        )
        readiness_elapsed = time.monotonic() - readiness_started
        _require(
            prepared_policy is not None and readiness_elapsed <= readiness_budget_seconds,
            {
                "elapsed_ms": round(readiness_elapsed * 1_000, 2),
                "policy_ready": prepared_policy is not None,
            },
        )
        with activity.background("installed_corpus", guard_home, workspace) if activity is not None else nullcontext():
            _exercise_installed_routes(daemon, guard_home, workspace, routes, route_receipts, reason_codes)
            worker_stats = wait_for_route_corpus(
                daemon._server.hook_worker.metrics,
                expected=len(route_receipts),
                timeout_seconds=45.0 if os.name == "nt" else 5.0,
            )
            writer = daemon._server.runtime_hook_evidence_writer
            # Count the route corpus receipts before the mode invariants send their
            # own PostToolUse requests, which write receipts of their own. A busy
            # store sends records through the writer's retry backoff on any
            # platform; the wait ends as soon as the corpus is durable.
            evidence_stats = wait_for_receipt_corpus(writer, expected=len(route_receipts), timeout_seconds=45.0)
            mode_invariants = _exercise_mode_invariants(daemon, guard_home, workspace)
    finally:
        daemon.stop()
    if not isinstance(worker_stats, Mapping) or not isinstance(evidence_stats, Mapping):
        raise RuntimeError("native_default_auto_probe_failed: hook corpus stats missing")
    expected = len(route_receipts)
    observed_routes_raw = worker_stats["routes"]
    if not isinstance(observed_routes_raw, dict):
        raise RuntimeError(f"native_default_auto_probe_failed: invalid route metrics: {worker_stats}")
    observed_routes = cast(dict[str, int], observed_routes_raw)
    _require(expected > 0, "installed hook corpus is empty")
    _require(expected == 23, {"expected": expected, "routes": routes})
    _require(sum(observed_routes.values()) == expected, worker_stats)
    _require(observed_routes.get("native_resident") == expected, worker_stats)
    _require(receipt_corpus_is_complete(evidence_stats, expected=expected), evidence_stats)
    return {
        "routes": route_receipts,
        "route_count": expected,
        "native_resident_decisions": observed_routes.get("native_resident", 0),
        "native_oneshot_decisions": observed_routes.get("native_oneshot", 0),
        "python_semantic_decisions": observed_routes.get("python_semantic", 0),
        "fail_safe_decisions": observed_routes.get("native_fail_safe", 0),
        "reason_code_counts": reason_codes,
        "receipt_metrics": {
            "accepted": evidence_stats["receipt_accepted"],
            "processed": evidence_stats["receipt_processed"],
            "deduped": evidence_stats["receipt_deduped"],
            "dropped": evidence_stats["receipt_dropped"],
            "failures": evidence_stats["receipt_failures"],
            "durable_pending": evidence_stats["receipt_durable_pending"],
        },
        "mode_invariants": mode_invariants,
    }
