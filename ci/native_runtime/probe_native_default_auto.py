"""Installed-wheel proof for normalized native hook ingress defaults."""

# The probe deliberately adds the repository root to sys.path so that it can
# validate the installed package against the checked-in ownership contract.
# Keep the import guard explicit instead of relying on the caller's cwd.
# ruff: noqa: E402

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

import codex_plugin_scanner
from codex_plugin_scanner.guard.config import hook_fast_path_enabled
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
    native_mode,
    native_runtime_health,
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_adapter import is_allowed
from scripts.native_slo_contract import proof_environment_violations

_HOOK_CLIENT_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_hook_client",
    Path(__file__).with_name("installed_hook_client.py"),
)
if _HOOK_CLIENT_SPEC is None or _HOOK_CLIENT_SPEC.loader is None:
    raise RuntimeError("native_default_auto_probe_failed: installed hook client could not be loaded")
_HOOK_CLIENT_MODULE = importlib.util.module_from_spec(_HOOK_CLIENT_SPEC)
_HOOK_CLIENT_SPEC.loader.exec_module(_HOOK_CLIENT_MODULE)
_installed_hook_request = _HOOK_CLIENT_MODULE.installed_hook_request


def _request(root: Path, text: str, request_id: str) -> HookReviewRequest:
    guard_home = root / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": text}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=root,
        home_dir=root,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
    )


def _synthetic_github_token() -> str:
    return "".join(("gh", "p_", "c" * 30))


def _short_temp_parent() -> str | None:
    """Keep Unix resident socket paths below platform sun_path limits."""
    if os.name == "nt":
        return None
    candidate = Path("/tmp")
    if not candidate.is_dir() or not os.access(candidate, os.W_OK | os.X_OK):
        return None
    return str(candidate)


def _require(condition: bool, detail: object) -> None:
    """Fail the CI probe even when Python assertions are optimized out."""
    if not condition:
        raise RuntimeError(f"native_default_auto_probe_failed: {detail}")


def _permission_decision(response: Mapping[str, object]) -> str | None:
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, Mapping):
        return None
    value = specific.get("permissionDecision")
    return value if isinstance(value, str) else None


def _native_state_files(guard_home: Path) -> list[Path]:
    return list((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))


def _stop_native_runtime(runtime: Path, guard_home: Path) -> None:
    try:
        result = subprocess.run(
            (str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime")),
            check=False,
            capture_output=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        print("native_default_auto_probe_cleanup_timeout", file=sys.stderr)
        return
    if result.returncode != 0:
        print(
            f"native_default_auto_probe_cleanup_failed: returncode={result.returncode}",
            file=sys.stderr,
        )


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
            response_payload = _installed_hook_request(daemon, guard_home, workspace, harness, event, payload)
            if response_payload is None:
                raise RuntimeError(f"empty response for {harness} {event}")
            _require(
                is_allowed(event, response_payload),
                {
                    "harness": harness,
                    "event": event,
                    "decision": response_payload.get("decision"),
                    "permission_decision": _permission_decision(response_payload),
                },
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
    try:
        for mode in ("off", "shadow"):
            os.environ["HOL_GUARD_NATIVE"] = mode
            response = _installed_hook_request(
                daemon,
                guard_home,
                workspace,
                "claude-code",
                "PostToolUse",
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                    "tool_response": [{"type": "text", "text": "mode invariant\n"}],
                },
            )
            if not isinstance(response, dict):
                raise RuntimeError(f"native_default_auto_probe_failed: invalid mode response: {response}")
            _require(
                response.get("continue") is True
                and response.get("policy_action") == "allow"
                and response.get("reason_code") in {"native_hook_disabled", "native_shadow_diagnostic_disabled"},
                {"mode": mode, "response": response},
            )
            mode_invariants[mode] = {
                "decision": response.get("decision"),
                "reason_code": response.get("reason_code"),
                "python_oracle": daemon._server.hook_worker.test_oracle is not None,
            }
            _require(mode_invariants[mode]["python_oracle"] is False, mode_invariants[mode])
    finally:
        os.environ.pop("HOL_GUARD_NATIVE", None)
    return mode_invariants


def _installed_hook_corpus(root: Path) -> dict[str, object]:
    guard_home = root / "hook-home"
    workspace = root / "hook-workspace"
    guard_home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
    )
    # Register the actual installed-hook workspace before timing the readiness
    # barrier. The publisher is already started by HookWorker construction;
    # pre-registering prevents the measured first request from paying for a
    # second workspace-overlay publication and keeps the strict 250 ms budget
    # meaningful on slower Intel runners.
    register_workspace = getattr(daemon._server.hook_worker.policy_snapshot_publisher, "register_workspace", None)
    if callable(register_workspace):
        _ = register_workspace(workspace)
    reason_codes: dict[str, int] = {}
    route_receipts: list[dict[str, str]] = []
    routes = _ownership_routes()
    daemon.start()
    mode_invariants: dict[str, dict[str, object]] = {}
    try:
        readiness_started = time.monotonic()
        prepared_policy = daemon._server.hook_worker.prepare_workspace_policy(
            workspace,
            deadline=readiness_started + 0.25,
        )
        readiness_elapsed = time.monotonic() - readiness_started
        _require(
            prepared_policy is not None and readiness_elapsed <= 0.25,
            {
                "elapsed_ms": round(readiness_elapsed * 1_000, 2),
                "policy_ready": prepared_policy is not None,
            },
        )
        _exercise_installed_routes(daemon, guard_home, workspace, routes, route_receipts, reason_codes)
        worker_stats = daemon._server.hook_worker.metrics.snapshot()
        writer = daemon._server.runtime_hook_evidence_writer
        mode_invariants = _exercise_mode_invariants(daemon, guard_home, workspace)
    finally:
        daemon.stop()

    expected = len(route_receipts)
    observed_routes_raw = worker_stats["routes"]
    if not isinstance(observed_routes_raw, dict):
        raise RuntimeError(f"native_default_auto_probe_failed: invalid route metrics: {worker_stats}")
    observed_routes = cast(dict[str, int], observed_routes_raw)
    evidence_stats = writer.stats()
    _require(expected > 0, "installed hook corpus is empty")
    _require(expected == 21, {"expected": expected, "routes": routes})
    _require(sum(observed_routes.values()) == expected, worker_stats)
    _require(observed_routes.get("native_resident") == expected, worker_stats)
    _require(evidence_stats["receipt_accepted"] == expected, evidence_stats)
    _require(evidence_stats["receipt_processed"] == expected, evidence_stats)
    _require(evidence_stats["receipt_dropped"] == 0, evidence_stats)
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


def _require_clean_probe_environment() -> None:
    violations = proof_environment_violations()
    _require(not violations, {"unexpected_proof_environment": violations})
    for environment_name in (
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_HOOK_FAST_PATH",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
    ):
        _require(environment_name not in os.environ, f"{environment_name} must be unset")
    _require(native_mode() == "auto", f"unexpected native mode: {native_mode()}")
    _require(hook_fast_path_enabled(), "unset fast-path configuration must be enabled")
    os.environ["HOL_GUARD_NATIVE"] = "invalid"
    try:
        _require(native_mode() == "auto", "invalid native mode must resolve to auto")
    finally:
        os.environ.pop("HOL_GUARD_NATIVE", None)

    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (_REPO_ROOT / "src" / "codex_plugin_scanner").resolve()
    _require(
        not package_path.is_relative_to(source_package),
        f"probe imported source tree package: {package_path}",
    )


def _probe_native_identity() -> tuple[NativeRuntimeStatus, NativeRuntimeIdentity, NativeRuntimeCapabilities]:
    status = native_runtime_status()
    _require(status.mode == "auto", status)
    _require(status.available and status.compatible, status)
    _require(status.reason == "native_ready", status)
    if status.identity is None or status.capabilities is None:
        raise RuntimeError(f"native_default_auto_probe_failed: {status}")
    return status, status.identity, status.capabilities


def _assert_binary_override_ignored(identity: NativeRuntimeIdentity) -> None:
    os.environ["HOL_GUARD_NATIVE_BINARY"] = "/definitely-missing/hol-guard-runtime"
    try:
        overridden = native_runtime_status()
        _require(overridden.mode == "auto", overridden)
        _require(overridden.available and overridden.compatible, overridden)
        _require(overridden.reason == "native_ready", overridden)
        _require(
            overridden.identity is not None and overridden.identity.path == identity.path,
            {"selected": overridden.identity, "expected": identity.path},
        )
    finally:
        os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)


def _run_native_smoke(root: Path) -> None:
    with native_policy_snapshot(root / "guard-home") as snapshot:
        clean = review_post_tool_native(
            _request(root, "const value = 1;\n", "default-auto-clean"),
            observe_mode=False,
            policy_snapshot=snapshot,
        )
        if clean is None:
            raise RuntimeError(
                f"native_default_auto_probe_failed: clean response missing: {native_resident_client_failure_code()}"
            )
        _require(clean.decision == "allow", clean)
        secret = review_post_tool_native(
            _request(root, _synthetic_github_token(), "default-auto-secret"),
            observe_mode=False,
            policy_snapshot=snapshot,
        )
        if secret is None:
            raise RuntimeError("native_default_auto_probe_failed: secret response missing")
        _require(secret.decision == "deny", secret)
        _require(secret.reason_code == "output_secret_match", secret)


def _run_temporary_probe(identity: NativeRuntimeIdentity) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="hg-auto-", dir=_short_temp_parent()) as temporary:
        root = Path(temporary)
        try:
            _run_native_smoke(root)
            health = native_runtime_health(root / "guard-home")
            _require(health.state == "healthy", health)
            _require(health.reason == "native_ready", health)
            _require(health.resident_failures == 0, health)
            _require(health.oneshot_failures == 0, health)
            _require(len(_native_state_files(root / "guard-home")) == 1, "native generation was not reused")
            return _installed_hook_corpus(root)
        finally:
            for guard_home in (root / "guard-home", root / "hook-home"):
                _stop_native_runtime(identity.path, guard_home)


def _assert_native_disabled_mode() -> None:
    os.environ["HOL_GUARD_NATIVE"] = "off"
    try:
        _require(native_mode() == "off", f"unexpected native mode: {native_mode()}")
        disabled = native_runtime_status()
        _require(disabled.mode == "off", disabled)
        _require(disabled.reason == "native_disabled", disabled)
    finally:
        os.environ.pop("HOL_GUARD_NATIVE", None)


def _build_probe_receipt(
    status: NativeRuntimeStatus,
    capabilities: NativeRuntimeCapabilities,
    installed_corpus: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "hol-guard.native-default-installed-receipt.v1",
        "corpus_scope": "normalized_daemon_ingress",
        "default_mode": "auto",
        "fast_path": "enabled",
        "runtime_reason": status.reason,
        "target": capabilities.target,
        "rollback": "off",
        "corpus_decisions": installed_corpus["route_count"],
        "resident_decisions": installed_corpus["route_count"],
        "resident_share": 1.0,
        "oneshot_decisions": 0,
        "fail_safe_decisions": installed_corpus["fail_safe_decisions"],
        "python_semantic_decisions": installed_corpus["python_semantic_decisions"],
        "route_receipts": installed_corpus["routes"],
        "reason_code_counts": installed_corpus["reason_code_counts"],
        "receipt_metrics": installed_corpus["receipt_metrics"],
        "mode_invariants": installed_corpus["mode_invariants"],
    }


def main(*, json_path: Path | None = None) -> int:
    _require_clean_probe_environment()
    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (Path.cwd() / "src" / "codex_plugin_scanner").resolve()
    _require(
        not package_path.is_relative_to(source_package),
        f"probe imported source tree package: {package_path}",
    )

    status, identity, capabilities = _probe_native_identity()
    _assert_binary_override_ignored(identity)
    installed_corpus = _run_temporary_probe(identity)
    _assert_native_disabled_mode()
    receipt = _build_probe_receipt(status, capabilities, installed_corpus)
    rendered = json.dumps(receipt, sort_keys=True)
    if json_path is not None:
        json_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(main(json_path=arguments.json))
