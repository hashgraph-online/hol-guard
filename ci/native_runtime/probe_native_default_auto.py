"""Installed-wheel proof for normalized native hook ingress defaults."""

# The probe deliberately adds the repository root to sys.path so that it can
# validate the installed package against the checked-in ownership contract.
# ruff: noqa: E402

from __future__ import annotations

import argparse
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
from ci.native_runtime.default_auto_failure import (
    DefaultAutoFailureCapture,
    bind_corpus,
    end_corpus,
    observe_corpus,
    observe_corpus_failure,
)
from ci.native_runtime.default_auto_routes import (
    _delivery_diagnostic as _delivery_diagnostic,
)
from ci.native_runtime.default_auto_routes import (
    _exercise_installed_routes,
    _exercise_mode_invariants,
    _ownership_routes,
    _require,
)
from ci.native_runtime.default_auto_startup_failure import SmokePublicationObservation
from codex_plugin_scanner.guard.config import hook_fast_path_enabled
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_resident_client import (
    close_native_residents,
    native_resident_client_failure_code,
)
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
from scripts.native_probe_receipts import (
    receipt_corpus_is_complete,
    wait_for_receipt_corpus,
    wait_for_route_corpus,
)
from scripts.native_slo_contract import MAX_READINESS_P95_MS, proof_environment_violations


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


def _prepare_empty_command_authority(store: GuardStore) -> dict[str, str]:
    """Provision generated production keys only inside this fresh CI fixture.

    An unenrolled installation deliberately blocks native command review. This
    synthetic allow corpus therefore needs an authenticated empty authority,
    as does the existing installed Extension Control Center CI fixture. There
    is no interactive enrollment claim and no invented protected health/ACK.
    """

    from scripts.native_slo_command_fixture import prepare_empty_command_authority

    return prepare_empty_command_authority(store)


def _native_state_files(guard_home: Path) -> list[Path]:
    return list((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))


def _stop_native_runtime(runtime: Path, guard_home: Path) -> None:
    # Join the scoped Python supervisor before the authenticated Rust stop.
    cleanup_error: OSError | RuntimeError | None = None
    try:
        contained = close_native_residents(guard_home)
    except (OSError, RuntimeError) as exc:
        contained = False
        cleanup_error = exc
    if _native_state_files(guard_home):
        try:
            if not _stop_native_process(runtime, guard_home):
                cleanup_error = cleanup_error or RuntimeError("native resident stop did not complete")
        except (OSError, RuntimeError) as exc:
            cleanup_error = cleanup_error or exc
    # The authenticated stop can release the child while the supervisor's
    # first bounded join is still unwinding its process handles.
    if cleanup_error is None and not contained:
        try:
            contained = close_native_residents(guard_home)
        except (OSError, RuntimeError) as exc:
            cleanup_error = exc
    if cleanup_error is not None:
        raise cleanup_error
    if not contained:
        raise RuntimeError("native resident containment did not complete")


def _stop_native_process(runtime: Path, guard_home: Path) -> bool:
    try:
        result = subprocess.run(
            (str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime")),
            check=False,
            capture_output=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        print("native_default_auto_probe_cleanup_timeout", file=sys.stderr)
        return False
    if result.returncode == 0:
        return True
    # Rust maps the authenticated idempotent "no resident" result to exit 2;
    # accept it only with the exact documented error and no remaining state.
    if (
        result.returncode == 2
        and result.stderr.strip() == b"native_resident_stop_unavailable"
        and not _native_state_files(guard_home)
    ):
        return True
    print(
        f"native_default_auto_probe_cleanup_failed: returncode={result.returncode}",
        file=sys.stderr,
    )
    return False


def _publisher_error_diagnostic(publisher: object) -> str | None:
    """Retain fixed publication codes without exporting arbitrary error text."""

    code = getattr(publisher, "last_error", None)
    if code is None:
        return None
    allowed = {
        "guardconfigsourceerror",
        "oserror",
        "runtimeerror",
        "typeerror",
        "valueerror",
        "attributeerror",
        "operationalerror",
        "databaseerror",
        "native_policy_snapshot_ack_invalid",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_integrity_key_unavailable",
        "native_policy_snapshot_native_disabled",
        "native_policy_snapshot_protocol_unsupported",
        "native_policy_snapshot_publish_failed",
        "native_policy_snapshot_resident_changed",
        "native_policy_snapshot_runtime_unavailable",
        "native_policy_snapshot_workspace_capacity",
    }
    return code if type(code) is str and code in allowed else "other"


def _evidence_failure_snapshot(value: object) -> dict[str, int] | None:
    """Keep diagnostics unavailable for an installed baseline without counters."""

    try:
        from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics import evidence_failure_snapshot
    except ModuleNotFoundError as error:
        if error.name != "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics":
            raise
        return None
    return evidence_failure_snapshot(value)


def _installed_hook_corpus(root: Path) -> dict[str, object]:
    guard_home = root / "hook-home"
    workspace = root / "hook-workspace"
    guard_home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    # This direct worker probe must perform the canonical admission used by ingress.
    workspace = workspace.resolve()
    store = GuardStore(guard_home)
    command_authority_fixture = _prepare_empty_command_authority(store)
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
    bind_corpus(daemon)
    try:
        readiness_started = time.monotonic()
        prepared_policy = daemon._server.hook_worker.prepare_workspace_policy(
            workspace,
            deadline=readiness_started + readiness_budget_seconds,
        )
        readiness_elapsed = time.monotonic() - readiness_started
        readiness_ok = prepared_policy is not None and readiness_elapsed <= readiness_budget_seconds
        if not readiness_ok:
            _require(
                False,
                {
                    "elapsed_ms": round(readiness_elapsed * 1_000, 2),
                    "policy_ready": prepared_policy is not None,
                    "publisher_last_error": _publisher_error_diagnostic(
                        daemon._server.hook_worker.policy_snapshot_publisher
                    ),
                },
            )
        _exercise_installed_routes(daemon, guard_home, workspace, routes, route_receipts, reason_codes)
        worker_stats = wait_for_route_corpus(
            daemon._server.hook_worker.metrics,
            expected=len(route_receipts),
        )
        observe_corpus(daemon, worker_stats)
        writer = daemon._server.runtime_hook_evidence_writer
        mode_invariants = _exercise_mode_invariants(daemon, guard_home, workspace)
        evidence_stats = wait_for_receipt_corpus(writer, expected=len(route_receipts))
    except BaseException as error:
        observe_corpus_failure(error)
        raise
    finally:
        end_corpus(daemon, worker_stats, evidence_stats)
        daemon.stop()
    if not isinstance(worker_stats, Mapping) or not isinstance(evidence_stats, Mapping):
        raise RuntimeError("native_default_auto_probe_failed: hook corpus stats missing")
    expected = len(route_receipts)
    observed_routes_raw = worker_stats["routes"]
    if not isinstance(observed_routes_raw, dict):
        raise RuntimeError(f"native_default_auto_probe_failed: invalid route metrics: {worker_stats}")
    observed_routes = cast(dict[str, int], observed_routes_raw)
    _require(expected > 0, "installed hook corpus is empty")
    _require(expected == 21, {"expected": expected, "routes": routes})
    _require(sum(observed_routes.values()) == expected, worker_stats)
    _require(observed_routes.get("native_resident") == expected, worker_stats)
    _require(receipt_corpus_is_complete(evidence_stats, expected=expected), evidence_stats)
    return {
        "command_authority_fixture": command_authority_fixture,
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
        "evidence_failure_diagnostics": {
            "all_evidence": _evidence_failure_snapshot(evidence_stats.get("failure_diagnostics")),
            "native_receipts": _evidence_failure_snapshot(evidence_stats.get("receipt_failure_diagnostics")),
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
    with SmokePublicationObservation(root / "guard-home"), native_policy_snapshot(root / "guard-home") as snapshot:
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
        completed = False
        try:
            _run_native_smoke(root)
            health = native_runtime_health(root / "guard-home")
            _require(health.state == "healthy", health)
            _require(health.reason == "native_ready", health)
            _require(health.resident_failures == 0, health)
            _require(health.oneshot_failures == 0, health)
            _require(len(_native_state_files(root / "guard-home")) == 1, "native generation was not reused")
            corpus = _installed_hook_corpus(root)
            completed = True
            return corpus
        finally:
            cleanup_error: OSError | RuntimeError | None = None
            for guard_home in (root / "guard-home", root / "hook-home"):
                try:
                    _stop_native_runtime(identity.path, guard_home)
                except (OSError, RuntimeError) as exc:
                    message = f"native_default_auto_probe_cleanup_failed: {type(exc).__name__}"
                    print(message, file=sys.stderr)
                    cleanup_error = cleanup_error or exc
            if cleanup_error is not None and completed:
                raise cleanup_error


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
        "evidence_failure_diagnostics": installed_corpus.get("evidence_failure_diagnostics"),
        "mode_invariants": installed_corpus["mode_invariants"],
        "command_authority_fixture": installed_corpus["command_authority_fixture"],
    }


def main(*, json_path: Path | None = None) -> int:
    with DefaultAutoFailureCapture(json_path) as capture:
        _require_clean_probe_environment()
        package_path = Path(codex_plugin_scanner.__file__).resolve()
        source_package = (Path.cwd() / "src" / "codex_plugin_scanner").resolve()
        _require(
            not package_path.is_relative_to(source_package),
            f"probe imported source tree package: {package_path}",
        )

        status, identity, capabilities = _probe_native_identity()
        capture.bind_identity(identity, capabilities)
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
