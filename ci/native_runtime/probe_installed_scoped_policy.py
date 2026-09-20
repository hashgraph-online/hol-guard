"""Verify bounded signed policy through installed default-auto native authority.

The isolated TLS issuer and enrollment are synthetic. The probe never replaces
runtime discovery, capabilities, authority capture, publication, IPC or ACKs.
It does not prove ordinary OAuth, physical devices, or unsupported policy shapes.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from typing import Any, TypeVar, cast

import codex_plugin_scanner
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.hook_review_engine import HOOK_SCANNER_DEFAULT_BUDGET_MS
from codex_plugin_scanner.guard.runtime.policy_runtime_posture import local_policy_runtime_posture

# Test utilities are outside the installed package. Append only the repository
# root (never src), after loading the package which is checked below.
_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))
from ci.native_runtime.installed_scoped_policy_fixture import COMMANDS, SignedPolicyFixture  # noqa: E402
from ci.native_runtime.native_client_stage_diagnostic import observe_client_stages  # noqa: E402
from scripts.native_publication_diagnostic import (  # noqa: E402
    cleanup_preserving_failure,
    observe_publication,
    report_publication_failure,
)
from scripts.native_slo_contract import (  # noqa: E402
    MAX_READINESS_P95_MS,
    proof_environment_violations,
)
from scripts.native_slo_session import stop_native_resident  # noqa: E402


class ProbeError(RuntimeError):
    """A finite, content-free failure at a known probe assertion."""


_T = TypeVar("_T")


def present(value: _T | None, code: str) -> _T:
    if value is None:
        raise ProbeError(code)
    return value


def mapping(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ProbeError(code)
    return cast(dict[str, Any], value)


def require(condition: object, code: str) -> None:
    if not condition:
        raise ProbeError(code)


def environment_is_clean(environment: Mapping[str, str]) -> bool:
    return not proof_environment_violations(environment) and "HOL_GUARD_PYTHON_ORACLE" not in environment


def _initial_readiness_elapsed(before: float, after: float) -> float | None:
    elapsed = (after - before) * 1000
    return round(min(999_999.0, elapsed), 3) if isfinite(elapsed) and elapsed >= 0 else None


def require_initial_readiness(publisher: NativePolicySnapshotPublisher, workspace: Path) -> None:
    """Observe the original first publication; never retry or prewarm it."""
    with observe_publication(publisher) as observation, observe_client_stages() as client_stages:
        started = time.monotonic()
        deadline = started + MAX_READINESS_P95_MS / 1000
        publisher.register_workspace(workspace)
        registered = time.monotonic()
        publisher.start()
        launched = time.monotonic()
        ready = publisher.wait_until_ready(deadline)
        completed = time.monotonic()
        ready = ready and completed <= deadline
        if not ready:
            with suppress(BaseException):
                print(
                    json.dumps(
                        {
                            "schema": "guard.installed-initial-readiness-failure.v1",
                            "registration_elapsed_ms": _initial_readiness_elapsed(started, registered),
                            "start_elapsed_ms": _initial_readiness_elapsed(registered, launched),
                            "wait_elapsed_ms": _initial_readiness_elapsed(launched, completed),
                            "total_elapsed_ms": _initial_readiness_elapsed(started, completed),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
            report_publication_failure(observation, publisher, window="before_publisher_start")
            with suppress(BaseException):
                client_stages.report_failure()
        require(ready, "readiness_deadline")


def require_current_application(posture: Mapping[str, object], *, version: int, completed_cases: int) -> None:
    """Preserve the returned observation and emit only finite failure fields."""
    if posture.get("canonical_policy_application_status") == "current":
        return

    def finite(field: str, allowed: set[str]) -> str:
        value = posture.get(field)
        return value if isinstance(value, str) and value in allowed else "missing" if value is None else "other"

    with suppress(BaseException):
        print(
            json.dumps(
                {
                    "schema": "guard.installed-scoped-application-failure.v1",
                    "bundle_version": min(99, max(0, version)),
                    "completed_cases": min(99, max(0, completed_cases)),
                    "configured_lane": finite("configured_enforcement_lane", {"canonical", "legacy", "unverified"}),
                    "selected_lane": finite("selected_enforcement_lane", {"canonical", "legacy", "unverified"}),
                    "application_status": finite("canonical_policy_application_status", {"current", "unverified"}),
                    "reason": finite(
                        "canonical_incompatibility_reason",
                        {
                            "canonical_enforcement_disabled",
                            "native_policy_publication_pending",
                            "native_policy_consumer_unavailable",
                            "native_policy_authority_changed",
                            "native_policy_authority_unavailable",
                        },
                    ),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    raise ProbeError("current_application_missing")


def exercise(root: Path, runtime: Path) -> dict[str, object]:
    fixture = SignedPolicyFixture(root)
    store = fixture.store
    previous_ca = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(fixture.ca_file)
    publisher = get_native_policy_snapshot_publisher(store)
    cases: list[str] = []

    def evaluate(command: str, *, binding: dict[str, object] | None = None, payload: dict[str, object] | None = None):
        return review_raw_hook_native(
            payload=payload or {"tool_name": "Bash", "tool_input": {"command": command}, "source_scope": "project"},
            harness="codex",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=root,
            cwd=fixture.workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + HOOK_SCANNER_DEFAULT_BUDGET_MS / 1000,
            policy_snapshot=publisher.current_snapshot_binding() if binding is None else binding,
        )

    def action(expected: str, *, command: str | None = None, selected: bool = True):
        result = present(evaluate(COMMANDS[expected] if command is None else command), "native_response_missing")
        require(
            result["authority"] == "rust" and result["schema"] == "guard-hook-edge-result.v3",
            "native_authority_missing",
        )
        require(result["result"]["policy_action"] == expected, "policy_action_mismatch")
        require(
            result["result"]["decision"] == ("allow" if expected in {"allow", "warn"} else "deny"), "decision_mismatch"
        )
        binding = present(publisher.current_snapshot_binding(), "result_binding_missing")
        require(
            binding is not None and publisher.result_binding_is_current(result["policy_binding"]),
            "result_binding_stale",
        )
        for field in ("policy_digest", "runtime_identity"):
            require(result["receipt"][field] == binding[field], "receipt_binding_mismatch")
        require(result["receipt"]["policy_generation"] == binding["generation"], "receipt_generation_mismatch")
        identity = publisher.policy_rule_identity_for_result(result["policy_binding"])
        require((identity is not None) is selected, "selected_rule_mismatch")
        if selected:
            require(
                present(identity, "selected_rule_missing").rule_id == f"synthetic.{expected}",
                "selected_rule_identity_mismatch",
            )
        return result

    def sync():
        before = fixture.requests
        result = runner.sync_receipts(store)
        require(fixture.requests > before, "verified_delivery_not_observed")
        return result

    def accepted(version: int):
        fixture.bundle = fixture.signed_bundle(version)
        result = sync()
        require(result["policy_validation_status"] == "accepted", "signed_source_refused")
        require(result["policy_application_status"] == "applied", "native_application_unconfirmed")
        ack = mapping(store.get_sync_payload("policy_bundle_ack"), "applied_ack_missing")
        require(isinstance(ack, dict) and ack["status"] == "applied", "applied_ack_missing")
        require(
            ack["bundleHash"] == fixture.bundle["bundleHash"] and ack["bundleVersion"] == version, "ack_source_mismatch"
        )
        acceptance = mapping(store.get_sync_payload("native_policy_bundle_ack_acceptance"), "ack_acceptance_missing")
        require(isinstance(acceptance, dict) and acceptance["ack"] == ack, "ack_acceptance_missing")
        require(acceptance["binding"] == publisher.current_snapshot_binding(), "ack_publication_mismatch")
        posture = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        require_current_application(posture, version=version, completed_cases=len(cases))
        return copy.deepcopy(ack)

    def cleanup() -> None:
        try:
            publisher.close()
            stopped = stop_native_resident(runtime, store.guard_home, write_diagnostic=False)
            require(stopped.contained, "resident_cleanup_failed")
        finally:
            try:
                fixture.close()
            finally:
                if previous_ca is None:
                    os.environ.pop("SSL_CERT_FILE", None)
                else:
                    os.environ["SSL_CERT_FILE"] = previous_ca

    with cleanup_preserving_failure(cleanup):
        require(store.get_sync_payload("policy_bundle") is None, "fixture_source_preinstalled")
        require(
            store.get_sync_payload("policy_bundle_ack") is None and not store.list_policy_decisions(),
            "fixture_authority_preinstalled",
        )
        require_initial_readiness(publisher, fixture.workspace)
        baseline = evaluate(COMMANDS["allow"])
        require(baseline is not None and baseline["result"]["decision"] == "deny", "baseline_review_missing")
        cases.append("cold-source-free-ready")
        accepted(1)
        action("warn", command=COMMANDS["review"] + " ", selected=False)
        cases.append("signed-review-nonmatching-control")
        for outcome in COMMANDS:
            # Each exact rule changes its baseline action. The nonmatching
            # review control above establishes that this rule causes the denial.
            action(outcome)
            cases.append(f"signed-{outcome}")
        action("review", command=COMMANDS["allow"] + " ", selected=False)
        cases.append("exact-bytes-preserved")
        wrong_target = evaluate(
            COMMANDS["allow"],
            payload={
                "tool_name": "Bash",
                "tool_input": {"command": COMMANDS["allow"]},
                "source_scope": "project",
                "artifact_id": "codex:project:unrelated",
            },
        )
        require(wrong_target is None or wrong_target["result"]["decision"] == "deny", "wrong_target_allowed")
        cases.append("wrong-target-refused")
        stale = present(publisher.current_snapshot_binding(), "binding_missing")
        wrong = {**stale, "source_input_digest": "0" * 64}
        require(evaluate(COMMANDS["allow"], binding=wrong) is None, "wrong_source_binding_allowed")
        cases.append("wrong-source-binding-refused")
        intrinsic = evaluate("rm -rf /")
        require(intrinsic is None or intrinsic["result"]["decision"] == "deny", "intrinsic_floor_weakened")
        cases.append("intrinsic-floor-preserved")
        require(
            evaluate(
                COMMANDS["allow"],
                payload={
                    "tool_name": "Bash",
                    "tool_input": {"command": COMMANDS["allow"], "cmd": COMMANDS["allow"]},
                },
            )
            is None,
            "ambiguous_request_allowed",
        )
        cases.append("unsupported-shape-refused")
        current_ack = accepted(2)
        require(evaluate(COMMANDS["allow"], binding=stale) is None, "stale_generation_allowed")
        action("allow")
        cases.append("fresh-publication-retires-prior-binding")
        fixture.bundle = fixture.signed_bundle(3)
        verifier = mapping(fixture.bundle["verifier"], "fixture_verifier_invalid")
        verifier["signature"] = "invalid"
        rejected = sync()
        require(rejected["policy_validation_status"] != "accepted", "invalid_signature_accepted")
        require(store.get_sync_payload("policy_bundle_ack") == current_ack, "invalid_signature_changed_ack")
        action("allow")
        cases.append("invalid-signature-retains-last-good")
        fixture.bundle = fixture.signed_bundle(3, workspace="synthetic-other-workspace")
        rejected = sync()
        require(rejected["policy_validation_status"] != "accepted", "foreign_source_accepted")
        require(store.get_sync_payload("policy_bundle_ack") == current_ack, "foreign_source_changed_ack")
        action("allow")
        cases.append("foreign-source-retains-last-good")
        for lifetime in ("once", "session", "project", "machine", "workspace", "team"):
            fixture.bundle = fixture.signed_bundle(3, lifetime=lifetime)
            rejected = sync()
            require(rejected["policy_validation_status"] == "rejected", "unsupported_lifetime_accepted")
            require(store.get_sync_payload("policy_bundle_ack") == current_ack, "unsupported_lifetime_changed_ack")
            action("allow")
            cases.append(f"unsupported-{lifetime}-lifetime-retains-last-good")
        prior_result = action("allow")
        binding = present(publisher.current_snapshot_binding(), "revocation_binding_missing")
        keyring = {"keys": [{**fixture.verification.to_dict(), "state": "revoked"}]}
        store.set_sync_payload("policy_bundle_keyring", keyring, datetime.now(timezone.utc).isoformat())
        require(
            not publisher.result_binding_is_current(prior_result["policy_binding"]),
            "revocation_retained_current_binding",
        )
        require(not publisher.is_ready(), "revocation_retained_readiness")
        revoked = evaluate(COMMANDS["allow"], binding=binding)
        if revoked is not None:
            require(revoked["authority"] == "rust", "revoked_result_authority_missing")
            require(revoked["receipt"]["policy_generation"] == binding["generation"], "revoked_receipt_mismatch")
            for field in ("policy_digest", "runtime_identity"):
                require(revoked["receipt"][field] == binding[field], "revoked_receipt_mismatch")
            require(
                not publisher.result_binding_is_current(revoked["policy_binding"]),
                "revocation_exposed_current_result",
            )
        cases.append("revocation-prevents-current-result-exposure")
        return {
            "schema": "guard.installed-scoped-policy.v1",
            "cases": cases,
            "native_mode": "auto",
            "ordinary_oauth_exercised": False,
            "synthetic_enrollment": True,
            "canonical_rollout_enabled": True,
            "target_commands_executed": 0,
            "source_only_lane_promoted": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    args = parser.parse_args()
    report: dict[str, object] = {"schema": "guard.installed-scoped-policy.v1", "passed": False}
    try:
        require("site-packages" in Path(codex_plugin_scanner.__file__).resolve().parts, "not_installed_package")
        require(environment_is_clean(os.environ), "native_environment_override")
        require(native_mode() == "auto", "native_mode_not_auto")
        require(os.environ.get("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT") == "1", "canonical_rollout_not_configured")
        status = native_runtime_status()
        require(status.available and status.compatible and status.identity is not None, "native_unavailable")
        capabilities = present(status.capabilities, "native_capabilities_missing")
        identity = present(status.identity, "native_identity_missing")
        require(
            re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha) is not None
            and capabilities.build_sha == args.expected_source_sha,
            "native_source_mismatch",
        )
        require(
            {"policy-snapshot-v4", "policy-scoped-authority-v1", "hook-envelope-v3"} <= set(capabilities.features),
            "scoped_features_missing",
        )
        report.update(source_sha=capabilities.build_sha, runtime_sha256=identity.sha256)
        with tempfile.TemporaryDirectory(prefix="hgs-", dir=None if os.name == "nt" else "/tmp") as temporary:
            report.update(exercise(Path(temporary), identity.path))
        report["passed"] = True
    except ProbeError as error:
        report["failure"] = str(error)
    except Exception:
        report["failure"] = "probe_execution_failed"
    args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
