"""Verify signed command restrictions at the installed native HTTP boundary.

Enrollment, issuer and local passwords are disposable synthetic inputs. Runtime
selection, signed delivery, authority capture, native ACKs, receipts and the
harness HTTP adapter are real. Commands are evaluated, never executed. This
probe does not establish a builder ceremony, dependency edges absent from the
packaged catalog, ordinary OAuth, or a physical device fleet.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import codex_plugin_scanner
from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateInput,
    require_approval_decision,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.managed_controls.feature_flags import ManagedControlsFeatureFlags
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

# Append probe support only after importing the installed production package.
_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))
from ci.native_runtime.installed_hook_client import installed_hook_request  # noqa: E402
from ci.native_runtime.installed_hook_failure_diagnostic import report_hook_transport_timeout  # noqa: E402
from ci.native_runtime.installed_managed_policy_fixture import ManagedPolicyFixture  # noqa: E402
from ci.native_runtime.installed_managed_recovery import repair_local_authority  # noqa: E402
from ci.native_runtime.probe_installed_native_extensions import commit_controls, control, provision, ready  # noqa: E402
from ci.native_runtime.probe_installed_scoped_policy import (  # noqa: E402
    ProbeError,
    environment_is_clean,
    mapping,
    present,
    require,
)
from scripts.native_publication_diagnostic import cleanup_after_failure, cleanup_preserving_failure  # noqa: E402

_PERMISSION = "command.git.permission.force-push"
_IMMUTABLE_PERMISSION = "command.guard-self-protection.permission.self-authorization"
_IMMUTABLE_RULE = "command.guard-self-protection.self-authorization"
_CASES = frozenset(
    f"{prefix}-{mode}"
    for prefix in (
        "managed-permission",
        "intrinsic",
        "immutable-baseline",
        "immutable-enable-rejected",
        "managed-after-immutable-rejection",
        "managed-lockdown",
        "approved-read-lockdown",
        "recovered-lockdown",
        "recovered-managed-permission",
    )
    for mode in ("enforce", "observe")
) | {"later-local-enable", "signed-enable-rejected"}


class NativeFloorMismatchError(ProbeError):
    """Retain only finite case and decision enums, never request material."""

    def __init__(self, label: str, result: dict[str, Any], expected: str) -> None:
        super().__init__("native_floor_weakened")
        decision = result.get("decision")
        minimum = result.get("minimum_action")
        self.observation = {
            "case": label if label in _CASES else "other",
            "expected_minimum_action": expected if expected in {"block", "review"} else "invalid",
            "decision": decision if isinstance(decision, str) and decision in {"allow", "deny"} else "invalid",
            "minimum_action": minimum
            if isinstance(minimum, str)
            and minimum in {"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"}
            else "invalid",
        }


class ReceiptRequestMismatchError(ProbeError):
    """Keep finite comparisons when two independently reviewed requests differ.

    These comparisons describe the captured receipts. They do not identify
    which input changed or prove that a policy transition caused the failure.
    """

    def __init__(
        self,
        *,
        label: str,
        completed_cases: int | None,
        receipt: dict[str, Any],
        binding: dict[str, object],
        command_binding: object,
        expected_reason: str,
        expected_action: str,
    ) -> None:
        super().__init__("receipt_request_mismatch")
        self.observation = {
            "case": label if type(label) is str and label in _CASES else "other",
            "completed_cases": min(len(_CASES), max(0, completed_cases)) if type(completed_cases) is int else None,
            "matches_expected": {
                "policy_generation": receipt.get("policy_generation") == binding.get("generation"),
                "policy_digest": receipt.get("policy_digest") == binding.get("policy_digest"),
                "runtime_identity": receipt.get("runtime_identity") == binding.get("runtime_identity"),
                "command_extensions": receipt.get("command_extensions") == command_binding,
                "reason_code": receipt.get("reason_code") == expected_reason,
                "policy_action": receipt.get("policy_action") == expected_action,
            },
        }


def verify_native_floor(result: dict[str, Any], *, label: str, immutable_review: bool = False) -> None:
    expected = "review" if immutable_review else "block"
    if result.get("decision") != "deny" or result.get("minimum_action") != expected:
        raise NativeFloorMismatchError(label, result, expected)
    require(result.get("policy_action") == expected, "native_floor_action_mismatch")
    if immutable_review:
        extensions = mapping(result.get("command_extensions"), "immutable_controls_missing")
        observations = extensions.get("observations")
        require(
            isinstance(observations, list)
            and any(
                isinstance(row, dict)
                and row.get("rule_id") == _IMMUTABLE_RULE
                and row.get("effective_segment_indexes") == [0]
                and row.get("uncertainty_reasons") == []
                for row in observations
            ),
            "immutable_rule_not_observed",
        )


def verify_delivery(
    response: dict[str, object],
    *,
    binding: dict[str, object],
    receipt: object,
    command_binding: object,
    previous_receipt: object,
    expected_reason: str,
    expected_request_digest: str,
    immutable_review: bool = False,
    label: str = "other",
    completed_cases: int | None = None,
) -> None:
    """A raw floor and receipt cannot substitute for its exact HTTP disposition."""
    output = mapping(response.get("hookSpecificOutput"), "http_output_missing")
    expected = "review" if immutable_review else "block"
    require(
        output.get("permissionDecision") == ("ask" if immutable_review else "deny")
        and response.get("policy_action") == expected,
        "http_floor_weakened",
    )
    require(response.get("approval_reuse_status") != "accepted", "floor_reused_approval")
    if immutable_review:
        request_id = response.get("approval_request_id")
        require(
            isinstance(request_id, str) and bool(request_id) and response.get("prompted") is True,
            "immutable_review_not_queued",
        )
    else:
        require("approval_request_id" not in response, "block_entered_approval")
    accepted = mapping(receipt, "receipt_missing")
    for field in ("decision_id", "request_id", "request_digest"):
        value = accepted.get(field)
        require(isinstance(value, str) and bool(value), "receipt_identity_missing")
        if field != "request_digest" and isinstance(previous_receipt, dict):
            require(value != previous_receipt.get(field), "receipt_not_fresh")
    if accepted.get("request_digest") != expected_request_digest:
        raise ReceiptRequestMismatchError(
            label=label,
            completed_cases=completed_cases,
            receipt=accepted,
            binding=binding,
            command_binding=command_binding,
            expected_reason=expected_reason,
            expected_action=expected,
        )
    require(
        accepted.get("reason_code") == expected_reason and accepted.get("policy_action") == expected,
        "receipt_result_mismatch",
    )
    require(accepted.get("authority") == "rust" and accepted.get("decision") == "deny", "receipt_not_native_deny")
    require(accepted.get("policy_generation") == binding["generation"], "receipt_generation_mismatch")
    for field in ("policy_digest", "runtime_identity"):
        require(accepted.get(field) == binding[field], "receipt_authority_mismatch")
    require(accepted.get("command_extensions") == command_binding, "receipt_controls_mismatch")


def exercise(root: Path) -> dict[str, object]:
    # HTTP validates canonical source directories; the direct native control
    # must bind the same paths even when the temporary root is a symlink.
    root = root.resolve(strict=True)
    fixture = ManagedPolicyFixture(root)
    previous_ca = os.environ.get("SSL_CERT_FILE")

    def cleanup_fixture() -> None:
        try:
            fixture.close()
        finally:
            if previous_ca is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca

    with cleanup_preserving_failure(cleanup_fixture):
        os.environ["SSL_CERT_FILE"] = str(fixture.ca_file)
        return _exercise_fixture(root, fixture)


def _exercise_fixture(root: Path, fixture: ManagedPolicyFixture) -> dict[str, object]:
    store = fixture.store
    home, workspace = store.guard_home, fixture.workspace
    password = secrets.token_urlsafe(32)
    update_settings(home, {"enabled": True, "new_password": password, "confirm_password": password})
    provision(store)
    local_controls = (control(ControlTargetKind.PERMISSION, _PERMISSION, ControlState.ENABLED),)
    revision = commit_controls(store, password, local_controls)
    publisher = get_native_policy_snapshot_publisher(store)

    def close_native() -> None:
        try:
            publisher.close()
        finally:
            require(close_native_residents(home), "resident_cleanup_failed")

    try:
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=root, workspace_dir=workspace)
    except BaseException:
        cleanup_after_failure(close_native)
        raise
    rows: list[dict[str, object]] = []

    def set_mode(mode: str) -> None:
        grant = require_high_risk(
            home, purpose="settings_write", approval_gate_input=ApprovalGateInput(password=password)
        )
        update_guard_settings(home, {"mode": mode}, approval_gate_grant=grant)

    def bound(mode: str, *, managed: bool = True) -> dict[str, object]:
        binding = ready(daemon, workspace, revision)
        snapshot = present(publisher.current_snapshot(), "snapshot_missing")
        require(snapshot["version"] == 3, "command_authority_not_v3")
        require(binding.get("command_extensions_bound") is True and binding["mode"] == mode, "posture_not_bound")
        command_binding = mapping(snapshot.get("command_extensions"), "command_binding_missing")
        require(command_binding["health"] == "protected", "authority_not_protected")
        if managed:
            require(command_binding["managed_revision"] > 0, "signed_control_missing")
            require(publisher.requires_policy_authority and not publisher.requires_scoped_authority, "source_not_bound")
        return binding

    def signed(
        version: int,
        *,
        lockdown: bool = False,
        enable: bool = False,
        permission: str = _PERMISSION,
        authority_mode: str = "managed-restrictive",
    ) -> dict[str, Any]:
        runner.sync_runtime_session(store, session={"harness": "claude-code", "workspace": str(workspace)})
        fixture.bundle = fixture.signed_managed_bundle(
            version,
            controls=(
                {"targetKind": "permission", "targetId": permission, "state": "enabled" if enable else "disabled"},
            ),
            lockdown=lockdown,
            defaults={"mode": "enforce", "defaultAction": "allow"},
            authority_mode=authority_mode,
        )
        before = fixture.requests
        result = runner.sync_receipts(store)
        require(fixture.requests > before, "tls_delivery_missing")
        return result

    def applied(version: int, *, lockdown: bool = False) -> None:
        result = signed(version, lockdown=lockdown)
        require(result.get("policy_validation_status") == "accepted", "signature_not_accepted")
        require(result.get("policy_application_status") == "applied", "application_not_acknowledged")
        ack = mapping(store.get_sync_payload("policy_bundle_ack"), "ack_missing")
        bundle = present(fixture.bundle, "source_missing")
        require(ack.get("status") == "applied" and ack.get("bundleHash") == bundle["bundleHash"], "source_ack_mismatch")
        require(ack.get("bundleVersion") == version, "source_version_mismatch")

    def case(
        label: str,
        command: str,
        mode: str,
        *,
        reason: str | None = None,
        approved_payload: dict[str, object] | None = None,
        immutable_review: bool = False,
    ) -> dict[str, object]:
        binding = bound(mode)
        payload: dict[str, object] = approved_payload or {
            "request_id": f"managed-floor-{label}",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        edge = present(
            review_raw_hook_native(
                payload=payload,
                harness="claude-code",
                event="PreToolUse",
                guard_home=home,
                home_dir=home,
                cwd=workspace,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=time.monotonic() + 5,
                policy_snapshot=binding,
            ),
            "native_response_missing",
        )
        result = mapping(edge["result"], "native_result_missing")
        require(
            edge["authority"] == "rust" and edge["schema"] == "guard-hook-edge-result.v2", "native_authority_missing"
        )
        verify_native_floor(result, label=label, immutable_review=immutable_review)
        if reason is not None:
            require(result["reason_code"] == reason, f"native_floor_reason_mismatch:{label}")
        extensions = mapping(result.get("command_extensions"), "result_control_binding_missing")
        previous_receipt = copy.deepcopy(daemon._server.hook_worker.last_native_decision_receipt)
        with report_hook_transport_timeout(case=label, completed_cases=len(rows), control_revision=revision):
            response = present(
                installed_hook_request(daemon, home, workspace, "claude-code", "PreToolUse", payload), "http_missing"
            )
        verify_delivery(
            response,
            binding=binding,
            receipt=daemon._server.hook_worker.last_native_decision_receipt,
            command_binding=extensions["binding"],
            previous_receipt=previous_receipt,
            expected_reason=result["reason_code"],
            expected_request_digest=mapping(edge.get("receipt"), "raw_receipt_missing")["request_digest"],
            immutable_review=immutable_review,
            label=label,
            completed_cases=len(rows),
        )
        if immutable_review:
            request_id = response.get("approval_request_id")
            require(isinstance(request_id, str), "immutable_review_request_missing")
            assert isinstance(request_id, str)
            pending = store.get_approval_request(request_id)
            require(pending is not None and pending.get("status") == "pending", "immutable_review_not_pending")
            assert pending is not None
            require(
                pending.get("policy_action") == "review"
                and pending.get("resolution_action") is None
                and pending.get("launch_target") == command
                and pending.get("workspace") == str(workspace),
                "immutable_review_request_mismatch",
            )
        rows.append(
            {
                "case": label,
                "mode": mode,
                "decision": "deny",
                "minimum_action": "review" if immutable_review else "block",
                "native_reason": result["reason_code"],
            }
        )
        return response

    def cleanup() -> None:
        try:
            daemon.stop()
        finally:
            close_native()

    with cleanup_preserving_failure(cleanup):
        daemon.start()
        bound("enforce", managed=False)
        runner.sync_runtime_session(store, session={"harness": "claude-code", "workspace": str(workspace)})
        require(len(fixture.negotiated_capabilities) == 3, "managed_negotiation_missing")
        applied(1)
        for mode in ("enforce", "observe"):
            set_mode(mode)
            case(
                f"managed-permission-{mode}",
                "git push --force origin main",
                mode,
                reason="native_command_permission_disabled",
            )
            case(f"intrinsic-{mode}", "rm -rf /", mode)
        # A new locally authorized enable cannot replace the signed layer.
        revision = commit_controls(store, password, local_controls)
        case(
            "later-local-enable", "git push --force origin main", "observe", reason="native_command_permission_disabled"
        )
        retained = copy.deepcopy(store.get_sync_payload("policy_bundle_ack"))
        rejected = signed(2, enable=True)
        require(rejected.get("policy_validation_status") == "rejected", "managed_enable_accepted")
        require(rejected.get("policy_rejection_reason") == "managed_restrictive_broadening", "managed_enable_reason")
        require(store.get_sync_payload("policy_bundle_ack") == retained, "rejected_enable_replaced_ack")
        case(
            "signed-enable-rejected",
            "git push --force origin main",
            "observe",
            reason="native_command_permission_disabled",
        )
        # The immutable packaged permission is a required review floor, not a
        # hard block. Witness that exact native floor and a real pending HTTP
        # review before and after the rejected signed enable in both modes.
        for mode in ("enforce", "observe"):
            set_mode(mode)
            case(
                f"immutable-baseline-{mode}",
                "hol-guard approvals approve synthetic-request",
                mode,
                immutable_review=True,
            )
        retained = copy.deepcopy(store.get_sync_payload("policy_bundle_ack"))
        retained_source = copy.deepcopy(store.get_sync_payload("policy_bundle"))
        rejected = signed(2, enable=True, permission=_IMMUTABLE_PERMISSION, authority_mode="workspace-shared")
        require(rejected.get("policy_validation_status") == "rejected", "immutable_enable_accepted")
        require(rejected.get("policy_rejection_reason") == "immutable_floor", "immutable_enable_reason")
        require(store.get_sync_payload("policy_bundle_ack") == retained, "rejected_enable_replaced_ack")
        require(store.get_sync_payload("policy_bundle") == retained_source, "rejected_enable_replaced_source")
        for mode in ("enforce", "observe"):
            set_mode(mode)
            case(
                f"immutable-enable-rejected-{mode}",
                "hol-guard approvals approve synthetic-request",
                mode,
                immutable_review=True,
            )
            case(
                f"managed-after-immutable-rejection-{mode}",
                "git push --force origin main",
                mode,
                reason="native_command_permission_disabled",
            )
        # Obtain one actual action-bound approval through the protected local
        # store API. No simulated native result or prepopulated approval is used.
        set_mode("enforce")
        bound("enforce")
        approved_payload: dict[str, object] = {
            "request_id": "managed-approved-read",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
        }
        with report_hook_transport_timeout(
            case="managed-read-approval", completed_cases=len(rows), control_revision=revision
        ):
            pending = present(
                installed_hook_request(daemon, home, workspace, "claude-code", "PreToolUse", approved_payload),
                "approval_http_missing",
            )
        require(pending.get("policy_action") == "review", "approval_not_native_review")
        request_id = pending.get("approval_request_id")
        require(isinstance(request_id, str), "approval_request_missing")
        assert isinstance(request_id, str)
        now = datetime.now(timezone.utc).isoformat()
        grant = require_approval_decision(
            home,
            action="allow",
            scope="artifact",
            subject=f"approval-request:{request_id}",
            approval_gate_input=ApprovalGateInput(password=password),
            now=now,
        )
        store.resolve_approval_request(
            request_id,
            resolution_action="allow",
            resolution_scope="artifact",
            reason="Disposable installed proof",
            resolved_at=now,
            approval_gate_grant=grant,
        )
        resolved = store.get_approval_request(request_id)
        require(resolved is not None and resolved.get("status") == "resolved", "approval_not_resolved")
        applied(2, lockdown=True)
        for mode in ("enforce", "observe"):
            set_mode(mode)
            case(f"managed-lockdown-{mode}", "pwd", mode, reason="native_command_control_authority_block")
            case(
                f"approved-read-lockdown-{mode}",
                "cat .env",
                mode,
                reason="native_command_control_authority_block",
                approved_payload=approved_payload,
            )
            require(store.get_approval_request(request_id) == resolved, "block_changed_approved_request")
            with store._connect() as connection:
                spent = connection.execute(
                    "select count(*) from guard_continuation_effects where request_id = ? and event_name = ?",
                    (request_id, "native-review.once-consumed"),
                ).fetchone()
            require(spent is not None and spent[0] == 0, "block_consumed_approval")
        revision = repair_local_authority(daemon, store, password)
        for mode in ("enforce", "observe"):
            set_mode(mode)
            case(f"recovered-lockdown-{mode}", "pwd", mode, reason="native_command_control_authority_block")
            case(
                f"recovered-managed-permission-{mode}",
                "git push --force origin main",
                mode,
                reason="native_command_permission_disabled",
            )
        return {
            "schema": "guard.installed-managed-floors.v1",
            "cases": rows,
            "native_mode": "auto",
            "synthetic_enrollment": True,
            "ordinary_oauth_exercised": False,
            "builder_ceremony_exercised": False,
            "target_commands_executed": 0,
            "dependency_edges_exercised": 0,
            "trusted_recovery_exercised": True,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    args = parser.parse_args()
    report: dict[str, object] = {"schema": "guard.installed-managed-floors.v1", "passed": False}
    try:
        require("site-packages" in Path(codex_plugin_scanner.__file__).resolve().parts, "not_installed_package")
        require(environment_is_clean(os.environ) and native_mode() == "auto", "native_environment_override")
        require(os.environ.get("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT") == "1", "canonical_rollout_not_configured")
        flags = ManagedControlsFeatureFlags.from_environment()
        require(
            flags.catalog_sync
            and flags.policy_extension_targets
            and flags.managed_extension_controls
            and flags.atomic_apply,
            "managed_rollout_not_configured",
        )
        status = native_runtime_status()
        require(status.available and status.compatible, "native_unavailable")
        capabilities = present(status.capabilities, "native_capabilities_missing")
        identity = present(status.identity, "native_identity_missing")
        require(
            re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha) is not None
            and capabilities.build_sha == args.expected_source_sha,
            "native_source_mismatch",
        )
        require("native-command-program-v1" in capabilities.features, "native_command_feature_missing")
        report.update(source_sha=capabilities.build_sha, runtime_sha256=identity.sha256)
        with tempfile.TemporaryDirectory(prefix="hgm-", dir=None if os.name == "nt" else "/tmp") as temporary:
            report.update(exercise(Path(temporary)))
        report["passed"] = True
    except ProbeError as error:
        report["failure"] = str(error)
        if isinstance(error, (NativeFloorMismatchError, ReceiptRequestMismatchError)):
            report["failure_observation"] = error.observation
    except Exception:
        report["failure"] = "probe_execution_failed"
    args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
