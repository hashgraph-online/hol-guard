"""Exercise installed Ollama controls through real authenticated native hooks.

This private CI fixture reviews synthetic command text only. It uses a private
encrypted-file authority backend and explicitly bootstraps fixture enrollment;
every subsequent control mutation consumes a real password-bound local proof.
It does not claim interactive enrollment or execution of an Ollama process.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import secrets
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings  # noqa: E402
from codex_plugin_scanner.guard.approvals import apply_approval_resolution  # noqa: E402
from codex_plugin_scanner.guard.native_approval_errors import NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES  # noqa: E402
from codex_plugin_scanner.guard.native_command_control_binding import load_native_command_program_metadata  # noqa: E402
from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY  # noqa: E402
from codex_plugin_scanner.guard.runtime.extension_contribution import validate_contribution  # noqa: E402
from codex_plugin_scanner.guard.runtime.extension_control_authority import (  # noqa: E402
    AuthorityHealth,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (  # noqa: E402
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (  # noqa: E402
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402
from scripts.ci.native_ollama_contract import (  # noqa: E402
    ACTIVE_CASES,
    INACTIVE_CASES,
    LEGACY_RETRY_SCOPE,
    READINESS_PHASES,
    RESTRICTED_CASES,
    OllamaCase,
    payload_digest,
    require,
    require_same_ack,
    review_payload,
    validate_legacy_retry,
    validate_review,
    validated_build_sha,
)
from scripts.native_slo_adapter import route_counts  # noqa: E402
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest  # noqa: E402
from scripts.native_slo_contract import MAX_READINESS_P95_MS, assert_privacy_safe  # noqa: E402
from scripts.native_slo_failure import FixtureFailureError, failure_evidence  # noqa: E402
from scripts.native_slo_publisher_diagnostic import publisher_error_diagnostic  # noqa: E402
from scripts.native_slo_session import AdapterSession, _request  # noqa: E402
from scripts.native_slo_workloads import configuration_text  # noqa: E402


def _bounded_artifact(path: Path, limit: int, reason: str) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(limit + 1)
    require(len(value) <= limit, reason)
    return value


def artifact_identity(expected: Mapping[str, object]) -> tuple[Path, dict[str, object]]:
    build_sha = validated_build_sha(expected.get("build_sha"))
    distribution = importlib.metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    package = Path(str(distribution.locate_file("codex_plugin_scanner"))).resolve(strict=True)
    require("site-packages" in package.parts, "installed_origin_missing")
    require(installed_package_digest(distribution) == expected["installed_package_sha256"], "wheel_contents_mismatch")
    data = package / "guard/contracts/data/extensions"
    contribution = _bounded_artifact(data / "contributions/command.ollama.json", 64 * 1024, "contribution_oversized")
    require(hashlib.sha256(contribution).hexdigest() == expected["contribution_sha256"], "contribution_mismatch")
    document = json.loads(contribution)
    validate_contribution(document, filename="command.ollama.json")
    require(document["id"] == "command.ollama" and document["version"] == "1.0.0", "contribution_version_mismatch")
    program = _bounded_artifact(data / "native-command-program.v1.json", 4 * 1024 * 1024, "program_oversized")
    require(hashlib.sha256(program).hexdigest() == expected["program_sha256"], "packaged_program_mismatch")
    metadata = load_native_command_program_metadata()
    require(metadata.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, "catalog_mismatch")
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.ollama")
    require(extension is not None, "contribution_not_registered")
    status = native_runtime_status()
    require(status.available and status.compatible and status.identity is not None, "native_runtime_unavailable")
    require(status.capabilities is not None, "native_capabilities_missing")
    assert status.capabilities is not None and status.identity is not None
    require(status.capabilities.build_sha == build_sha, "native_build_mismatch")
    require(
        {"native-command-program-v1", "native-command-control-fence-v1"} <= set(status.capabilities.features),
        "native_capability_missing",
    )
    return status.identity.path, {
        "build_sha": status.capabilities.build_sha,
        "wheel_sha256": expected["wheel_sha256"],
        "installed_package_sha256": expected["installed_package_sha256"],
        "runtime_sha256": status.identity.sha256,
        "package_version": distribution.version,
        "target": status.capabilities.target,
        "program_digest": metadata.program_digest,
        "catalog_digest": metadata.catalog_digest,
        "trust_digest": metadata.trust_digest,
        "contribution_sha256": expected["contribution_sha256"],
        "program_sha256": expected["program_sha256"],
    }


def prepare_fixture_authority(store: GuardStore) -> str:
    """Use isolated fixture enrollment, then production mutation approvals."""
    from scripts.native_slo_command_fixture import verify_empty_command_authority

    # AdapterSession provisioned the generated-key empty authority before daemon
    # construction. Verify it here without bootstrapping another authority.
    verify_empty_command_authority(store)
    password = secrets.token_urlsafe(36)
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    verify_empty_command_authority(store)
    return password


def control_layer(*, enabled: bool, restrict_push: bool = False) -> ExtensionControlLayer:
    controls = [
        ExtensionControl(
            ControlTarget(ControlTargetKind.EXTENSION, "command.ollama"),
            ControlState.ENABLED if enabled else ControlState.DISABLED,
        )
    ]
    if restrict_push:
        controls.append(
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, "command.ollama.permission.push"), ControlState.DISABLED
            )
        )
    return ExtensionControlLayer(
        schema_version="1.0.0",
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(controls),
    )


def commit_controls(store: GuardStore, password: str, layer: ExtensionControlLayer, *, revision: int) -> int:
    key = secrets.token_hex(16)
    mutation = ExtensionControlMutation(
        previous_revision=revision,
        catalog_digest=layer.catalog_digest,
        layers=(layer,),
        actor_id="installed-ollama-fixture",
        idempotency_key=key,
        nonce=key,
    )
    proof = issue_extension_control_proof(
        store.guard_home,
        mutation,
        approval_gate_input=ApprovalGateInput(password=password),
        session_nonce=secrets.token_hex(16),
    )
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=layer.catalog_digest,
        actor_id=mutation.actor_id,
        expected_revision=revision,
        idempotency_key=key,
        nonce=key,
        proof=proof,
    )
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    require(view.health is AuthorityHealth.PROTECTED and view.revision == revision + 1, "control_commit_mismatch")
    return view.revision


_PUBLISHER_ERRORS = (
    frozenset(
        {
            "native_policy_snapshot_workspace_capacity",
            "native_policy_snapshot_expired",
            "native_policy_snapshot_publish_failed",
            "native_policy_snapshot_resident_changed",
            "native_policy_snapshot_native_disabled",
            "native_policy_snapshot_runtime_unavailable",
            "native_policy_snapshot_protocol_unsupported",
            "native_policy_snapshot_integrity_key_unavailable",
            "native_policy_snapshot_ack_invalid",
            "native_policy_snapshot_ack_mismatch",
            "native_client_containment_failed",
            "native_client_process_failed",
            "native_client_launcher_failed",
            "native_client_timed_out",
            "native_client_output_limit_exceeded",
            "native_client_status_missing",
            "native_client_exit_nonzero",
            "native_client_output_missing",
            "native_command_control_binding_changed",
            "permissionerror",
            "oserror",
            "timeouterror",
            "runtimeerror",
            "valueerror",
            "typeerror",
            "attributeerror",
            "operationalerror",
        }
    )
    | NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
)


def ready_binding(session: AdapterSession, revision: int, *, phase: str) -> dict[str, object]:
    worker = session.daemon._server.hook_worker
    started = time.monotonic()
    deadline = started + MAX_READINESS_P95_MS / 1000
    snapshot = worker.prepare_workspace_policy(session.workspace, deadline=deadline)
    finished = time.monotonic()
    if snapshot is None or finished > deadline:
        publisher = worker.policy_snapshot_publisher
        error = publisher.last_error
        if error in _PUBLISHER_ERRORS:
            publisher_error = error
        elif error:
            publisher_error = "unclassified"
        else:
            publisher_error = "none"
        detail = failure_evidence(AssertionError("installed_ollama_native_readiness_failed"))
        detail["phase"] = phase if phase in READINESS_PHASES else "unknown"
        detail["readiness"] = {
            "expected_revision": revision,
            "budget_ms": MAX_READINESS_P95_MS,
            "elapsed_ms": round((finished - started) * 1000, 3),
            "snapshot_returned": snapshot is not None,
            "budget_exhausted": finished > deadline,
            "publisher_ready_after_failure": publisher.is_ready(),
            "publisher_closed_after_failure": publisher.closed,
            "publisher_error": publisher_error,
        }
        try:
            cast(dict[str, object], detail["readiness"]).update(publisher_error_diagnostic(error))
        except Exception:
            detail["readiness"]["publisher_error_state"] = "collection_failed"
        raise FixtureFailureError(detail)
    current = worker.policy_snapshot_publisher.current_snapshot()
    require(current is not None and worker.policy_snapshot_publisher.is_ready(), "policy_ack_missing")
    current = cast(dict[str, Any], current)
    binding = current.get("command_extensions")
    require(isinstance(binding, Mapping) and binding.get("revision") == revision, "ack_revision_mismatch")
    binding = cast(Mapping[str, object], binding)
    require(binding.get("health") == "protected", "ack_authority_unprotected")
    return current


def review_case(
    session: AdapterSession,
    phase: str,
    case: OllamaCase,
    snapshot: Mapping[str, Any],
    *,
    request_payload: Mapping[str, object],
) -> tuple[dict[str, object], str | None]:
    worker = session.daemon._server.hook_worker
    captured: list[dict[str, object]] = []
    original = worker._review_raw_hook_native

    def capture(**kwargs: Any) -> dict[str, object] | None:
        edge = original(**kwargs)
        if edge is not None:
            captured.append(edge)
        return edge  # Pure observation: never replace native decisions or receipts.

    before = route_counts(worker.metrics.snapshot())
    worker._review_raw_hook_native = capture
    try:
        response = _request(
            session.daemon,
            guard_home=session.guard_home,
            workspace=session.workspace,
            harness="claude-code",
            request_payload=request_payload,
        )
    finally:
        worker._review_raw_hook_native = original
    after = route_counts(worker.metrics.snapshot())
    delta = {name: after.get(name, 0) - before.get(name, 0) for name in set(before) | set(after)}
    require({name: count for name, count in delta.items() if count} == {"native_resident": 1}, "route_mismatch")
    require(len(captured) == 1, "native_capture_ambiguous")
    control = snapshot["command_extensions"]
    expected = {
        "program_digest": control["program_digest"],
        "catalog_digest": control["catalog_digest"],
        "trust_digest": control["trust_digest"],
        "control_revision": control["revision"],
        "managed_control_revision": control["managed_revision"],
        "control_effective_digest": control["effective_digest"],
    }
    receipt = validate_review(case, captured[0], response, expected_binding=expected)
    require(receipt["policy_generation"] == snapshot["generation"], "receipt_generation_mismatch")
    # Compact controls omit the authority epoch and mutation fence. The full
    # acknowledged policy digest binds both and must match the actual receipt.
    require(receipt["policy_digest"] == snapshot["policy_digest"], "receipt_policy_mismatch")
    decision_id = cast(str, receipt["decision_id"])
    deadline = time.monotonic() + 5.0
    while session.store.get_native_decision_receipt(decision_id) != receipt:
        require(time.monotonic() < deadline, "receipt_not_durable")
        time.sleep(0.01)
    approval_recorded = False
    approval_id = None
    if case.action == "review":
        approval_id = cast(str, response["approval_request_id"])
        approval = session.store.get_approval_request(approval_id)
        require(
            approval is not None and approval.get("status") == "pending" and approval.get("harness") == "claude-code",
            "approval_not_durable",
        )
        approval_recorded = True
    return {
        "phase": phase,
        "case": case.name,
        "decision_id": decision_id,
        "hook_envelope_digest": payload_digest(request_payload),
        "request_digest": receipt["request_digest"],
        "policy_generation": receipt["policy_generation"],
        "policy_digest": receipt["policy_digest"],
        "control_revision": control["revision"],
        "observations_digest": cast(Mapping[str, object], receipt["command_extensions"])["observations_digest"],
        "rule": case.rule,
        "safe_variant": case.safe_variant,
        "action": case.action,
        "reason": case.reason,
        "route": "native_resident",
        "receipt_durable": True,
        "approval_durable": approval_recorded,
        "legacy_approval_reused": False,
    }, approval_id


def approve_review(store: GuardStore, password: str, approval_id: str) -> None:
    """Resolve an actual queued review through the existing production service."""
    apply_approval_resolution(
        store=store,
        request_id=approval_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="Synthetic installed qualification approval",
        persist_policy=False,
        resolve_scope_matches=False,
        approval_gate_input=ApprovalGateInput(password=password),
    )
    row = store.get_approval_request(approval_id)
    require(
        row is not None and row.get("status") == "resolved" and row.get("resolution_action") == "allow",
        "approval_resolution_failed",
    )


def _run_probe(expected: Mapping[str, object], progress: dict[str, Any]) -> dict[str, object]:
    runtime, identity = artifact_identity(expected)
    progress["identity"] = identity
    session = AdapterSession(runtime, configuration=configuration_text("normal"))
    results: list[dict[str, object]] = progress["cases"]
    entered = False
    try:
        password = prepare_fixture_authority(session.store)
        # AdapterSession owns cleanup once entry starts, including failed start.
        entered = True
        with session:
            require(session.daemon._server.hook_worker.test_oracle is None, "python_oracle_present")
            revision = 0
            previous_generation = 0
            phases = (
                ("initial", None, INACTIVE_CASES),
                ("enabled", control_layer(enabled=True), ACTIVE_CASES),
                ("disabled", control_layer(enabled=False), INACTIVE_CASES),
                ("updated", control_layer(enabled=True, restrict_push=True), RESTRICTED_CASES),
                ("settings_rollback", control_layer(enabled=True), ACTIVE_CASES),
            )
            for phase, layer, cases in phases:
                progress["phase"] = phase
                if layer is not None:
                    revision = commit_controls(session.store, password, layer, revision=revision)
                snapshot = ready_binding(session, revision, phase=phase)
                generation = cast(int, snapshot["generation"])
                require(generation > previous_generation, "generation_did_not_advance")
                previous_generation = generation
                for case in cases:
                    request_payload = review_payload(session.workspace, case)
                    record, approval_id = review_case(session, phase, case, snapshot, request_payload=request_payload)
                    results.append(record)
                    if phase == "enabled" and case.name == "push":
                        progress["phase"] = "approved_retry"
                        require(approval_id is not None, "approval_missing")
                        approve_review(session.store, password, cast(str, approval_id))
                        current = ready_binding(session, revision, phase="approved_retry")
                        require_same_ack(snapshot, current)
                        retry, next_id = review_case(
                            session, "approved_retry", case, current, request_payload=request_payload
                        )
                        retry.update(
                            validate_legacy_retry(session.store, cast(str, approval_id), next_id, record, retry)
                        )
                        results.append(retry)
                        progress["phase"] = phase
            progress["phase"] = "stale_write_rejected"
            try:
                commit_controls(session.store, password, control_layer(enabled=False), revision=1)
            except ExtensionControlAuthorityError:
                pass
            else:
                raise AssertionError("installed_ollama_stale_revision_accepted")
            snapshot = ready_binding(session, revision, phase="stale_write_rejected")
            record, _ = review_case(
                session,
                "stale_write_rejected",
                ACTIVE_CASES[0],
                snapshot,
                request_payload=review_payload(session.workspace, ACTIVE_CASES[0]),
            )
            results.append(record)
    finally:
        if not entered:
            session.close()
    _, after = artifact_identity(expected)
    require(after == identity, "artifact_changed_during_probe")
    return assert_privacy_safe(
        {
            "schema": "hol-guard.installed-native-ollama.v1",
            "passed": True,
            "identity": identity,
            "cases": results,
            "final_control_revision": revision,
            "boundary": "authenticated_daemon_http",
            "authority_backend": "isolated_encrypted_file_fixture",
            "mutation_approval": "production_local_approval_proof",
            "interactive_enrollment_qualified": False,
            "package_downgrade_qualified": False,
            "tool_invocation_mode": "synthetic_policy_review_only",
            "python_semantic_oracle": False,
            "stale_control_write_rejected": True,
            "prior_approval_did_not_bypass_disabled_controls": True,
            "native_approval_consume_qualified": False,
            "approval_retry_scope": LEGACY_RETRY_SCOPE,
        }
    )


def run_probe(expected: Mapping[str, object]) -> dict[str, object]:
    """Retain completed witnesses when a later phase misses its unchanged gate."""
    progress: dict[str, Any] = {"cases": [], "phase": "identity"}
    try:
        return _run_probe(expected, progress)
    except Exception as error:
        return assert_privacy_safe(
            {
                "schema": "hol-guard.installed-native-ollama.v1",
                "passed": False,
                **progress,
                "completed_case_count": len(progress["cases"]),
                "completed_phase_count": len({record["phase"] for record in progress["cases"]}),
                "failure": failure_evidence(error),
                "retained_scope": "completed_cases_only",
                "package_downgrade_qualified": False,
                "native_approval_consume_qualified": False,
                "approval_retry_scope": LEGACY_RETRY_SCOPE,
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_probe(json.loads(args.expected.read_text(encoding="utf-8")))
    except Exception as error:
        print(json.dumps(failure_evidence(error), sort_keys=True), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
