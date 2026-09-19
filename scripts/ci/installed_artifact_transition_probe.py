"""Observe a stopped wheel replacement using one persistent private fixture home.

Each invocation imports one installed wheel in a fresh interpreter. It never
copies authority rows, lowers revision floors, repairs a failed downgrade, or
turns missing native program support into qualified native execution.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import secrets
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: E402
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter  # noqa: E402
from codex_plugin_scanner.guard.adapters.claude_hook_config import claude_managed_settings_path  # noqa: E402
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings  # noqa: E402
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer  # noqa: E402
from codex_plugin_scanner.guard.native_decision_receipt import (  # noqa: E402
    receipt_matches_edge,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY  # noqa: E402
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
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore  # noqa: E402
from scripts.ci.installed_transition_diagnostics import (  # noqa: E402
    LEGACY_REJECTION_REASONS,
    policy_state,
    process_metadata,
    publisher_metadata,
    state_preserved,
)
from scripts.ci.installed_transition_quiescence import (  # noqa: E402
    digest_json,
    exact_rejection,
    private_json,
    tree_digest,
)
from scripts.ci.installed_transition_quiescence import (  # noqa: E402
    write_private as write_owned_private,
)
from scripts.ci.installed_transition_receipts import (  # noqa: E402
    AUDITED_BASELINE_SHA,
    TransitionReceiptReader,
    same_receipt,
)
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest  # noqa: E402
from scripts.native_slo_command_fixture import prepare_empty_command_authority  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_launcher import _observe_launcher, registered_claude_argv  # noqa: E402
from scripts.native_slo_session import AdapterSession  # noqa: E402
from scripts.native_slo_workloads import configuration_text  # noqa: E402

_STATE_LIMIT = 64 * 1024
_PHASE_NAMES = ("clean_baseline", "candidate_upgrade", "candidate_reinstall", "baseline_rollback", "candidate_restore")
_COMPATIBLE_PHASE_NAMES = (
    "compatible_candidate_start",
    "compatible_candidate_rollback",
    "compatible_candidate_restore",
)


def require(condition: object, reason: str) -> None:
    if not condition:
        raise RuntimeError("qualification_transition_" + reason)


def read_private(path: Path) -> dict:
    if os.name == "nt":
        return private_json(path, maximum_bytes=_STATE_LIMIT)
    with path.open("rb") as stream:
        value = stream.read(_STATE_LIMIT + 1)
    require(len(value) <= _STATE_LIMIT, "private_state_limit")
    result = json.loads(value)
    require(isinstance(result, dict), "private_state_invalid")
    return result


def write_private(path: Path, value: dict) -> None:
    content = json.dumps(value, sort_keys=True).encode()
    require(len(content) <= _STATE_LIMIT, "private_state_limit")
    if os.name == "nt":
        write_owned_private(path, value)
        return
    pending = path.with_suffix(".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)


def installed_identity(expected: Mapping[str, object]) -> tuple[Path, dict]:
    distribution = importlib.metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    package = Path(distribution.locate_file("codex_plugin_scanner")).absolute()
    require(package.is_relative_to(Path(sys.prefix).absolute()), "installation_prefix_mismatch")
    require(installed_package_digest(distribution) == expected["installed_package_sha256"], "wheel_bytes_mismatch")
    status = native_runtime_status()
    require(status.available and status.compatible and status.identity is not None, "native_unavailable")
    require(status.capabilities is not None, "capabilities_missing")
    require(status.capabilities.build_sha == expected["build_sha"], "build_identity_mismatch")
    return status.identity.path, {
        **expected,
        "package_version": distribution.version,
        "runtime_sha256": status.identity.sha256,
        "native_program_supported": "native-command-program-v1" in status.capabilities.features,
        "installed_origin_verified": True,
    }


def commit_layer(store: GuardStore, password: str, *, revision: int, enabled: bool) -> None:
    catalog = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    layer = ExtensionControlLayer(
        schema_version="1.0.0",
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=catalog,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, "command.ollama"),
                ControlState.ENABLED if enabled else ControlState.DISABLED,
            ),
        ),
    )
    nonce = secrets.token_hex(16)
    mutation = ExtensionControlMutation(
        previous_revision=revision,
        catalog_digest=catalog,
        layers=(layer,),
        actor_id="installed-artifact-transition",
        idempotency_key=nonce,
        nonce=nonce,
    )
    proof = issue_extension_control_proof(
        store.guard_home,
        mutation,
        approval_gate_input=ApprovalGateInput(password=password),
        session_nonce=secrets.token_hex(16),
    )
    store.commit_extension_control_layers(
        (layer,),
        catalog_digest=catalog,
        actor_id=mutation.actor_id,
        expected_revision=revision,
        idempotency_key=nonce,
        nonce=nonce,
        proof=proof,
    )


def authority_view(store: GuardStore, previous: Mapping[str, object] | None) -> object:
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    require(view.health is AuthorityHealth.PROTECTED, "authority_not_protected")
    if previous is not None:
        require(view.revision >= previous["revision"], "authority_revision_regressed")
        states = [
            control.state.value
            for layer in view.layers
            for control in layer.controls
            if control.target.kind is ControlTargetKind.EXTENSION and control.target.target_id == "command.ollama"
        ]
        require(states == [previous["ollama_state"]], "prior_control_not_preserved")
    return view


class RetainedSession(AdapterSession):
    """Reuse only fixture filesystem ownership; production daemon/start/stop stay unchanged."""

    def __init__(self, runtime: Path, root: Path, store: GuardStore) -> None:
        self.root = root
        self.guard_home = store.guard_home
        self.workspace = root / "workspace"
        self.store = store
        # The outer orchestrator owns this temporary directory across workers.
        self.temporary = SimpleNamespace(cleanup=lambda: None)
        self.runtime = runtime
        self.readiness_ms = 0.0
        self._connection = None
        self._owner_thread_id = 0
        self.last_stop_diagnostic = {}
        self._stop_diagnostic_written = False
        self.retirement_confirmed = False
        self.start_failure = {}
        self.daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        self.daemon._server.hook_worker.policy_snapshot_publisher.register_workspace(self.workspace)

    def start(self) -> None:
        try:
            super().start()
        except BaseException:
            self.start_failure = publisher_metadata(self.daemon._server.hook_worker.policy_snapshot_publisher)
            raise

    def stop_resident(self) -> bool:
        stopped = super().stop_resident()
        self.retirement_confirmed = stopped and self.last_stop_diagnostic.get("status") == "contained"
        return stopped

    def close(self) -> None:
        try:
            super().close()
        except BaseException:
            self.retirement_confirmed = False
            raise
        self.retirement_confirmed = self.retirement_confirmed and self.last_stop_diagnostic.get("status") in {
            "contained",
            "already-stopped",
        }

    def verify_failed_start_retirement(self) -> dict:
        """Ask the exact installed runtime for authenticated idempotent stop proof."""
        publisher = publisher_metadata(self.daemon._server.hook_worker.policy_snapshot_publisher)
        active = getattr(self.daemon._server, "active_hook_requests", None)
        evidence = {
            "publisher_after_close": publisher,
            "prior_stop": self.last_stop_diagnostic,
            "active_hook_requests": active,
            "verified": False,
        }
        if publisher.get("thread_alive") is not False or active != 0:
            return evidence
        environment = dict(os.environ)
        clear_proof_environment(environment)
        result = run_isolated_hook_process(
            (str(self.runtime), "resident-stop", "--state-dir", str(self.guard_home / "native-runtime")),
            cwd=self.root,
            environment=environment,
            input_text="",
            timeout_seconds=2,
            output_limit=8192,
        )
        evidence.update(process_metadata(result))
        evidence.update(
            timed_out=result.timed_out,
            containment_failed=result.containment_failed,
            limit_exceeded=result.output_limit_exceeded,
        )
        evidence["verified"] = (
            result.returncode == 0
            and not result.timed_out
            and not result.containment_failed
            and not result.output_limit_exceeded
            and self.last_stop_diagnostic.get("status") != "contained_client_cleanup_failed"
        )
        self.retirement_confirmed = evidence["verified"]
        return evidence


def observe_registered(
    session: RetainedSession, identity: dict, previous: dict | None, reader: TransitionReceiptReader
) -> tuple[list[dict], str]:
    context = HarnessContext(home_dir=session.root, workspace_dir=session.workspace, guard_home=session.guard_home)
    if previous is None:
        ClaudeCodeHarnessAdapter().install(context)
    settings = claude_managed_settings_path(context)
    with settings.open("rb") as stream:
        registration = stream.read(_STATE_LIMIT + 1)
    require(len(registration) <= _STATE_LIMIT, "registration_limit")
    registration_digest = hashlib.sha256(registration).hexdigest()
    if previous is not None:
        require(registration_digest == previous["registration_sha256"], "registration_changed")
    argv = registered_claude_argv(settings, "PostToolUse")
    require(Path(argv[0]).absolute() == Path(sys.executable).absolute(), "registration_interpreter_mismatch")
    worker = session.daemon._server.hook_worker
    require(worker.test_oracle is None, "python_oracle_present")
    captured = []
    original = worker._review_raw_hook_native

    def capture(**kwargs):
        edge = original(**kwargs)
        captured.append(edge)
        return edge

    receipts = []
    worker._review_raw_hook_native = capture
    try:
        for index, case in enumerate(("benign", "secret")):
            captured.clear()
            _observe_launcher(session, argv, sample=index + (len(previous["receipts"]) if previous else 0), case=case)
            require(len(captured) == 1 and isinstance(captured[0], Mapping), "native_capture_ambiguous")
            receipt = validate_native_decision_receipt(captured[0].get("receipt"))
            require(receipt is not None and receipt_matches_edge(captured[0], receipt), "receipt_mismatch")
            require(receipt["runtime_identity"] == identity["runtime_sha256"], "receipt_runtime_mismatch")
            deadline = time.monotonic() + 5
            while not same_receipt(reader.read_current(receipt["decision_id"]), receipt):
                require(time.monotonic() < deadline, "receipt_not_durable")
                time.sleep(0.01)
            receipts.append(receipt)
    finally:
        worker._review_raw_hook_native = original
    return receipts, registration_digest


def run_phase(expected: dict, root: Path, phase: str) -> dict:
    report = {
        "schema": "hol-guard.installed-artifact-transition-phase.v1",
        "phase": phase,
        "passed": False,
        "cleanup_confirmed": False,
        "registered_native_cases": 0,
        "native_review_started": False,
        "native_program_downgrade_qualified": False,
    }
    session = None
    before = {}
    previous = None
    pending_checkpoint = None

    def stage(value: str) -> None:
        report["last_stage"] = value
        print("HOL_GUARD_TRANSITION_STAGE=" + value, file=sys.stderr, flush=True)

    try:
        stage("installed_identity")
        runtime, identity = installed_identity(expected)
        report["identity"] = identity
        compatible = phase in _COMPATIBLE_PHASE_NAMES
        sequence = _COMPATIBLE_PHASE_NAMES if compatible else _PHASE_NAMES
        require(phase in sequence, "phase_invalid")
        if compatible:
            require(identity["native_program_supported"], "compatible_program_unsupported")
        stage("private_history")
        journal = root / "transition-state.json"
        previous = read_private(journal) if journal.exists() else None
        require((phase == sequence[0]) == (previous is None), "phase_history_mismatch")
        if previous is not None:
            require(previous["phase"] == sequence[sequence.index(phase) - 1], "phase_history_mismatch")
        guard_home = root / ".hol-guard"
        guard_home.mkdir(mode=0o700, exist_ok=True)
        (root / "workspace").mkdir(mode=0o700, exist_ok=True)
        if previous is None:
            (guard_home / "config.toml").write_text(configuration_text("normal"))
        stage("open_store")
        store = GuardStore(guard_home)
        store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard_home)
        if previous is None:
            prepare_empty_command_authority(store)
            password = secrets.token_urlsafe(36)
            update_settings(
                guard_home,
                {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
            )
            commit_layer(store, password, revision=0, enabled=compatible)
        else:
            password = previous["password"]
        stage("verify_authority")
        view = authority_view(store, previous)
        old_receipts = previous["receipts"] if previous else []
        stage("verify_receipts")
        reader = TransitionReceiptReader(store, build_sha=identity["build_sha"])
        require(
            all(reader.preserves_prior(item) for item in old_receipts),
            "prior_receipt_changed",
        )
        report["receipt_readback"] = "audited_baseline_sql" if reader.legacy else "installed_public_getter"
        report["prior_binding_interpretation_qualified"] = False
        report["prior_receipts_verified"] = len(old_receipts)
        if phase == "candidate_upgrade":
            commit_layer(store, password, revision=view.revision, enabled=True)
            view = authority_view(store, None)
        enabled = compatible or phase != "clean_baseline"
        stage("reject_stale_write")
        # A real password-authorized stale write must still fail before mutation.
        try:
            commit_layer(store, password, revision=max(0, view.revision - 1), enabled=not enabled)
        except ExtensionControlAuthorityError:
            report["stale_control_write_rejected"] = True
        else:
            raise RuntimeError("qualification_transition_stale_write_accepted")
        current = authority_view(store, None)
        require(current.revision == view.revision and current.layers == view.layers, "stale_write_changed_authority")
        report["control_revision"] = current.revision
        report["authority_health"] = current.health.value
        before = policy_state(guard_home)
        if phase == "baseline_rollback":
            report["policy_before"] = before
            require(previous is not None and before == previous.get("policy_state"), "prior_policy_checkpoint_changed")
            report["prior_policy_checkpoint_verified"] = True
        stage("construct_daemon")
        session = RetainedSession(runtime, root, store)
        stage("native_start")
        with session:
            stage("registered_hooks")
            report["native_review_started"] = True
            receipts, registration_digest = observe_registered(session, identity, previous, reader)
            require(
                len({item["decision_id"] for item in [*old_receipts, *receipts]}) == len(old_receipts) + len(receipts),
                "receipt_not_distinct",
            )
            report["registered_native_cases"] = len(receipts)
            report["registration_preserved"] = previous is not None
            stage("retire")
        require(session.retirement_confirmed, "generation_cleanup_unverified")
        report["cleanup_confirmed"] = True
        _, after = installed_identity(expected)
        require(after == identity, "artifact_changed_during_phase")
        stage("checkpoint")
        checkpoint = policy_state(guard_home)
        write_private(
            journal,
            {
                "password": password,
                "phase": phase,
                "revision": current.revision,
                "ollama_state": "enabled" if enabled else "disabled",
                "receipts": [*old_receipts, *receipts],
                "registration_sha256": registration_digest,
                "policy_state": checkpoint,
            },
        )
        report["restored_after_rejected_legacy"] = previous is not None and previous.get("rejected_legacy") is True
        report["passed"] = True
    except Exception as error:
        report["failure"] = failure_evidence(error)
        if session is not None:
            report["cleanup_confirmed"] = session.retirement_confirmed
            report["publisher_at_failure"] = session.start_failure
            report["stop_diagnostic"] = session.last_stop_diagnostic
            report["policy_after"] = policy_state(session.guard_home)
            # Preserve a rejected legacy start as a negative result. Continuing
            # to a candidate restore needs independent retirement and unchanged
            # candidate authority bytes; an arbitrary startup failure never qualifies.
            if (
                phase == "baseline_rollback"
                and previous is not None
                and identity["build_sha"] == AUDITED_BASELINE_SHA
                and identity["native_program_supported"] is False
                and session.start_failure.get("ready") is False
                and session.start_failure.get("reason") in LEGACY_REJECTION_REASONS
                and state_preserved(before, report["policy_after"])
            ):
                try:
                    report["retirement_verification"] = session.verify_failed_start_retirement()
                    report["cleanup_confirmed"] = session.retirement_confirmed
                    owned_continuation = (
                        sys.platform in {"linux", "win32"}
                        and len(os.environ.get("HOL_GUARD_TRANSITION_OWNED_NONCE", "")) == 64
                        and report["last_stage"] == "native_start"
                        and report["failure"].get("reason")
                        == "native_installed_slo_failed:_native_policy_was_not_ready"
                        and session.start_failure.get("reason") == "native_policy_snapshot_unknown_field"
                        and report["retirement_verification"].get("return_code") == 2
                        and not any(
                            report["retirement_verification"].get(key) is not False
                            for key in (
                                "timed_out",
                                "containment_failed",
                                "limit_exceeded",
                            )
                        )
                    )
                    if session.retirement_confirmed or owned_continuation:
                        preserved = authority_view(store, previous)
                        require(preserved.revision >= current.revision, "authority_revision_regressed")
                        require(all(reader.preserves_prior(item) for item in old_receipts), "prior_receipt_changed")
                        context = HarnessContext(home_dir=root, workspace_dir=session.workspace, guard_home=guard_home)
                        with claude_managed_settings_path(context).open("rb") as stream:
                            registration = stream.read(_STATE_LIMIT + 1)
                        require(len(registration) <= _STATE_LIMIT, "registration_limit")
                        require(
                            hashlib.sha256(registration).hexdigest() == previous["registration_sha256"],
                            "registration_changed",
                        )
                        require(state_preserved(before, policy_state(guard_home)), "policy_changed_after_retirement")
                        _, final_identity = installed_identity(expected)
                        require(final_identity == identity, "artifact_changed_during_phase")
                        checkpoint = {
                            **previous,
                            "phase": phase,
                            "revision": preserved.revision,
                            "rejected_legacy": True,
                            "policy_state": before,
                        }
                        report.update(
                            persistent_authority_preserved=True,
                            registration_preserved=True,
                            control_revision=preserved.revision,
                        )
                        if session.retirement_confirmed:
                            write_private(journal, checkpoint)
                            report["rejected_legacy_start_verified"] = True
                        else:
                            # The worker cannot certify its own future child
                            # exhaustion. Keep its original failure/stop result;
                            # only the owning supervisor may commit this state.
                            report["legacy_postcheck_verified"] = True
                            pending_checkpoint = checkpoint
                except Exception as continuation_error:
                    report["continuation_failure"] = failure_evidence(continuation_error)
    public = assert_privacy_safe(report)
    if pending_checkpoint is not None and exact_rejection(public):
        write_private(
            root.parent / "rejected-legacy-pending.json",
            {
                "nonce": os.environ["HOL_GUARD_TRANSITION_OWNED_NONCE"],
                "worker_report_sha256": digest_json(public),
                "fixture_sha256": tree_digest(root),
                "previous_sha256": digest_json(previous),
                "checkpoint": pending_checkpoint,
            },
        )
    return public


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument(
        "--phase",
        choices=(*_PHASE_NAMES, *_COMPATIBLE_PHASE_NAMES),
        required=True,
    )
    args = parser.parse_args()
    result = run_phase(read_private(args.expected), args.fixture_root.resolve(strict=True), args.phase)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
