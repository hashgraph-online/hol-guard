"""Exercise installed native extension decisions, authenticated controls and receipts.

Only synthetic command strings are evaluated; target commands are never executed.
The disposable enrolled fixture uses generated production keys. Interactive local
terminal enrollment is not exercised by this headless probe.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_FILE_NAME
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.native_resident_client import (
    close_native_residents,
    native_resident_client_failure_code,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_RECEIPT_PERSISTENCE_TIMEOUT_SECONDS = 20.0

_ACTION_RANK = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(f"installed_native_extensions_failed:{code}")


def installed_probe_support():
    spec = importlib.util.spec_from_file_location(
        "installed_extension_probe_support", Path(__file__).with_name("installed_extension_probe_support.py")
    )
    require(spec is not None and spec.loader is not None, "support_missing")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_support = installed_probe_support()
prove_installed_data_only_authoring = _support.prove_installed_data_only_authoring
persisted_native_receipt_ids = _support.persisted_native_receipt_ids
receipt_processed_count = _support.receipt_processed_count
await_persisted_native_receipt = _support.await_persisted_native_receipt
receipt_binding_diagnostic = _support.receipt_binding_diagnostic
policy_readiness_diagnostic = _support.policy_readiness_diagnostic


def installed_client():
    spec = importlib.util.spec_from_file_location(
        "native_extension_installed_client", Path(__file__).with_name("installed_hook_client.py")
    )
    require(spec is not None and spec.loader is not None, "client_missing")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.installed_hook_request


def provision(store: GuardStore) -> None:
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(store.guard_home)
    catalog = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    with store._extension_control_authority_lock():
        before = store._read_extension_control_authority_locked(catalog)
        require(before.health is AuthorityHealth.UNENROLLED, "fixture_not_new")
        store._bootstrap_extension_control_authority(catalog, key=None)
        after = store._read_extension_control_authority_locked(catalog)
        require(after.health is AuthorityHealth.PROTECTED and after.revision == 0 and not after.layers, "bootstrap")


def commit_controls(store: GuardStore, password: str, controls: tuple[ExtensionControl, ...]) -> int:
    catalog = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    require(before.health is AuthorityHealth.PROTECTED, "mutation_not_protected")
    layers = (
        ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.LOCAL_ADMIN,
            catalog_digest=catalog,
            global_lockdown=False,
            controls=controls,
        ),
    )
    nonce = secrets.token_hex(16)
    mutation = ExtensionControlMutation(
        previous_revision=before.revision,
        catalog_digest=catalog,
        layers=layers,
        actor_id="isolated-installed-probe",
        idempotency_key=nonce,
        nonce=nonce,
    )
    proof = issue_extension_control_proof(
        store.guard_home, mutation, approval_gate_input=ApprovalGateInput(password=password), session_nonce=nonce
    )
    store.commit_extension_control_layers(
        layers,
        catalog_digest=catalog,
        actor_id=mutation.actor_id,
        expected_revision=before.revision,
        idempotency_key=nonce,
        nonce=nonce,
        proof=proof,
    )
    after = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    require(after.health is AuthorityHealth.PROTECTED and after.revision == before.revision + 1, "mutation_commit")
    return after.revision


def control(kind: ControlTargetKind, target: str, state: ControlState) -> ExtensionControl:
    return ExtensionControl(ControlTarget(kind, target), state)


def ready(
    daemon: GuardDaemonServer,
    workspace: Path,
    revision: int,
    *,
    previous_publisher: object | None = None,
) -> dict[str, object]:
    worker = daemon._server.hook_worker
    # This functional fixture awaits a production publication, including a
    # cold Windows restart. Keep one bound for publication and admission, and
    # do not expire before the publisher's own platform timeout. Installed
    # readiness latency is enforced separately by native_slo_contract.
    deadline = time.monotonic() + max(5.0, _PUBLISH_TIMEOUT_SECONDS)
    publisher = worker.policy_snapshot_publisher
    publisher.register_workspace(workspace)
    publisher.start()
    # Await asynchronous control publication before measuring hook admission.
    published = publisher.wait_until_ready(deadline)
    if not published:
        print(
            json.dumps(
                {
                    "schema": "guard.installed-native-extension-readiness-failure.v1",
                    "stage": "publication",
                    "publisher": policy_readiness_diagnostic(publisher),
                    "previous_publisher": (
                        policy_readiness_diagnostic(previous_publisher) if previous_publisher is not None else None
                    ),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    require(published, "policy_not_ready")
    binding = worker.prepare_workspace_policy(workspace, deadline=deadline)
    require(binding is not None, "policy_not_ready")
    snapshot = publisher.current_snapshot()
    require(snapshot is not None, "snapshot_missing")
    require(snapshot["command_extensions"]["revision"] == revision, "wrong_control_generation")
    return binding


def exercise(root: Path) -> dict[str, object]:
    home, workspace = root / "home", root / "work"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    store = GuardStore(home)
    password = secrets.token_urlsafe(32)
    update_guard_settings(home, {"mode": "enforce"})
    update_settings(
        home, {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0}
    )
    provision(store)
    request = installed_client()
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=root, workspace_dir=workspace)
    rows: list[dict[str, object]] = []
    all_receipts: list[str] = []
    previous_publisher: object | None = None

    def case(
        label: str,
        command: str,
        revision: int,
        *,
        matched: str | None,
        minimum: str | None = None,
        minimum_at_least: str | None = None,
        tool_payload: dict[str, object] | None = None,
        permission_id: str | None = None,
    ) -> dict:
        binding = ready(daemon, workspace, revision, previous_publisher=previous_publisher)
        payload = tool_payload or {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        payload = {"hook_event_name": "PreToolUse", **payload}
        raw = review_raw_hook_native(
            payload=payload,
            harness="claude-code",
            event="PreToolUse",
            guard_home=home,
            home_dir=root,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=binding,
        )
        if raw is None:
            print(
                json.dumps(
                    {
                        "schema": "guard.installed-native-extension-failure.v1",
                        "case": label,
                        "completed_cases": len(rows),
                        "control_revision": revision,
                        "policy_generation": binding["generation"],
                        "native_failure_code": native_resident_client_failure_code(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        require(raw is not None, f"{label}:native_missing")
        result = raw["result"]
        extensions = result.get("command_extensions")
        require(isinstance(extensions, dict), f"{label}:extension_binding_missing")
        observations = extensions["observations"]
        ids = [row["rule_id"] for row in observations]
        if matched is not None:
            require(matched in ids, f"{label}:owned_rule_missing")
        else:
            require(
                not any(row["extension_id"] == "command.ollama" for row in observations), f"{label}:external_not_inert"
            )
        if permission_id is not None:
            require(
                any(row["permission_id"] == permission_id for row in extensions["permission_observations"]),
                f"{label}:owned_permission_missing",
            )
        if minimum is not None:
            require(result["minimum_action"] == minimum, f"{label}:wrong_floor:{result['minimum_action']}")
        if minimum_at_least is not None:
            actual = result["minimum_action"]
            require(
                isinstance(actual, str)
                and actual in _ACTION_RANK
                and minimum_at_least in _ACTION_RANK
                and _ACTION_RANK[actual] >= _ACTION_RANK[minimum_at_least],
                f"{label}:floor_below_{minimum_at_least}:{actual}",
            )
        require(result["decision"] == "deny", f"{label}:unsafe_allow")
        known_receipt_ids = persisted_native_receipt_ids(store)
        receipt_writer = daemon._server.runtime_hook_evidence_writer
        receipt_processed_value = receipt_processed_count(receipt_writer)
        require(receipt_processed_value is not None, f"{label}:receipt_writer_stats")
        receipt_processed_before = receipt_processed_value
        response = request(daemon, home, workspace, "claude-code", "PreToolUse", payload)
        require(isinstance(response, dict), f"{label}:http_missing")
        # Compatibility hooks execute in the isolated hook process. Its receipt
        # reaches the parent through the evidence writer, so the parent
        # worker's mutable last-receipt field cannot identify this request.
        # Wait for that asynchronous writer to report successful persistence
        # before querying SQLite, avoiding reader/writer lock churn on Windows.
        receipt = await_persisted_native_receipt(
            store,
            known_receipt_ids,
            writer=receipt_writer,
            receipt_processed_before=receipt_processed_before,
            timeout_seconds=_RECEIPT_PERSISTENCE_TIMEOUT_SECONDS,
        )
        require(receipt.get("authority") == "rust", f"{label}:receipt_missing")
        if receipt.get("command_extensions") != extensions["binding"]:
            diagnostic = receipt_binding_diagnostic(response, receipt, extensions["binding"], all_receipts)
            print(json.dumps({"case": label, "completed_cases": len(rows), **diagnostic}, sort_keys=True), flush=True)
        require(receipt.get("command_extensions") == extensions["binding"], f"{label}:receipt_generation_mismatch")
        require(receipt["decision"] == result["decision"], f"{label}:http_decision_mismatch")
        all_receipts.append(receipt["decision_id"])
        rows.append(
            {
                "case": label,
                "control_revision": revision,
                "decision": receipt["decision"],
                "minimum_action": result["minimum_action"],
                "rule_ids": ids,
                "permission_ids": [row["permission_id"] for row in extensions["permission_observations"]],
                "observations": extensions["binding"]["observation_count"],
            }
        )
        return extensions

    try:
        daemon.start()
        case("external-off", "ollama rm example-model", 0, matched=None)
        enabled = control(ControlTargetKind.EXTENSION, "command.ollama", ControlState.ENABLED)
        revision = commit_controls(store, password, (enabled,))
        case("external-enabled", "ollama rm example-model", revision, matched="command.ollama.rm")
        safe = case("owned-help", "ollama rm --help", revision, matched="command.ollama.rm")
        owned = next(row for row in safe["observations"] if row["rule_id"] == "command.ollama.rm")
        require(bool(owned["safe_variants"]) and not owned["effective_segment_indexes"], "safe_variant_not_applied")
        case(
            "safe-does-not-weaken-floor",
            "ollama rm --help; rm -rf /",
            revision,
            matched="command.ollama.rm",
            minimum="block",
        )
        permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_rule_id("command.ollama.rm")
        require(permission is not None, "permission_missing")
        revision = commit_controls(
            store,
            password,
            (enabled, control(ControlTargetKind.PERMISSION, permission.permission_id, ControlState.DISABLED)),
        )
        case("permission-disabled", "ollama rm example-model", revision, matched="command.ollama.rm", minimum="block")
        revision = commit_controls(
            store, password, (control(ControlTargetKind.EXTENSION, "command.ollama", ControlState.DISABLED),)
        )
        case("external-disabled", "ollama rm example-model", revision, matched=None)
        revision = commit_controls(store, password, (enabled,))
        case("external-reenabled", "ollama push example-model", revision, matched="command.ollama.push")
        previous_publisher = daemon._server.hook_worker.policy_snapshot_publisher
        daemon.stop()
        require(close_native_residents(home), "restart_containment")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=root, workspace_dir=workspace)
        daemon.start()
        case("restart-retains-controls", "ollama rm example-model", revision, matched="command.ollama.rm")
        delegated = [
            extension
            for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
            if extension.delegated_protection == "package-firewall"
        ]
        delegated_controls = tuple(
            control(
                ControlTargetKind.PERMISSION,
                extension.permissions[0].permission_id,
                ControlState.DISABLED,
            )
            for extension in delegated
        )
        revision = commit_controls(store, password, (enabled, *delegated_controls))
        for extension in delegated:
            permission_id = extension.permissions[0].permission_id
            case(
                extension.extension_id,
                f"{extension.executables[0]} install fixture-package",
                revision,
                matched=None,
                minimum="block",
                permission_id=permission_id,
            )
        mcp_enabled = control(ControlTargetKind.EXTENSION, "command.mcp-filesystem", ControlState.ENABLED)
        revision = commit_controls(store, password, (enabled, mcp_enabled))
        mcp_permission = "command.mcp-filesystem.permission.mcp-filesystem-tool"
        case(
            "mcp-write-blocked",
            "",
            revision,
            matched=None,
            minimum="block",
            permission_id=mcp_permission,
            tool_payload={
                "tool_name": "mcp__filesystem__write_file",
                "tool_input": {"path": "fixture.txt", "content": "sample"},
            },
        )
        case(
            "mcp-read-inherits",
            "",
            revision,
            matched=None,
            permission_id=mcp_permission,
            tool_payload={"tool_name": "mcp__filesystem__read_file", "tool_input": {"path": "fixture.txt"}},
        )
        instapods_enabled = control(ControlTargetKind.EXTENSION, "command.mcp-instapods", ControlState.ENABLED)
        revision = commit_controls(store, password, (enabled, instapods_enabled))
        instapods_permission = "command.mcp-instapods.permission.mcp-instapods-tool"
        case(
            "mcp-instapods-delete-review",
            "",
            revision,
            matched=None,
            minimum_at_least="review",
            permission_id=instapods_permission,
            tool_payload={"tool_name": "mcp__instapods__delete_pod", "tool_input": {"pod_id": "synthetic-pod"}},
        )
        case(
            "mcp-instapods-alias-exec-review",
            "",
            revision,
            matched=None,
            minimum_at_least="review",
            permission_id=instapods_permission,
            tool_payload={"tool_name": "mcp__instapods-mcp__exec_command", "tool_input": {"command": "echo synthetic"}},
        )
        case(
            "mcp-instapods-inherit",
            "",
            revision,
            matched=None,
            permission_id=instapods_permission,
            tool_payload={"tool_name": "mcp__instapods__manage_pod", "tool_input": {"operation": "status"}},
        )
        revision = commit_controls(store, password, (enabled,))
        case(
            "mcp-off",
            "",
            revision,
            matched=None,
            tool_payload={
                "tool_name": "mcp__filesystem__write_file",
                "tool_input": {"path": "fixture.txt", "content": "sample"},
            },
        )
        end = time.monotonic() + 5
        while time.monotonic() < end and any(
            store.get_native_decision_receipt(identity) is None for identity in all_receipts
        ):
            time.sleep(0.02)
        require(
            all(store.get_native_decision_receipt(identity) is not None for identity in all_receipts),
            "durable_receipts_missing",
        )
        stale_binding = ready(daemon, workspace, revision)
        marker = home / "native-runtime" / AUTHORITY_FILE_NAME
        marker.write_text("{}\n", encoding="utf-8")
        tampered = review_raw_hook_native(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
            },
            harness="claude-code",
            event="PreToolUse",
            guard_home=home,
            home_dir=root,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=False,
            deadline=time.monotonic() + 5,
            policy_snapshot=stale_binding,
        )
        require(tampered is None or tampered["result"]["decision"] == "deny", "tampered_marker_allowed")
        return {
            "schema": "guard.installed-native-extensions.v1",
            "cases": rows,
            "persisted_receipts": len(all_receipts),
            "marker_tamper_rejected": True,
            "interactive_enrollment_exercised": False,
            "cross_version_upgrade_rollback_exercised": False,
            "bad_generation_injection_exercised": False,
            "stale_approval_replay_exercised": False,
            "target_commands_executed": 0,
        }
    finally:
        daemon.stop()
        require(close_native_residents(home), "final_containment")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    package = Path(codex_plugin_scanner.__file__).resolve()
    require("site-packages" in package.parts, "not_installed_package")
    status = native_runtime_status()
    require(status.available and status.compatible and status.identity is not None, "native_not_available")
    require(
        status.capabilities is not None and "native-command-program-v1" in status.capabilities.features,
        "native_feature_missing",
    )
    authoring = prove_installed_data_only_authoring(package)
    with tempfile.TemporaryDirectory(prefix="hge-", dir=None if os.name == "nt" else "/tmp") as temporary:
        report = exercise(Path(temporary))
    report["data_only_authoring"] = authoring
    report["data_only_authoring_receipts_authenticated"] = False
    report["source_sha"] = status.capabilities.build_sha
    report["rule_digest"] = status.capabilities.rule_digest
    args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
