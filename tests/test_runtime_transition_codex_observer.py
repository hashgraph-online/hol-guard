from __future__ import annotations

import json
import time
import uuid

import pytest

from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, native_runtime_status
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
    load_or_create_installation_correlation_key,
    rotate_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.runtime_transition_admission import verified_admission_payload
from codex_plugin_scanner.guard.runtime_transition_hook_probe import PROBE_FIELD, transition_hook_observation
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_decision_receipt import _receipt


def installed_context(tmp_path):
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    context = HarnessContext(
        home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard", home_override_explicit=True
    )
    store = GuardStore(context.guard_home)
    CodexHarnessAdapter().install(context)
    return context, workspace, store


def observe(context, workspace, identity, deadline, receipt_store=None):
    config = context.home_dir / ".codex" / "config.toml"
    with codex_install_transaction(context.guard_home, config, actor="transition-probe", deadline=deadline):
        return observer.observe_configured_codex_hook(
            operation_id=str(uuid.uuid4()),
            artifact_generation="candidate",
            expected_runtime=identity,
            guard_home=context.guard_home,
            config_path=config,
            workspace=workspace,
            deadline_monotonic=deadline,
            receipt_store=receipt_store,
        )


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("security_level", ["balanced", "paranoid"])
def test_legacy_channel_uses_real_configured_hook_and_persisted_rust_receipts(tmp_path, monkeypatch, security_level):
    with monkeypatch.context() as role_patch:
        paths = codex_adapter._hook_packaged_file_paths
        role_patch.setattr(
            codex_adapter,
            "_hook_packaged_file_paths",
            lambda: tuple((role, path) for role, path in paths() if role not in {"hook_probe", "native_receipt"}),
        )
        context, workspace, store = installed_context(tmp_path)
    (context.guard_home / "config.toml").write_text(f'security_level = "{security_level}"\n')
    live_identity = native_runtime_status().identity
    assert live_identity is not None
    reference = context.guard_home / "native-comparison-reference"
    reference.write_bytes(live_identity.path.read_bytes())
    reference.chmod(0o700)
    metadata = reference.stat()
    identity = NativeRuntimeIdentity(reference, metadata.st_size, metadata.st_mtime_ns, live_identity.sha256)
    assert identity.path != live_identity.path
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=context.home_dir)
    daemon.start()
    real_launch = observer.run_isolated_hook_process
    launched = []
    launch_diagnostics = []

    def legacy_launch(*args, **kwargs):
        payload = json.loads(kwargs["input_text"])
        assert PROBE_FIELD not in payload and payload["tool_call_id"].startswith("transition-hook-")
        launched.append(payload["tool_call_id"])
        started = time.monotonic()
        result = real_launch(*args, **kwargs)
        receipt = daemon._server.hook_worker.last_native_decision_receipt or {}
        output = json.loads(result.stdout)
        launch_diagnostics.append(
            {
                "elapsed": time.monotonic() - started,
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "decision": receipt.get("decision"),
                "policy_action": receipt.get("policy_action"),
                "reason_code": receipt.get("reason_code"),
                "permission_reason": str(output.get("hookSpecificOutput", {}).get("permissionDecisionReason", ""))[
                    :512
                ],
            }
        )
        assert not result.stderr  # Actual bridge has no probe envelope to emit.
        return result

    monkeypatch.setattr(observer, "run_isolated_hook_process", legacy_launch)
    try:
        try:
            proof = observe(context, workspace, identity, time.monotonic() + 20, receipt_store=store)
        except TransitionError as error:
            with store._connect() as connection:
                counts = {
                    name: connection.execute(f"select count(*) from {name}").fetchone()[0]
                    for name in ("command_activity", "command_activity_correlations", "native_hook_decision_receipts")
                }
            pytest.fail(
                str(
                    {
                        "reason": error.reason,
                        "launches": launch_diagnostics,
                        "counts": counts,
                        "writer": daemon._server.runtime_hook_evidence_writer.stats(),
                    }
                )
            )
        assert len(launched) == 2 and len(set(launched)) == 2
        assert proof.allow_receipt["decision"] == "allow" and proof.deny_receipt["decision"] == "deny"
        assert store.get_native_decision_receipt(proof.allow_receipt["decision_id"]) == proof.allow_receipt
        assert store.get_native_decision_receipt(proof.deny_receipt["decision_id"]) == proof.deny_receipt
        assert verified_admission_payload(proof)["installed_hook_evidence"]["harness"] == "codex"
        evidence = verified_admission_payload(proof)["installed_hook_evidence"]
        assert evidence["observation_channel"] == "persisted-receipt"
        assert native_runtime_status().identity == live_identity  # Comparison file never selects the loaded runtime.
    finally:
        daemon.stop()
        assert close_native_residents(context.guard_home, deadline_monotonic=time.monotonic() + 5)


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("no_store", "legacy_probe_store_unavailable"),
        ("missing_key", "legacy_probe_correlation_unavailable"),
        ("unsafe_key", "legacy_probe_correlation_unavailable"),
        ("malformed_key", "legacy_probe_correlation_invalid"),
        ("changed_key", "legacy_probe_correlation_changed"),
        ("missing_receipt", "admission_deadline_expired"),
        ("unrelated_nonce", "admission_deadline_expired"),
        ("wrong_runtime", "admission_protection_failed"),
        ("changed_receipt", "legacy_probe_receipt_invalid"),
        ("stale_receipt", "legacy_probe_receipt_invalid"),
    ],
)
def test_legacy_observer_refuses_unverified_state_without_relaunch(tmp_path, monkeypatch, fault, reason):
    with monkeypatch.context() as role_patch:
        paths = codex_adapter._hook_packaged_file_paths
        role_patch.setattr(
            codex_adapter,
            "_hook_packaged_file_paths",
            lambda: tuple((role, path) for role, path in paths() if role not in {"hook_probe", "native_receipt"}),
        )
        context, workspace, store = installed_context(tmp_path)
    identity = NativeRuntimeIdentity(tmp_path / "fixture-native", 1, 1, "d" * 64)
    writer = None
    if fault not in {"no_store", "missing_key"}:
        load_or_create_installation_correlation_key(context.guard_home)
    if fault == "unsafe_key":
        (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).chmod(0o644)
    elif fault == "malformed_key":
        (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).write_text('{"invalid":"fixture"}')
    if fault in {"unrelated_nonce", "wrong_runtime", "changed_receipt", "stale_receipt"}:
        writer = RuntimeHookEvidenceWriter(store=store)
    launched = []

    def launch(argv, *, input_text, **kwargs):
        payload = json.loads(input_text)
        launched.append(payload["tool_call_id"])
        if fault == "changed_key":
            rotate_installation_correlation_key(context.guard_home)
        if writer is not None:
            receipt = _receipt(
                harness="codex",
                event_name="PreToolUse",
                runtime_identity="0" * 64 if fault == "wrong_runtime" else identity.sha256,
            )
            if fault == "unrelated_nonce":
                payload["tool_call_id"] = uuid.uuid4().hex
            assert writer.submit_native_decision_receipt(receipt=receipt)
            assert writer.submit_command_activity(
                harness="codex",
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action="allow",
                receipt_id=receipt["decision_id"],
            )
            assert writer.stop(timeout_seconds=1)
            if fault in {"changed_receipt", "stale_receipt"}:
                with store._connect() as connection:
                    if fault == "changed_receipt":
                        connection.execute("update native_hook_decision_receipts set runtime_identity = ?", ("0" * 64,))
                    else:
                        connection.execute(
                            "update native_hook_decision_receipts set recorded_at = ?", ("2000-01-01T00:00:00+00:00",)
                        )
        return BoundedHookProcessResult(0, "{}", False, False, stderr="")

    monkeypatch.setattr(observer, "run_isolated_hook_process", launch)
    try:
        with pytest.raises(TransitionError, match=reason):
            observe(
                context,
                workspace,
                identity,
                time.monotonic() + 0.7,
                receipt_store=None if fault == "no_store" else store,
            )
        assert len(launched) == (0 if fault in {"no_store", "missing_key", "unsafe_key", "malformed_key"} else 1)
        if fault == "missing_key":
            assert not (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).exists()
        if fault == "unsafe_key":
            assert (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).stat().st_mode & 0o777 == 0o644
    finally:
        if writer is not None:
            assert writer.stop(timeout_seconds=1)


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize("security_level", [None, "paranoid"], ids=["default", "hard_block"])
def test_real_configured_argv_traverses_daemon_rpc_and_native_edge(tmp_path, monkeypatch, security_level):
    context, workspace, store = installed_context(tmp_path)
    if security_level is not None:
        (context.guard_home / "config.toml").write_text(f'security_level = "{security_level}"\n')
    identity = native_runtime_status().identity
    assert identity is not None
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=context.home_dir)
    daemon.start()
    assert load_guard_config(context.guard_home).security_level == (security_level or "balanced")
    policy_path = context.guard_home / "config.toml"
    policy_before = policy_path.read_bytes() if policy_path.exists() else None
    real_launch = observer.run_isolated_hook_process
    real_review = daemon._server.hook_worker.review_http_payload
    reviews = []

    def measured_review(**kwargs):
        result = real_review(**kwargs)
        receipt = daemon._server.hook_worker.last_native_decision_receipt or {}
        response = result or {}
        reviews.append(
            {
                "probe_present": PROBE_FIELD in kwargs["payload"],
                "decision": receipt.get("decision"),
                "harness": receipt.get("harness"),
                "receipt_present": bool(receipt),
                "policy_action": response.get("policy_action"),
                "reason_code": response.get("reason_code"),
                "prompted": response.get("prompted") is True,
            }
        )
        return result

    monkeypatch.setattr(daemon._server.hook_worker, "review_http_payload", measured_review)

    def measured_launch(*args, **kwargs):
        started = time.monotonic()
        result = real_launch(*args, **kwargs)
        assert not result.timed_out, {
            "elapsed": time.monotonic() - started,
            "returncode": result.returncode,
            "containment_failed": result.containment_failed,
            "stdout_present": bool(result.stdout),
            "stderr_present": bool(result.stderr),
            "reviews": reviews,
        }
        output = json.loads(result.stdout)
        assert result.stderr, {
            "elapsed": time.monotonic() - started,
            "returncode": result.returncode,
            "containment_failed": result.containment_failed,
            "output_limit_exceeded": result.output_limit_exceeded,
            "output_keys": list(output),
            "reason_code": output.get("reason_code"),
            "reviews": reviews,
        }
        observed = json.loads(result.stderr)["native_receipt"]
        expected = "allow" if json.loads(kwargs["input_text"])["tool_input"].get("command") == "pwd" else "deny"
        assert observed["decision"] == expected, {
            "expected": expected,
            "decision": observed["decision"],
            "policy_action": observed["policy_action"],
            "reason_code": observed["reason_code"],
            "reviews": reviews,
        }
        assert observed["runtime_identity"] == identity.sha256
        permission = output.get("hookSpecificOutput", {}).get("permissionDecision")
        assert permission in ({None, "allow"} if expected == "allow" else {"deny"}), {
            "expected": expected,
            "permission": permission,
            "output_keys": list(output),
        }
        return result

    monkeypatch.setattr(observer, "run_isolated_hook_process", measured_launch)
    try:
        proof = observe(context, workspace, identity, time.monotonic() + 20)
        assert len(reviews) == 2 and all(item["probe_present"] and item["receipt_present"] for item in reviews)
        assert [item["decision"] for item in reviews] == ["allow", "deny"]
        assert all(not item["prompted"] for item in reviews)
        payload = verified_admission_payload(proof)
        assert proof.allow_receipt["decision"] == "allow"
        assert proof.deny_receipt["decision"] == "deny"
        assert proof.deny_receipt["policy_action"] == "block"
        assert (policy_path.read_bytes() if policy_path.exists() else None) == policy_before
        assert payload["installed_hook_evidence"]["harness"] == "codex"
        assert payload["installed_hook_evidence"]["observation_channel"] == "probe-envelope"
        # Active hook evidence is covered by the same tamper seal as receipts.
        proof.installed_hook_evidence["harness"] = "foreign"
        with pytest.raises(TransitionError, match="functional_proof_missing"):
            verified_admission_payload(proof)
    finally:
        daemon.stop()
        assert close_native_residents(context.guard_home, deadline_monotonic=time.monotonic() + 3)


@pytest.mark.usefixtures("native_hook_force")
@pytest.mark.parametrize(
    "fault",
    [
        "missing_receipt",
        "replay",
        "foreign_runtime",
        "wrong_stdout",
        "policy_change",
        "changed_config",
        "containment",
        "deadline",
    ],
)
def test_configured_observer_refuses_false_functional_proof(tmp_path, monkeypatch, fault):
    context, workspace, store = installed_context(tmp_path)
    identity = native_runtime_status().identity
    assert identity is not None
    calls = []
    deadline = time.monotonic() + 5

    def launch(argv, *, input_text, **kwargs):
        calls.append((argv, kwargs))
        payload = json.loads(input_text)
        decision = "allow" if len(calls) == 1 else "deny"
        receipt = _receipt(
            request_id=payload[PROBE_FIELD]["request_id"],
            harness="codex",
            event_name="PreToolUse",
            runtime_identity=identity.sha256,
            decision=decision,
            policy_action=decision,
            request_digest=("a" if decision == "allow" else "b") * 64,
            policy_generation=2 if fault == "policy_change" and len(calls) == 2 else 1,
        )
        if fault == "replay":
            receipt["request_id"] = "transition-hook-" + "0" * 32
        elif fault == "foreign_runtime":
            receipt["runtime_identity"] = "0" * 64
        observation = transition_hook_observation(payload, receipt)
        if fault == "missing_receipt":
            observation = {}
        output = {"hookSpecificOutput": {"permissionDecision": decision}}
        if fault == "wrong_stdout" and len(calls) == 2:
            output = {}
        if fault == "changed_config":
            config = context.home_dir / ".codex" / "config.toml"
            config.write_bytes(config.read_bytes() + b"\n# concurrent writer\n")
        if fault == "deadline":
            monkeypatch.setattr(observer.time, "monotonic", lambda: deadline + 1)
        return BoundedHookProcessResult(
            0,
            json.dumps(output),
            False,
            False,
            containment_failed=fault == "containment",
            stderr=json.dumps(observation),
        )

    monkeypatch.setattr(observer, "run_isolated_hook_process", launch)

    def forbidden_legacy_lookup(*args, **kwargs):
        raise AssertionError("modern channel failure attempted legacy rescue")

    monkeypatch.setattr(observer, "read_legacy_codex_probe_receipt", forbidden_legacy_lookup)
    with pytest.raises(TransitionError):
        observe(context, workspace, identity, deadline, receipt_store=store)
    assert calls and all(call[1]["deadline_monotonic"] == deadline for call in calls)


@pytest.mark.parametrize("fault", ["disabled", "argv", "missing_manifest", "expired"])
def test_invalid_configuration_never_launches_a_child(tmp_path, monkeypatch, fault):
    context, workspace, _store = installed_context(tmp_path)
    config = context.home_dir / ".codex" / "config.toml"
    if fault == "disabled":
        config.write_text(config.read_text().replace("hooks = true", "hooks = false"))
    elif fault == "argv":
        config.write_text(config.read_text().replace("codex_daemon_hook_bridge.py", "foreign_bridge.py"))
    elif fault == "missing_manifest":
        hook_manifest_path(context.guard_home, config).unlink()
    deadline = time.monotonic() + (5 if fault != "expired" else -1)

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid binding launched a child")

    monkeypatch.setattr(observer, "run_isolated_hook_process", forbidden)
    # Expiry is tested before acquiring the transaction so this exercises the
    # observer boundary rather than the installer lock's own deadline check.
    with (
        codex_install_transaction(context.guard_home, config, actor="transition-probe"),
        pytest.raises(TransitionError),
    ):
        observer.observe_configured_codex_hook(
            operation_id=str(uuid.uuid4()),
            artifact_generation="candidate",
            expected_runtime=None,
            guard_home=context.guard_home,
            config_path=config,
            workspace=workspace,
            deadline_monotonic=deadline,
        )
