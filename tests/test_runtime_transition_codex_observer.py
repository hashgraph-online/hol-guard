from __future__ import annotations

import json
import time
import uuid

import pytest

from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
from codex_plugin_scanner.guard.codex_harness_lifecycle import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.harness.base import HarnessContext
from codex_plugin_scanner.guard.native_hook_evidence_writer import NativeHookEvidenceWriter
from codex_plugin_scanner.guard.native_owned import codex_install_transaction
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, native_runtime_status
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
)
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
    PROBE_FIELD,
    PROBE_SCHEMA,
    transition_hook_observation,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_legacy_roles import without_package_roles
from tests.command_activity_correlation_key_support import write_correlation_key
from tests.native_store_shims import count_command_shadow_observations
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


@pytest.mark.parametrize(
    ("desktop", "proxy", "expected"),
    [
        (None, "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard", {}),
        ("0", "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard", {}),
        ("1", "relative/proxy", {}),
        (
            "1",
            "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard",
            {
                "HOL_GUARD_DESKTOP": "1",
                "HOL_GUARD_DESKTOP_HOOK_PROXY": "/Applications/HOL Guard.app/Contents/MacOS/HOL Guard",
            },
        ),
    ],
)
def test_desktop_hook_proxy_context_is_explicit_and_minimal(monkeypatch, desktop, proxy, expected):
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP_HOOK_PROXY", raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", raising=False)
    if desktop is not None:
        monkeypatch.setenv("HOL_GUARD_DESKTOP", desktop)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", proxy)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", "/untrusted/runtime-owner")

    context = observer._desktop_hook_proxy_context()

    assert context == expected
    assert "HOL_GUARD_DESKTOP_RUNTIME_OWNER" not in context


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
def test_legacy_observer_refuses_unverified_state_without_relaunch(
    native_hook_force, tmp_path, monkeypatch, fault, reason
):
    with without_package_roles(monkeypatch, {"hook_probe", "native_receipt"}):
        context, workspace, store = installed_context(tmp_path)
    identity = NativeRuntimeIdentity(tmp_path / "fixture-native", 1, 1, "d" * 64)
    writer = None
    if fault not in {"no_store", "missing_key"}:
        write_correlation_key(context.guard_home)
    if fault == "unsafe_key":
        (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).chmod(0o644)
    elif fault == "malformed_key":
        (context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).write_text('{"invalid":"fixture"}')
    if fault in {"unrelated_nonce", "wrong_runtime", "changed_receipt", "stale_receipt"}:
        writer = NativeHookEvidenceWriter(store=store)
        # The deadline measures the observer, not one-time native store provisioning.
        _ = count_command_shadow_observations(store)
    launched = []

    def launch(argv, *, input_text, **kwargs):
        payload = json.loads(input_text)
        launched.append(payload["tool_call_id"])
        if fault == "changed_key":
            write_correlation_key(context.guard_home)
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
        config.write_text(config.read_text().replace("codex-hook-bridge", "foreign-bridge"))
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


def _observation_envelope() -> dict[str, object]:
    request_id = "transition-hook-" + "c" * 32
    payload = {
        PROBE_FIELD: {
            "schema": PROBE_SCHEMA,
            "operation_id": str(uuid.uuid4()),
            "request_id": request_id,
        }
    }
    receipt = _receipt(
        request_id=request_id,
        harness="codex",
        event_name="PreToolUse",
        decision="allow",
        policy_action="allow",
    )
    observation = transition_hook_observation(payload, receipt)
    assert observation is not None
    return observation


def test_observation_is_read_from_a_stderr_shared_with_runtime_diagnostics():
    # The native bridge writes the observation to the hook's own stderr, which
    # the runtime also traces resident phases on under
    # HOL_GUARD_NATIVE_DIAGNOSTIC. The whole stream is not one JSON document.
    observation = _observation_envelope()
    stderr = (
        "native_resident_phase phase=client_connect status=start elapsed_ms=0\n"
        + json.dumps(observation)
        + "\nnative_resident_phase phase=client_close status=ok elapsed_ms=1\n"
    )
    assert observer._probe_observation(stderr) == observation


@pytest.mark.parametrize(
    "stderr", ["", "native_resident_phase phase=client_connect status=start elapsed_ms=0\n", '{"schema":"other"}\n']
)
def test_missing_observation_is_refused_rather_than_guessed(stderr):
    with pytest.raises(ValueError):
        observer._probe_observation(stderr)
