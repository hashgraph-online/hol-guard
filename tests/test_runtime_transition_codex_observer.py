from __future__ import annotations

import json
import time
import uuid
from io import StringIO
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge, desktop_hook_proxy
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.native_hook_evidence_writer import NativeHookEvidenceWriter
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, native_runtime_status
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
    load_or_create_installation_correlation_key,
    rotate_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
    PROBE_FIELD,
    PROBE_SCHEMA,
    transition_hook_observation,
)
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


def test_frozen_desktop_configured_bridge_routes_probe_through_signed_proxy(monkeypatch, tmp_path):
    bundle = tmp_path / "HOL Guard.app"
    macos = bundle / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    proxy = macos / "HOL Guard"
    proxy.write_text("signed app fixture", encoding="utf-8")
    proxy.chmod(0o755)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setattr(desktop_hook_proxy, "_codesign_team", lambda _path: "TEAMID")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))

    guard_home = tmp_path / "guard-home"
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    payload = {
        "hook_event_name": "PreToolUse",
        "cwd": str(workspace),
        PROBE_FIELD: {
            "schema": PROBE_SCHEMA,
            "operation_id": str(uuid.uuid4()),
            "request_id": "transition-hook-" + uuid.uuid4().hex,
        },
    }
    command = codex_daemon_hook_bridge._desktop_transition_probe_command(
        data=json.dumps(payload),
        state_path=guard_home / "daemon-state.json",
        query=urlencode({"home": str(home)}),
        hook_timeouts={"PreToolUse": 25},
        environment={"HOL_GUARD_DESKTOP": "1", "HOL_GUARD_DESKTOP_HOOK_PROXY": str(proxy)},
    )

    assert command is not None
    assert command[0:2] == ("/bin/sh", "-c")
    assert command[3] == "hol-guard-desktop-proxy"
    assert command[4] == str(proxy)
    assert command[8] == str(proxy)
    assert command[9] == "1"
    config = json.loads(command[7])
    assert config["harness"] == "codex"
    assert config["cli_args"] == [
        "guard",
        "hook",
        "--guard-home",
        str(guard_home.resolve()),
        "--harness",
        "codex",
        "--home",
        str(home.resolve()),
        "--workspace",
        str(workspace.resolve()),
    ]


def test_frozen_desktop_configured_bridge_fails_closed_without_proxy(monkeypatch, tmp_path):
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.delenv("HOL_GUARD_DESKTOP_HOOK_PROXY", raising=False)
    payload = {
        "hook_event_name": "PreToolUse",
        "cwd": str((tmp_path / "workspace").resolve()),
        PROBE_FIELD: {
            "schema": PROBE_SCHEMA,
            "operation_id": str(uuid.uuid4()),
            "request_id": "transition-hook-" + uuid.uuid4().hex,
        },
    }

    with pytest.raises(RuntimeError, match="signed proxy"):
        codex_daemon_hook_bridge._desktop_transition_probe_command(
            data=json.dumps(payload),
            state_path=tmp_path / "guard-home" / "daemon-state.json",
            query=urlencode({"home": str(tmp_path / "home")}),
            hook_timeouts={"PreToolUse": 25},
            environment={"HOL_GUARD_DESKTOP": "1"},
        )


def test_desktop_bridge_runs_proxy_and_preserves_its_hook_channels(monkeypatch, tmp_path):
    payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
            "cwd": str(tmp_path),
            PROBE_FIELD: {
                "schema": PROBE_SCHEMA,
                "operation_id": str(uuid.uuid4()),
                "request_id": "transition-hook-" + uuid.uuid4().hex,
            },
        }
    )
    launched = []
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(
        codex_daemon_hook_bridge,
        "_bound_hook_input",
        lambda *_args, **_kwargs: ("PreToolUse", payload, 10.0, time.monotonic(), payload),
    )
    monkeypatch.setattr(
        codex_daemon_hook_bridge,
        "_desktop_transition_probe_command",
        lambda **_kwargs: ("signed-proxy", "probe-config"),
    )

    def launch(command, **kwargs):
        launched.append((tuple(command), kwargs))
        return BoundedHookProcessResult(
            returncode=0,
            stdout='{"hookSpecificOutput":{"permissionDecision":"allow"}}',
            output_limit_exceeded=False,
            timed_out=False,
            stderr='{"schema":"native-observation"}\n',
        )

    monkeypatch.setattr(codex_daemon_hook_bridge, "run_isolated_hook_process", launch)
    monkeypatch.setattr(
        codex_daemon_hook_bridge.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("the native bridge ran"),
    )
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "stdout", stdout)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "stderr", stderr)

    result = codex_daemon_hook_bridge.main(
        state_path=tmp_path / "guard" / "daemon-state.json",
        fallback_command=("fallback",),
        start_command=("start",),
        query="home=%2Ftmp%2Fhome",
        hook_timeouts={"PreToolUse": 10},
    )

    assert result == 0
    assert launched[0][0] == ("signed-proxy", "probe-config")
    assert launched[0][1]["input_text"] == payload
    assert stdout.getvalue() == '{"hookSpecificOutput":{"permissionDecision":"allow"}}'
    assert stderr.getvalue() == '{"schema":"native-observation"}\n'


def test_desktop_dispatch_hands_the_runtime_what_is_left_of_the_budget(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Desktop dispatch spends hook time, so the runtime reviews inside the rest of it."""
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(tmp_path)})
    stdout, stderr = StringIO(), StringIO()
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    # Four of this hook's eight seconds are already gone when the runtime starts.
    monkeypatch.setattr(
        codex_daemon_hook_bridge,
        "_bound_hook_input",
        lambda *_args, **_kwargs: ("PreToolUse", payload, 8.0, time.monotonic() - 4.0, payload),
    )
    monkeypatch.setattr(codex_daemon_hook_bridge, "_desktop_transition_probe_command", lambda **_kwargs: None)
    monkeypatch.setattr(
        codex_daemon_hook_bridge, "_native_bridge_executable", lambda _guard_home: tmp_path / "hol-guard-runtime"
    )
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "stdout", stdout)
    monkeypatch.setattr(codex_daemon_hook_bridge.sys, "stderr", stderr)
    budgets: list[float] = []
    configured: list[int] = []

    def run(command, **kwargs):
        budgets.append(kwargs["timeout"])
        configured.append(json.loads(command[2])["hook_timeouts"]["PreToolUse"])
        raise codex_daemon_hook_bridge.subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(codex_daemon_hook_bridge.subprocess, "run", run)

    result = codex_daemon_hook_bridge.main(
        state_path=tmp_path / "guard" / "daemon-state.json",
        fallback_command=("fallback",),
        start_command=("start",),
        query="home=%2Ftmp%2Fhome",
        hook_timeouts={"PreToolUse": 10},
    )

    assert result == 0
    # The runtime subtracts the same two-second grace from what it is told, so
    # the five seconds in its config leave it the three this hook has left.
    assert configured == [5]
    # Python's own wait only outlives that deadline; it does not set it, and it
    # ends before Codex's own, so this denial is written while Codex still reads
    # the hook.
    assert configured[0] - 2 < budgets[0] < configured[0]
    assert json.loads(stdout.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(stderr.getvalue())["causes"] == [{"reason_code": "codex_hook_native_runtime_deadline_exceeded"}]


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
        writer = NativeHookEvidenceWriter(store=store)
        # The deadline measures the observer, not one-time native store provisioning.
        _ = store.count_command_shadow_observations()
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
