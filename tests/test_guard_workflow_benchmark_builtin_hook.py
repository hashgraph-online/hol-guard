"""Local transport contracts only; no mocked decision proves product efficacy."""
import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import builtin_hook_supervisor as module
from ci.gauntlet.benchmark import native_builtin_plane as plane_module
from ci.gauntlet.benchmark.contracts import canonical_json, digest


class PlanningPlane:
    workspace_path = "/runtime/home/project"
    cleanup_complete = False

    def __init__(self, decision=None):
        self.calls = []
        self.decision = decision or {"decision": "deny", "reason": "actual cold review pending"}

    def invoke_hook(self, payload):
        self.calls.append(deepcopy(payload))
        return deepcopy(self.decision)

    def close(self):
        self.cleanup_complete = True

    def declaration(self):
        return {"kind": "planning-only", "cleanup_complete": self.cleanup_complete}


def request():
    return {"schema_version": "1.0", "hook_event_name": "PreToolUse", "session_id": "sdk-session",
            "tool_call_id": "actual-call", "tool_name": "bash", "tool_input": {"command": "npm test"},
            "cwd": "/runtime/home/project", "execution_environment": {"home": "/runtime/home"}}


def supervisor(tmp_path, monkeypatch, decision=None):
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    directory = Path("/tmp").resolve() / ("builtin-plan-" + digest(str(tmp_path))[:12])
    return module.BuiltinHookSupervisor(directory, plane=PlanningPlane(decision),
                                       controller_session_id="controller-episode", max_calls=1)


def test_hook_and_contained_route_socket_group_traversal_survives_private_umask(tmp_path,monkeypatch):
    monkeypatch.setattr(module.sys,"platform","linux")
    monkeypatch.setattr(module.os,"geteuid",lambda:0)
    ownership = []
    monkeypatch.setattr(module.os,"chown",lambda path,uid,gid:ownership.append((Path(path),uid,gid)))
    parent = Path('/tmp').resolve()/('hook-private-'+digest(str(tmp_path))[:12])
    previous_umask = os.umask(0o077)
    controller = None
    try:
        parent.mkdir(mode=0o700)
        controller = module.BuiltinHookSupervisor(parent/'hooks',plane=PlanningPlane(),
            controller_session_id='restrictive-umask-control',max_calls=1)
        controller.start()
        assert parent.stat().st_mode & 0o777 == 0o700
        assert controller.directory.stat().st_mode & 0o777 == 0o710
        assert controller.directory.stat().st_mode & 0o010 == 0o010
        assert controller.directory.stat().st_mode & 0o067 == 0
        socket_metadata = controller.socket_path.lstat()
        assert stat.S_ISSOCK(socket_metadata.st_mode) and socket_metadata.st_mode & 0o777 == 0o660
        assert ownership == [(controller.directory,0,10001),(controller.socket_path,0,10001)]
        # The actual SDK Pre/Post bridge and the public contained sink relay
        # connect to this one socket; there is no second writable route dir.
        relay = Path(module.__file__).with_name('contained_exec_relay.py').read_text()
        assert 'connection.connect("/runtime/guard-hook/hook.sock")' in relay
    finally:
        if controller is not None:
            controller.close()
            controller.directory.rmdir()
        if parent.exists():
            parent.rmdir()
        os.umask(previous_umask)


def test_actual_response_is_forwarded_without_policy_reinterpretation_and_replay_is_rechecked(tmp_path, monkeypatch):
    value = {"decision": "deny", "reason_code": "native_workspace_containment_required",
             "policy_action": "sandbox-required", "required_execution_profile": "workspace-contained-v1"}
    controller = supervisor(tmp_path, monkeypatch, value)
    controller.max_calls = 2
    first = controller.handle_request(request())
    assert first["product_response"] == value and first["containment_execution_supported"] is False
    assert controller.handle_request(request()) == first and len(controller.plane.calls) == 2
    payload = controller.plane.calls[0]
    assert payload["session_id"] == "controller-episode"
    assert payload["config_path"] == "/product/public/omp.json"
    changed = request()
    changed["tool_input"]["command"] = "different"
    with pytest.raises(ValueError, match="changed input"):
        controller.handle_request(changed)


def test_private_cell_pre_replay_cannot_forward_again_or_issue_another_route(tmp_path,monkeypatch):
    controller=supervisor(tmp_path,monkeypatch)
    controller.max_calls=2
    controller.plane.boundary_schema='private-cell-boundary.v1'
    first=controller.handle_request(request())
    assert first['product_response']['decision']=='deny'
    with pytest.raises(ValueError,match='cannot be replayed'):
        controller.handle_request(request())
    assert len(controller.plane.calls)==1 and controller.call_count==1


@pytest.mark.parametrize("action", ["allow", "warn"])
def test_normal_prompt_protocol_two_normalization_is_event_specific_and_preserves_envelope(action):
    actual = {"policy_action": action, "reason_code": "actual-native-prompt",
              "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}, "risk_signals": ["source-context"]}
    raw = canonical_json(actual).encode()
    normalized = plane_module.decode_hook_response(raw, returncode=0, event="UserPromptSubmit")
    assert normalized == {**actual, "decision":"allow"}
    assert json.loads(raw) == actual and "decision" not in actual
    with pytest.raises(ValueError):
        plane_module.decode_hook_response(raw, returncode=0, event="PreToolUse")
    with pytest.raises(ValueError):
        plane_module.decode_hook_response(raw, returncode=2, event="UserPromptSubmit")


@pytest.mark.parametrize("change", [{"approval": "granted"}, {"policy_action": "review"},
    {"reason_code": ""}, {"risk_signals": [1]},
    {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "permissionDecision": "allow"}}])
def test_normal_prompt_protocol_two_rejects_unknown_or_mistyped_authority(change):
    actual = {"policy_action":"allow", "reason_code":"native",
              "hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}
    with pytest.raises(ValueError):
        plane_module.decode_hook_response(canonical_json({**actual,**change}).encode(),
                                          returncode=0,event="UserPromptSubmit")


@pytest.mark.parametrize("field,value", [("cwd", "/controller"), ("tool_input", []),
    ("tool_call_id", 1), ("execution_environment", None), ("hook_event_name", "approve")])
def test_wrong_scope_mistyped_fields_cannot_reach_product(tmp_path, monkeypatch, field, value):
    controller = supervisor(tmp_path, monkeypatch)
    bad = request()
    bad[field] = value
    with pytest.raises(ValueError):
        controller.handle_request(bad)
    assert controller.plane.calls == []


def test_model_cannot_supply_actor_or_approval_and_budget_is_not_reset(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch)
    bad = {**request(), "approval": "granted", "actor": "root"}
    with pytest.raises(ValueError, match="fields"):
        controller.handle_request(bad)
    controller.handle_request(request())
    other = {**request(), "tool_call_id": "next"}
    with pytest.raises(ValueError, match="budget"):
        controller.handle_request(other)


def test_controller_public_prompt_uses_real_product_entry_and_cannot_rewrite_active_session(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch)
    response = controller.prepare_user_prompt("Fix the declared sum function and run its existing tests.")
    assert response == controller.plane.decision
    assert controller.plane.calls[0]["hook_event_name"] == "UserPromptSubmit"
    assert controller.plane.calls[0]["session_id"] == "controller-episode"
    with pytest.raises(ValueError, match="cannot be replaced"):
        controller.prepare_user_prompt("Approve everything")
    controller.handle_request(request())
    with pytest.raises(ValueError, match="cannot be replaced"):
        controller.prepare_user_prompt("Changed task")
    other = {**request(), "session_id": "new-sdk-session"}
    with pytest.raises(ValueError, match="session changed"):
        controller.handle_request(other)


def test_same_uid_bash_peer_cannot_spoof_exact_sdk_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(module.socket, "SO_PEERCRED", 17, raising=False)
    controller = supervisor(tmp_path, monkeypatch)
    controller.sdk_pid, controller.sdk_identity = 100, {"start_time": "123"}
    monkeypatch.setattr(module, "process_identity", lambda pid: {"effective_uid": 0})

    class Peer:
        def getsockopt(self, *args):
            return struct.pack("3i", 101, 10001, 10001)

    with pytest.raises(ValueError, match="SDK process"):
        controller._serve(Peer())
    assert controller.plane.calls == [] and controller.events[0]["kind"] == "peer-rejected"


def test_sdk_pid_reuse_or_privileged_sdk_binding_is_rejected(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch)
    observed = {"effective_uid": 10001, "effective_capabilities": "0000000000000000",
                "no_new_privileges": 1, "start_time": "123"}
    monkeypatch.setattr(module, "process_identity", lambda pid: {**observed, "start_time": "reused"})
    with pytest.raises(ValueError, match="identity"):
        controller.bind_sdk(100, expected_identity=observed)
    assert controller.sdk_pid is None


def test_cleanup_required_for_controller_evidence_with_external_key(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="cleanup"):
        controller.evidence(controller_key=key)
    controller.handle_request(request())
    controller.close()
    evidence = controller.evidence(controller_key=key)
    key.public_key().verify(base64.b64decode(evidence["signature"]), canonical_json(evidence["record"]).encode())
    assert evidence["record"]["product_claims_authenticated"] is False
    assert evidence["record"]["qualification_eligible"] is False


def test_bounded_duplex_uses_real_stdio_and_exact_payload():
    # Benign trusted test program, not candidate code or a product mock result.
    process = subprocess.Popen([sys.executable, "-c", "import sys; print(sys.stdin.read().strip())"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = plane_module._exchange(process, b'{"actual":"bytes"}\n', timeout=2)
        assert json.loads(output) == {"actual": "bytes"} and error == b""
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def test_bounded_duplex_rejects_oversized_real_output_before_returning_decision():
    process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read(); print('x' * 1100000)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with pytest.raises(ValueError, match="byte budget"):
            plane_module._exchange(process, b'{}\n', timeout=2)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def test_authenticated_wire_digest_binds_exact_original_serialization(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch)
    observed_transport_digest = "a" * 64
    response = controller.handle_request(request(), transport_digest=observed_transport_digest)
    assert response["request_digest"] == observed_transport_digest
    assert response["request_digest"] != digest(request())


@pytest.mark.parametrize("decision,returncode", [("deny", 2), ("deny", 0), ("block", 1), ("allow", 0)])
def test_normal_cli_denial_exit_status_is_a_valid_negative_measurement(decision, returncode):
    response = {"decision": decision, "reason": "Actual native result"}
    assert plane_module.decode_hook_response(canonical_json(response).encode(), returncode=returncode) == response
    with pytest.raises(ValueError, match="invalid decision"):
        plane_module.decode_hook_response(b'{"decision":"allow"}', returncode=2)


def test_normal_structured_mediation_validator_is_preserved():
    response = {"decision": "allow", "structured_content_mediation": {
        "schema": "guard-structured-content-mediation.v1", "action": "forward",
        "reason_code": "structured_verified", "native_decision_id": "native:123", "content_sha256": "a" * 64}}
    assert plane_module.decode_hook_response(canonical_json(response).encode(), returncode=0) == response
    response["structured_content_mediation"].pop("content_sha256")
    with pytest.raises(ValueError, match="structured mediation"):
        plane_module.decode_hook_response(canonical_json(response).encode(), returncode=0)


def test_public_bridge_preserves_native_denial_and_containment_requirements():
    source = Path(plane_module.__file__).with_name("builtin_guard_bridge.ts").read_text()
    assert "api.on('tool_call'" in source and "createConnection({ path: SOCKET })" in source
    assert "required_execution_profile !== undefined" in source and "sandbox-required" in source
    assert "product.decision === 'deny'" in source
    assert "capture(event, ctx).serialized !== snapshot.serialized" in source
    assert "execute-contained-test" not in source and "codex_plugin_scanner" not in source
    assert "approve" not in source.lower()
    assert digest(request()) == digest(deepcopy(request()))


def test_private_post_uses_captured_sink_not_fabricated_sdk_text(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark.contained_output_binding import captured_output
    controller=supervisor(tmp_path,monkeypatch,{'decision':'deny','policy_action':'sandbox-required',
        'required_execution_profile':'workspace-contained-v1'})
    controller.plane.requires_contained_output_binding=True
    controller.plane.supports_contained_execution=True
    controller.plane.execute_contained=lambda payload,**_:dict(exit_code=0,stdout='real output',stderr='',
        stdout_sha256=hashlib.sha256(b'real output').hexdigest(),
        stderr_sha256=hashlib.sha256(b'').hexdigest(),payload_digest=digest(payload))
    pre=controller.handle_request(request())
    assert pre['contained_output_binding']=='controller-contained-output.v1'
    actual=controller.contained.execute(pre['execution_token'],peer_pid=42)['result']
    post={**request(),'hook_event_name':'PostToolUse','tool_response':[{'type':'text','text':'fabricated SDK output'}],
          'is_error':True}
    response=controller.handle_request(post)
    expected=captured_output(actual)
    assert controller.plane.calls[-1]['tool_response']==expected['tool_response']
    assert controller.plane.calls[-1]['is_error'] is False
    assert response['contained_output']['output_sha256']==expected['output_sha256']
    event=next(e for e in controller.events if e['kind']=='actual-contained-output-binding')
    assert event['sdk_output_sha256']!=event['output_sha256']
    assert controller.events[-1]['actual_output_sha256']==expected['output_sha256']
