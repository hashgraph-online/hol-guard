"""Controller invariants; mocked native output is not containment proof."""
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import native_builtin_plane, native_contained_plane
from ci.gauntlet.benchmark.contained_hook_router import ContainedHookRouter
from ci.gauntlet.benchmark.contained_request_file import contained_request_file
from ci.gauntlet.benchmark.contracts import digest
from ci.gauntlet.benchmark.normal_hook_invoker import NormalHookInvoker
from tests.test_guard_workflow_benchmark_builtin_hook import request, supervisor


class Sink:
    supports_contained_execution = True

    def __init__(self):
        self.calls = []

    def execute_contained(self, payload, **kwargs):
        self.calls.append(deepcopy(payload))
        return {"exit_code": 17, "stdout": "actual-output", "stderr": "actual-error"}


def receipt():
    return {"decision": "deny", "policy_action": "sandbox-required",
            "required_execution_profile": "workspace-contained-v1"}


def payload():
    return {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "npm test"}}


def test_ticket_freezes_snapshot_and_real_exit_output_is_preserved_once_under_race():
    sink, original = Sink(), payload()
    router = ContainedHookRouter(sink)
    token = router.prepare(original, receipt(), request_digest="frozen-request")
    original["tool_input"]["command"] = "changed-after-authorization"

    def invoke(_):
        try:
            return router.execute(token, peer_pid=101)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = list(executor.map(invoke, range(2)))
    accepted = next(value for value in outputs if value is not None)
    assert sum(value is not None for value in outputs) == 1
    assert sink.calls == [payload()]
    assert accepted["result"] == {"exit_code": 17, "stdout": "actual-output", "stderr": "actual-error"}
    assert accepted["request_digest"] == "frozen-request"
    assert all("token" not in event for event in router.events)


@pytest.mark.parametrize("change", [{"decision": "allow"}, {"observe_mode": True},
                                   {"policy_action": "review"}, {"required_execution_profile": None},
                                   {"required_execution_profile": ""},
                                   {"required_execution_profile": "unknown-contained-v99"}])
def test_no_sink_for_native_allow_review_or_unsupported_receipt(change):
    sink = Sink()
    assert ContainedHookRouter(sink).prepare(payload(), {**receipt(), **change}, request_digest="d") is None
    assert sink.calls == []


def test_failed_sink_consumes_ticket_without_retrying_effect():
    sink = Sink()
    def fail(*args, **kwargs):
        raise RuntimeError("actual native refusal/error")
    sink.execute_contained = fail
    router = ContainedHookRouter(sink, max_executions=1)
    token = router.prepare(payload(), receipt(), request_digest="d")
    with pytest.raises(RuntimeError):
        router.execute(token, peer_pid=10)
    with pytest.raises(ValueError, match="consumed"):
        router.execute(token, peer_pid=10)
    with pytest.raises(ValueError, match="budget"):
        router.prepare(payload(), receipt(), request_digest="d")


def test_post_hook_separate_from_tool_budget_requires_original_snapshot_and_rejects_replay(tmp_path, monkeypatch):
    controller = supervisor(tmp_path, monkeypatch, {"decision": "allow"})
    pre = request()
    controller.handle_request(pre)
    post = {**pre, "hook_event_name": "PostToolUse", "tool_response": [{"type":"text","text":"actual"}],
            "is_error": False}
    changed = deepcopy(post)
    changed["tool_input"]["command"] = "different"
    with pytest.raises(ValueError, match="original"):
        controller.handle_request(changed)
    response = controller.handle_request(post)
    assert response["product_response"] == {"decision": "allow"}
    assert controller.call_count == 1 and len(controller.plane.calls) == 2
    assert controller.plane.calls[-1]["tool_response"] == post["tool_response"]
    with pytest.raises(ValueError, match="replayed"):
        controller.handle_request(post)


def test_request_cleanup_never_traverses_product_replacement_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
    home, outside = tmp_path / "home", tmp_path / "outside"
    home.mkdir()
    outside.mkdir()
    protected = outside / "request.json"
    protected.write_text("controller-canary")
    errors = []
    with contained_request_file(home, b"native-request", cleanup_errors=errors, owner=os.getuid()) as name:
        original = home / name
        assert original.stat().st_mode & 0o777 == 0o700
        assert (original / "request.json").stat().st_mode & 0o777 == 0o600
        original.rename(home / "moved")
        original.symlink_to(outside, target_is_directory=True)
    assert protected.read_text() == "controller-canary"
    assert not (home / "moved" / "request.json").exists()
    assert len(errors) == 1 and "custody changed" in errors[0]


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux private-cell retired-directory inode contract')
def test_request_cleanup_accepts_native_removal_of_consumed_request(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
    errors = []
    with contained_request_file(tmp_path, b"native-request", cleanup_errors=errors, owner=os.getuid()) as name:
        original = tmp_path / name
        (original / "request.json").unlink()
        original.rmdir()  # The installed release retires its validated request.
    assert errors == [] and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('replace_name', [False, True])
def test_request_cleanup_cannot_mistake_removed_name_for_retired_inode(tmp_path, monkeypatch, replace_name):
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
    errors = []
    with contained_request_file(tmp_path, b"native-request", cleanup_errors=errors, owner=os.getuid()) as name:
        original = tmp_path / name
        original.rename(tmp_path / 'moved')
        if replace_name:
            original.mkdir()
            (original / 'request.json').write_text('replacement must survive')
    assert len(errors) == 1 and 'custody changed' in errors[0]
    assert not (tmp_path / 'moved' / 'request.json').exists()
    if replace_name:
        assert (original / 'request.json').read_text() == 'replacement must survive'


def test_request_preparation_failure_closes_resources_and_cleans_only_created_scope(tmp_path, monkeypatch):
    errors = []
    def fail(*args):
        raise OSError("ownership handoff failed")
    monkeypatch.setattr(os, "fchown", fail)
    with pytest.raises(OSError, match="handoff"), contained_request_file(tmp_path, b"x", cleanup_errors=errors):
        pytest.fail("must not invoke native after failed preparation")
    assert list(tmp_path.iterdir()) == [] and errors == []


def test_normal_prompt_helper_uses_inside_plane_cli_and_preserves_actual_denial(monkeypatch):
    class Plane:
        started = True
        python = Path("/root-installed/.venv/bin/python")
        _lock = threading.RLock()
    plane = Plane()
    seen = []
    def invoke(self, command, raw, packet, timeout):
        seen.append((command, raw, packet))
        self.hook_observations.append({"returncode": 2, "response": {"decision":"deny"}})
        return {"decision":"deny","reason":"actual cold review"}
    monkeypatch.setattr(native_builtin_plane.NativeBuiltinHookPlane, "_invoke", invoke)
    invoker = NormalHookInvoker(plane, controller_session_id="root-bound")
    assert invoker.prepare_user_prompt("Public task") == {"decision":"deny","reason":"actual cold review"}
    command, raw, packet = seen[0]
    assert b'"Public task"' in raw
    assert command[:4] == [str(plane.python), "-I", "-m", "codex_plugin_scanner.cli"]
    assert command[-4:] == ["--home", "/product/home", "--workspace", "/product/home/project"]
    assert packet["session_id"] == "root-bound" and packet["prompt"] == "Public task"
    assert invoker.observation()["public_prompt_digest"] == digest("Public task")
    assert invoker.observation()["hooks"][0]["returncode"] == 2
    assert not hasattr(plane, "hook_observations")
    with pytest.raises(ValueError, match="once"):
        invoker.prepare_user_prompt("Changed task")


def test_executor_profile_exact_idmap_does_not_change_readonly_prefix_or_share_controller_files(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *args: None)
    plane = native_contained_plane.NativeContainedHookPlane.__new__(native_contained_plane.NativeContainedHookPlane)
    plane.root, plane.python = tmp_path, Path("/installed/.venv/bin/python")
    plane.home_path, plane.workspace_path = "/runtime/home", "/runtime/home/project"
    plane.workspace_source = Path("/owned/task/checkouts/main")
    plane.provider_mounts = (Path("/owned/task/remotes/main.git"),)
    mounts = plane._profile_mounts(tmp_path / "public")
    assert len(mounts) == 7
    assert all(row["mode"] == "ro" for row in mounts[:2])
    mapped = [row for row in mounts if "idmap" in row]
    assert [row["source"] for row in mapped] == [str(plane.workspace_source), str(plane.provider_mounts[0])]
    assert all(row["idmap"] == "uids=10001-10004-1;gids=10001-10004-1" for row in mapped)
    assert not any("controller.sqlite" in row["source"] or "oracle" in row["source"] for row in mounts)


def test_normal_contained_sink_receives_exact_frozen_native_request(tmp_path, monkeypatch):
    import hashlib
    import json
    monkeypatch.setattr(os, "fchown", lambda *args: None)
    plane = native_contained_plane.NativeContainedHookPlane.__new__(native_contained_plane.NativeContainedHookPlane)
    plane.root, plane.python = tmp_path, Path("/installed/.venv/bin/python")
    plane.home_path, plane.workspace_path = "/runtime/home", "/runtime/home/project"
    plane.started, plane.backend_observation = True, {"sha256":"a"*64}
    plane.executions, plane.execution_observation_bytes = [], 0
    plane.cleanup_errors, plane._lock = [], threading.RLock()
    (tmp_path / "home").mkdir()
    seen = []
    def sink(command, actual, sha, timeout, cancelled):
        files = list((tmp_path / "home").glob("*/request.json"))
        assert len(files) == 1
        raw = files[0].read_bytes()
        assert hashlib.sha256(raw).hexdigest() == sha
        assert json.loads(raw) == {"schema":"guard-contained-test-request.v1",
                                  "workspace":plane.workspace_path,"payload":payload()}
        seen.append(command)
        return {"exit_code":23,"stdout":"normal-sink-result","stderr":"native-negative"}
    monkeypatch.setattr(plane, "_execute", sink)
    result = plane.execute_contained(payload(), timeout=120)
    assert result["exit_code"] == 23 and result["stderr"] == "native-negative"
    assert seen[0][:6] == [str(plane.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "execute-contained-test"]
    assert seen[0][-2:] == ["--timeout-seconds","120"]
    assert list((tmp_path / "home").iterdir()) == [] and plane.cleanup_errors == []
