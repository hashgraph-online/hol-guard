"""Inline analysis receives enforcement, not unrestricted interpreter consent."""

import json
import shutil
import sys
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_inline_eval as inline
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import READ_ONLY_TEST_PROFILES, RestrictedPytestError


@pytest.mark.parametrize(
    "argv",
    [
        ["python3", "file.py"],
        ["python3", "-c", "print(1)", "extra"],
        ["node", "-p", "1"],
        ["node", "--require", "preload.js", "-e", "1"],
        ["sh", "-c", "echo ok"],
    ],
)
def test_other_execution_shapes_do_not_inherit_inline_profile(argv, tmp_path):
    with pytest.raises(RestrictedPytestError):
        inline.prepare_restricted_inline_eval(argv, workspace=tmp_path)


@pytest.mark.parametrize(
    "runtime,flag,profile",
    [
        ("python3", "-c", "python-eval-readonly-v1"),
        ("node", "-e", "node-eval-readonly-v1"),
    ],
)
@pytest.mark.parametrize("failure", [None, "original", "resolved", "watch"])
def test_original_and_resolved_eval_need_independent_native_authority(
    monkeypatch, tmp_path, runtime, flag, profile, failure
):
    resolved = f"/usr/bin/{runtime}"
    plan = SimpleNamespace(profile_version=profile, command=(resolved, flag, "synthetic analysis"))
    monkeypatch.setattr(sink, "prepare_restricted_inline_eval", lambda *args, **kwargs: plan)
    calls, executed = [], []
    monkeypatch.setattr(sink, "run_restricted_inline_eval", lambda *args, **kwargs: executed.append(args) or 0)

    def authorize(payload):
        calls.append(payload["tool_input"]["command"])
        phase = "resolved" if calls[-1].startswith("/") else "original"
        return {
            "decision": "deny",
            "policy_action": "block" if phase == failure else "sandbox-required",
            "reason_code": f"native_{'python' if runtime == 'python3' else 'node'}_eval_readonly_containment_required",
            "required_execution_profile": profile,
            "observe_mode": failure == "watch",
        }

    payload = {"tool_input": {"command": f"{runtime} {flag} 'synthetic analysis'"}}
    if failure:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
        assert not executed
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
            == 0
        )
        assert executed == [(plan,)]
        assert calls == [f"{runtime} {flag} 'synthetic analysis'", f"{resolved} {flag} 'synthetic analysis'"]
    assert profile in READ_ONLY_TEST_PROFILES


@pytest.mark.skipif(sys.platform != "darwin", reason="Actual macOS execution boundary")
@pytest.mark.parametrize("runtime", ["python3", "node"])
def test_actual_eval_computes_data_but_cannot_read_credentials_or_mutate_source(tmp_path, runtime, monkeypatch):
    if shutil.which(runtime) is None:
        pytest.skip(f"{runtime} is unavailable")
    monkeypatch.delenv("PYTHONPATH", raising=False)
    (tmp_path / "pyproject.toml").write_text('[project]\nname="guard-synthetic-eval"\nversion="0.0.0"\n')
    (tmp_path / "data.json").write_text(json.dumps({"values": [1, 2, 3]}))
    (tmp_path / ".env").write_text("synthetic fixture only")
    source = tmp_path / "source.txt"
    source.write_text("original")
    directory = tmp_path / "source-directory"
    directory.mkdir()
    (directory / "ordinary.txt").write_text("original")
    if runtime == "python3":
        code = """import json, pathlib, shutil, socket, subprocess, tempfile
assert sum(json.loads(pathlib.Path("data.json").read_text())["values"]) == 6
with tempfile.TemporaryDirectory() as directory:
    pathlib.Path(directory, "result.txt").write_text("private output")
for action in [lambda: pathlib.Path(".env").read_text(), lambda: pathlib.Path("source.txt").write_text("changed"),
               lambda: pathlib.Path("source.txt").unlink(), lambda: shutil.rmtree("source-directory"),
               lambda: socket.create_connection(("127.0.0.1", 9), timeout=1),
               lambda: subprocess.run(["/bin/sh", "-c", "echo unsafe"], check=True)]:
    try:
        action()
    except (PermissionError, OSError):
        pass
    else:
        raise AssertionError("restricted capability unexpectedly succeeded")
print("guard-python-eval-boundary-verified")
"""
        argv = [runtime, "-c", code]
    else:
        code = """const fs=require('node:fs'), assert=require('node:assert'), cp=require('node:child_process');
assert.equal(JSON.parse(fs.readFileSync('data.json')).values.reduce((a,b)=>a+b),6);
const result=require('node:path').join(require('node:os').tmpdir(),'result.txt');
fs.writeFileSync(result,'private output');
for(const action of [()=>fs.readFileSync('.env'),()=>fs.writeFileSync('source.txt','changed'),
()=>fs.unlinkSync('source.txt'),()=>fs.rmSync('source-directory',{recursive:true}),
()=>cp.execFileSync('/bin/sh',['-c','echo unsafe'])]) assert.throws(action);
console.log('guard-node-eval-boundary-verified');"""
        argv = [runtime, "-e", code]
    plan = inline.prepare_restricted_inline_eval(argv, workspace=tmp_path)
    assert inline.run_restricted_inline_eval(plan, timeout_seconds=20, authorize_capability=lambda argv: None) == 0
    assert source.read_text() == "original"
    assert (directory / "ordinary.txt").read_text() == "original"
    assert (tmp_path / ".env").read_text() == "synthetic fixture only"
