"""Inline analysis receives enforcement, not unrestricted interpreter consent."""

import json
import shlex
import shutil
import sys
from pathlib import Path
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
        ["python3", "-I", "-m", "arbitrary"],
        ["python3", "-S", "file.py"],
        ["python3", "deploy.py"],
        ["python3", "../test_calc.py"],
        ["python3", "/tmp/test_calc.py"],
        ["python3", "-W", "ignore", "test_calc.py"],
        ["python3", "-m", "test_calc"],
        ["python3", "-m", "unittest", "-k", "$NAME"],
        ["python3", "-m", "unittest", "a;b"],
        ["python3", "-W", "ignore", "-c", "print(1)"],
        ["python3", "-I", "-I", "-c", "print(1)"],
        ["python3", "-IS", "-S", "-c", "print(1)"],
        ["node", "-p", "1"],
        ["node", "--require", "preload.js", "-e", "1"],
        ["sh", "-c", "echo ok"],
    ],
)
def test_other_execution_shapes_do_not_inherit_inline_profile(argv, tmp_path):
    with pytest.raises(RestrictedPytestError):
        inline.prepare_restricted_inline_eval(argv, workspace=tmp_path)


def test_node_inline_eval_preserves_bounded_heap_option() -> None:
    assert inline.is_inline_eval(["node", "--max-old-space-size=12288", "-e", "1+1"])
    assert inline.is_inline_eval(["nodejs", "--max-old-space-size=12288", "--eval", "1+1"])
    with pytest.raises(RestrictedPytestError):
        inline.is_inline_eval(["node", "--max-old-space-size=999999", "-e", "1+1"])


@pytest.mark.parametrize("flags", [[], ["-I"], ["-S"], ["-I", "-S"], ["-S", "-I"], ["-IS"], ["-SI"]])
def test_python_inline_eval_accepts_only_bounded_isolation_flags(flags):
    argv = ["python3", *flags, "-c", "print(1)"]
    assert inline.is_inline_eval(argv)
    assert inline._python_runtime_args(argv) == tuple(flags)


@pytest.mark.parametrize(
    "argv",
    [
        ["python3", "test_calc.py"],
        ["python3", "test_calc.py", "-v"],
        ["python3", "-I", "tests/test_parser.py"],
        ["/usr/bin/python3.12", "src/calc_test.py"],
        ["python3", "run_tests.py"],
    ],
)
def test_test_named_python_scripts_share_the_inline_profile(argv):
    assert inline.is_inline_eval(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["python3", "-m", "unittest"],
        ["python3", "-m", "unittest", "-q"],
        ["python", "-I", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        ["/usr/bin/python3.12", "-m", "unittest", "test_calc.CalcTest.test_add", "-v"],
    ],
)
def test_unittest_shares_the_inline_profile(argv):
    assert inline.is_inline_eval(argv)


@pytest.mark.parametrize("target", ["missing", "outside", "directory"])
def test_test_script_must_be_a_workspace_file(tmp_path, target):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "test_outside.py"
    outside.write_text("print(1)\n")
    if target == "outside":
        (workspace / "test_calc.py").symlink_to(outside)
    elif target == "directory":
        (workspace / "test_calc.py").mkdir()
    with pytest.raises(RestrictedPytestError):
        inline.prepare_restricted_inline_eval(["python3", "test_calc.py"], workspace=workspace)


@pytest.mark.parametrize(
    "runtime,flag,profile",
    [
        ("python3", "-c", "python-eval-readonly-v1"),
        ("python3", "-I -S -c", "python-eval-readonly-v1"),
        ("node", "-e", "node-eval-readonly-v1"),
    ],
)
@pytest.mark.parametrize("failure", [None, "original", "resolved", "watch"])
def test_original_and_resolved_eval_need_independent_native_authority(
    monkeypatch, tmp_path, runtime, flag, profile, failure
):
    resolved = f"/usr/bin/{runtime}"
    plan = SimpleNamespace(profile_version=profile, command=(resolved, *shlex.split(flag), "synthetic analysis"))
    prepared = []

    def prepare(*args, **kwargs):
        prepared.append((args, kwargs))
        return plan

    monkeypatch.setattr(sink, "prepare_restricted_inline_eval", prepare)
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

    home = tmp_path / "home"
    payload = {"tool_input": {"command": f"{runtime} {flag} 'synthetic analysis'"}}
    if failure:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                payload, workspace=tmp_path, home_dir=home, authorize=authorize, timeout_seconds=20
            )
        assert not executed
    else:
        assert (
            sink.run_authorized_contained_test(
                payload, workspace=tmp_path, home_dir=home, authorize=authorize, timeout_seconds=20
            )
            == 0
        )
        assert executed == [(plan,)]
        assert calls == [f"{runtime} {flag} 'synthetic analysis'", f"{resolved} {flag} 'synthetic analysis'"]
    assert prepared[0][1]["home_dir"] == home
    assert profile in READ_ONLY_TEST_PROFILES


@pytest.mark.skipif(sys.platform != "darwin", reason="Actual macOS execution boundary")
@pytest.mark.parametrize(
    "runtime,flags",
    [
        ("python3", []),
        ("python3", ["-I", "-S"]),
        ("python3", ["-IS"]),
        ("script", []),
        ("script", ["-I"]),
        ("unittest", []),
        ("node", []),
    ],
)
def test_actual_eval_computes_data_but_cannot_read_credentials_or_mutate_source(tmp_path, runtime, flags, monkeypatch):
    if runtime not in {"script", "unittest"} and shutil.which(runtime) is None:
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
    if runtime in {"python3", "script", "unittest"}:
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
        # uv prepends the development venv to PATH; that venv is outside the
        # isolated fixture workspace and must not become a trusted runtime.
        system_python = next(
            (
                path
                for path in (
                    Path("/opt/homebrew/bin/python3"),
                    Path("/usr/local/bin/python3"),
                    Path("/usr/bin/python3"),
                )
                if path.is_file()
            ),
            None,
        )
        python = str(system_python) if system_python else "python3"
        if runtime == "script":
            (tmp_path / "test_boundary.py").write_text(code)
            argv = [python, *flags, "test_boundary.py"]
        elif runtime == "unittest":
            # Discovery imports the module; one passing case keeps the run green.
            case = "import unittest\nclass Boundary(unittest.TestCase):\n    def test_ok(self):\n        pass\n"
            (tmp_path / "test_boundary.py").write_text(code + case)
            argv = [python, *flags, "-m", "unittest", "-q"]
        else:
            argv = [python, *flags, "-c", code]
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
    assert plan.command[1 : 1 + len(flags)] == tuple(flags)
    assert inline.run_restricted_inline_eval(plan, timeout_seconds=20, authorize_capability=lambda argv: None) == 0
    assert source.read_text() == "original"
    assert (directory / "ordinary.txt").read_text() == "original"
    assert (tmp_path / ".env").read_text() == "synthetic fixture only"
