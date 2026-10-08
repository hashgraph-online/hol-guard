"""Check the native Luna route's readiness validation, process lifecycle and CLI guards."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ci.gauntlet import luna_route
from ci.gauntlet.luna_route import ADAPTER_ID, NativeLunaRoute, sdk_root_for, validate_ready

READY = {
    "pid": 1,
    "port": 40123,
    "adapter": ADAPTER_ID,
    "provider": "openai-codex",
    "model": "gpt-5.6-luna",
    "thinking": "medium",
}


def _sdk(tmp_path):
    root = tmp_path / "sdk"
    (root / "node_modules" / "@oh-my-pi" / "pi-agent-core").mkdir(parents=True)
    pinned = json.loads(luna_route.PINNED_PACKAGE.read_text())["dependencies"]["@oh-my-pi/pi-coding-agent"]
    coding = root / "node_modules" / "@oh-my-pi" / "pi-coding-agent"
    coding.mkdir()
    (coding / "package.json").write_text(json.dumps({"version": pinned}))
    (root / "node_modules" / ".bin").mkdir()
    omp = root / "node_modules" / ".bin" / "omp"
    omp.write_text("#!/bin/sh\n")
    return root, omp


def _fake_bun(tmp_path, body):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    bun = bin_dir / "bun"
    bun.write_text("#!/bin/sh\n" + body)
    bun.chmod(0o700)
    return bin_dir


def test_ready_record_must_name_the_expected_backend_and_a_real_port():
    assert validate_ready(json.dumps(READY))["port"] == 40123
    for change in (
        {"model": "gpt-5.6-mini"},
        {"provider": "other"},
        {"thinking": "low"},
        {"thinking": "high"},
        {"adapter": "x"},
        {"port": 0},
        {"port": "40123"},
        {"port": True},
    ):
        with pytest.raises(RuntimeError):
            validate_ready(json.dumps({**READY, **change}))
    assert validate_ready(json.dumps({**READY, "thinking": "high"}), "high")["port"] == 40123
    with pytest.raises(RuntimeError):
        validate_ready(json.dumps(READY), "high")
    for bad in ("", "not json", "[]"):
        with pytest.raises((RuntimeError, AttributeError)):
            validate_ready(bad)


def test_sdk_root_comes_from_the_omp_executable_and_must_hold_the_packages(tmp_path):
    root, omp = _sdk(tmp_path)
    assert sdk_root_for(str(omp)) == root
    with pytest.raises(RuntimeError):
        sdk_root_for(None, tmp_path)


@pytest.mark.parametrize(("requested", "effort"), [({}, "medium"), ({"effort": "high"}, "high")])
def test_route_provider_is_loopback_with_real_identity_and_effort(tmp_path, monkeypatch, requested, effort):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exit 0\n")) + os.pathsep + os.environ["PATH"])
    route = NativeLunaRoute(omp=str(omp), **requested)
    route.port = 40123
    provider = route.provider(max_rounds=32, timeout=120)
    assert provider["base_url"] == "http://127.0.0.1:40123/v1"
    assert provider["allow_loopback"] is True and bool(provider["api_key"])
    assert provider["reasoning_effort"] == effort
    assert f"openai-codex/gpt-5.6-luna/{effort} via" in provider["identity"]


def test_route_rejects_unsupported_effort(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exit 0\n")) + os.pathsep + os.environ["PATH"])
    with pytest.raises(ValueError):
        NativeLunaRoute(omp=str(omp), effort="low")


def test_route_passes_its_effort_to_the_adapter(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    ready = json.dumps({**READY, "thinking": "high"})
    script = f"[ \"$GUARD_GAUNTLET_LUNA_THINKING\" = high ] || exit 4\necho '{ready}'\nexec sleep 300\n"
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, script)) + os.pathsep + os.environ["PATH"])
    with NativeLunaRoute(omp=str(omp), effort="high") as route:
        assert route.port == 40123


def test_route_starts_stops_and_reaps_its_process_group(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    ready = json.dumps(READY)
    monkeypatch.setenv(
        "PATH", str(_fake_bun(tmp_path, f"echo '{ready}'\nexec sleep 300\n")) + os.pathsep + os.environ["PATH"]
    )
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-forwarded")
    with NativeLunaRoute(omp=str(omp)) as route:
        process = route.process
        assert route.port == 40123 and process.poll() is None
    assert process.poll() is not None and route.process is None
    route.stop()


def test_route_fails_closed_when_the_adapter_exits_or_misreports(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exit 3\n")) + os.pathsep + os.environ["PATH"])
    with pytest.raises(RuntimeError):
        NativeLunaRoute(omp=str(omp)).__enter__()


def test_environment_forwards_no_provider_keys():
    names = luna_route._ENVIRONMENT_KEYS + luna_route._WINDOWS_ENVIRONMENT_KEYS
    assert not any("KEY" in name or "TOKEN" in name for name in names)


class _FakeJob:
    def __init__(self):
        self.calls = []

    def terminate(self):
        self.calls.append("terminate")

    def __exit__(self, *_args):
        self.calls.append("close")


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX stand-in process")
def test_job_owned_stop_closes_stdin_terminates_the_job_and_reaps(tmp_path, monkeypatch):
    # The Windows path never signals a process group: it ends the owned job only.
    monkeypatch.setattr(luna_route.os, "killpg", lambda *_a: pytest.fail("killpg must not be used with a job"))
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exec sleep 300\n")) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(luna_route, "STOP_SECONDS", 0.2)
    route = NativeLunaRoute(omp=str(omp))
    route.process = subprocess.Popen(
        ["sleep", "300"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True
    )
    process, job = route.process, _FakeJob()
    route._job = job
    # The stand-in ignores stdin closing, so the job terminate is the escalation.
    job.terminate = lambda: (job.calls.append("terminate"), process.kill())
    route.stop()
    assert job.calls == ["terminate", "close"] and process.poll() is not None
    assert route.process is None and route._job is None
    route.stop()


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX stand-in process")
def test_job_stop_kills_a_process_that_never_joined_the_job(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exec sleep 300\n")) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(luna_route, "STOP_SECONDS", 0.2)
    route = NativeLunaRoute(omp=str(omp))
    route.process = subprocess.Popen(
        ["sleep", "300"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True
    )
    process, job = route.process, _FakeJob()
    route._job = job
    route.stop()
    assert job.calls == ["terminate", "close"] and process.poll() is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object lifecycle")
def test_windows_route_starts_and_stops_in_a_job(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    bun = tmp_path / "bin" / "bun.cmd"
    bun.parent.mkdir()
    bun.write_text(f"@echo {json.dumps(READY)}\r\n@ping -n 300 127.0.0.1 >nul\r\n")
    monkeypatch.setenv("PATH", str(bun.parent) + os.pathsep + os.environ["PATH"])
    with NativeLunaRoute(omp=str(omp)) as route:
        process = route.process
        assert process.poll() is None
    assert process.poll() is not None and route._job is None


def test_cli_rejects_a_conflicting_provider_selection(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ci.gauntlet",
            "run",
            "--expected-source-sha",
            "0" * 40,
            "--output",
            str(tmp_path / "e"),
            "--native-luna-route",
            "--model",
            "other",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parents[1],
        timeout=60,
        check=False,
    )
    assert result.returncode == 2 and "native-luna-route" in result.stderr


def test_cli_rejects_an_unsupported_luna_effort(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ci.gauntlet",
            "run",
            "--expected-source-sha",
            "0" * 40,
            "--output",
            str(tmp_path / "e"),
            "--native-luna-route",
            "--reasoning-effort",
            "low",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parents[1],
        timeout=60,
        check=False,
    )
    assert result.returncode == 2 and "Luna medium or high" in result.stderr


@pytest.mark.skipif(shutil.which("bun") is None, reason="bun is required for the adapter unit tests")
def test_adapter_unit_tests_pass():
    result = subprocess.run(
        ["bun", "test", "ci/gauntlet/luna_adapter.test.ts"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parents[1],
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]


def test_non_object_and_error_readiness_lines_fail_with_runtime_error():
    for line in ("[]", "1", '"x"', "null"):
        with pytest.raises(RuntimeError):
            validate_ready(line)
    with pytest.raises(RuntimeError, match="model unavailable"):
        validate_ready(json.dumps({"error": "model unavailable"}))


def test_sdk_root_must_match_the_pinned_version(tmp_path):
    root, omp = _sdk(tmp_path)
    (root / "node_modules" / "@oh-my-pi" / "pi-coding-agent" / "package.json").write_text('{"version": "0.0.1"}')
    with pytest.raises(RuntimeError, match="pinned"):
        sdk_root_for(str(omp))
    with pytest.raises(RuntimeError, match="pinned"):
        sdk_root_for(None, root)


def test_route_authenticates_the_relay_with_a_per_run_token(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exit 0\n")) + os.pathsep + os.environ["PATH"])
    first, second = NativeLunaRoute(omp=str(omp)), NativeLunaRoute(omp=str(omp))
    assert len(first.provider(max_rounds=1, timeout=1)["api_key"]) >= 32
    assert first.provider(max_rounds=1, timeout=1)["api_key"] != second.provider(max_rounds=1, timeout=1)["api_key"]
    assert first.bun.is_absolute()


def test_sigterm_to_the_runner_stops_the_adapter(tmp_path):
    _root, omp = _sdk(tmp_path)
    ready = json.dumps(READY)
    pidfile = tmp_path / "adapter.pid"
    bin_dir = _fake_bun(tmp_path, f"echo $$ > {pidfile}\necho '{ready}'\nexec sleep 300\n")
    script = tmp_path / "hold.py"
    script.write_text(
        "import signal, sys, time\n"
        "from ci.gauntlet.luna_route import NativeLunaRoute\n"
        "signal.signal(signal.SIGTERM, lambda n, f: sys.exit(143))\n"
        f"with NativeLunaRoute(omp={str(omp)!r}):\n    print('up', flush=True)\n    time.sleep(300)\n"
    )
    environment = {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "PYTHONPATH": str(Path(__file__).parents[1]),
    }
    runner = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True, env=environment)
    try:
        assert runner.stdout.readline().strip() == "up"
        pid = int(pidfile.read_text())
        runner.terminate()
        runner.wait(timeout=20)
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("adapter survived the runner")
    finally:
        runner.kill()
        runner.wait()
