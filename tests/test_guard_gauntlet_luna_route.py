"""Check the native Luna route's readiness validation, process lifecycle and CLI guards."""

import json
import os
import shutil
import subprocess
import sys
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
    "thinking": "high",
}


def _sdk(tmp_path):
    root = tmp_path / "sdk"
    (root / "node_modules" / "@oh-my-pi" / "pi-agent-core").mkdir(parents=True)
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
        {"adapter": "x"},
        {"port": 0},
        {"port": "40123"},
        {"port": True},
    ):
        with pytest.raises(RuntimeError):
            validate_ready(json.dumps({**READY, **change}))
    for bad in ("", "not json", "[]"):
        with pytest.raises((RuntimeError, AttributeError)):
            validate_ready(bad)


def test_sdk_root_comes_from_the_omp_executable_and_must_hold_the_packages(tmp_path):
    root, omp = _sdk(tmp_path)
    assert sdk_root_for(str(omp)) == root
    with pytest.raises(RuntimeError):
        sdk_root_for(None, tmp_path)


def test_route_provider_is_loopback_high_with_real_identity(tmp_path, monkeypatch):
    _root, omp = _sdk(tmp_path)
    monkeypatch.setenv("PATH", str(_fake_bun(tmp_path, "exit 0\n")) + os.pathsep + os.environ["PATH"])
    route = NativeLunaRoute(omp=str(omp))
    route.port = 40123
    provider = route.provider(max_rounds=32, timeout=120)
    assert provider["base_url"] == "http://127.0.0.1:40123/v1"
    assert provider["allow_loopback"] is True and provider["api_key"] is None
    assert provider["reasoning_effort"] == "high"
    assert "openai-codex/gpt-5.6-luna/high" in provider["identity"]


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
    assert not any("KEY" in name or "TOKEN" in name for name in luna_route._ENVIRONMENT_KEYS)


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
