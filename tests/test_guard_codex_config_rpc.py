from __future__ import annotations

import json
import logging
import sys
import time

import pytest

from codex_plugin_scanner.guard.runtime.codex_config_rpc import CodexConfigRpc, _check_json_depth


@pytest.fixture
def fake_host(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def create(mode="normal"):
        script = """import json, signal, sys, time
from pathlib import Path
mode = MODE
for line in sys.stdin:
    message = json.loads(line)
    with Path("requests.jsonl").open("a") as log:
        log.write(json.dumps(message) + "\\n")
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        print(json.dumps({"id": message["id"], "result": {"userAgent": "fixture"}}), flush=True)
        if mode == "blocked_input":
            time.sleep(60)
        continue
    if mode == "exit":
        print("private configuration must never be logged", file=sys.stderr, flush=True)
        sys.exit(7)
    elif mode == "timeout":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
    elif mode == "oversized":
        sys.stdout.write("x" * 1048577 + "\\n")
        sys.stdout.flush()
    elif mode == "duplicate":
        print('{"id":2,"result":{},"result":{"private":"never expose"}}', flush=True)
    elif mode == "wrong_id":
        print(json.dumps({"id": True, "result": {}}), flush=True)
    elif mode == "nonfinite":
        print('{"id":2,"result":{"version":NaN}}', flush=True)
    elif mode == "deep":
        print('{"id":2,"result":{"nested":' + '[' * 2000 + '0' + ']' * 2000 + '}}', flush=True)
    elif mode == "bad_error_code":
        print(json.dumps({"id": message["id"], "error": {"data": {"code": {"private": "never expose"}}}}), flush=True)
    elif mode == "conflict":
        print(json.dumps({"id": message["id"], "error": {"code": -32000,
            "data": {"configWriteErrorCode": "configVersionConflict"},
            "message": "private configuration must not be exposed"}}), flush=True)
    else:
        print(json.dumps({"id": message["id"], "result": {"accepted": True}}), flush=True)
""".replace("MODE", repr(mode))
        (tmp_path / "app-server").write_text(script)
        return CodexConfigRpc(sys.executable, timeout=0.5)

    return create


def test_rpc_only_initializes_and_uses_allowed_configuration_operations(fake_host, tmp_path):
    rpc = fake_host()
    with rpc:
        assert rpc.request("config/read", {"includeLayers": True}) == {"accepted": True}
        with pytest.raises(ValueError, match="unsupported_codex_config_operation"):
            rpc.request("turn/start", {})
        with pytest.raises(ValueError, match="codex_config_version_required"):
            rpc.request("config/batchWrite", {"edits": []})
        assert rpc.request("config/batchWrite", {"expectedVersion": "version-1", "edits": []}) == {"accepted": True}
    methods = [json.loads(line)["method"] for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert methods == ["initialize", "initialized", "config/read", "config/batchWrite"]
    assert rpc._process is not None and rpc._process.poll() is not None


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("oversized", "codex_config_rpc_limit"),
        ("duplicate", "codex_config_rpc_invalid"),
        ("wrong_id", "codex_config_rpc_invalid"),
        ("nonfinite", "codex_config_rpc_invalid"),
        ("deep", "codex_config_rpc_invalid"),
        ("bad_error_code", "codex_config_rpc_rejected"),
        ("conflict", "codex_config_changed"),
    ],
)
def test_invalid_or_conflicting_responses_fail_without_exposing_payloads(fake_host, mode, reason):
    rpc = fake_host(mode)
    with pytest.raises(ValueError, match=reason) as caught, rpc:
        rpc.request("config/read", {"includeLayers": True})
    assert "private" not in str(caught.value)
    assert rpc._process is not None and rpc._process.poll() is not None


def test_stalled_response_terminates_only_the_task_owned_host(fake_host):
    rpc = fake_host("timeout")
    started = time.monotonic()
    with pytest.raises(ValueError, match="codex_config_rpc_timeout"), rpc:
        rpc.request("config/read", {"includeLayers": True})
    assert time.monotonic() - started < 5
    assert rpc._process is not None and rpc._process.poll() is not None


def test_process_exit_records_only_generic_debug_diagnostics(fake_host, caplog):
    rpc = fake_host("exit")
    with (
        caplog.at_level(logging.DEBUG, logger="codex_plugin_scanner.guard.runtime.codex_config_rpc"),
        pytest.raises(ValueError, match="codex_config_rpc_unavailable"),
        rpc,
    ):
        rpc.request("config/read", {"includeLayers": True})
    assert "Codex app-server exited with code 7" in caplog.text
    assert "private configuration" not in caplog.text
    assert rpc._process is not None and rpc._process.poll() == 7


def test_stalled_input_pipe_cannot_bypass_timeout_or_prevent_cleanup(fake_host):
    rpc = fake_host("blocked_input")
    started = time.monotonic()
    with pytest.raises(ValueError, match="codex_config_rpc_timeout"), rpc:
        rpc.request("config/batchWrite", {"expectedVersion": "1", "fixture": "x" * 200000})
    assert time.monotonic() - started < 5
    assert rpc._process is not None and rpc._process.poll() is not None


def test_invalid_version_values_are_rejected_before_any_write(fake_host, tmp_path):
    with fake_host() as rpc:
        for version in (None, True, 1, {}, [], "", "x" * 257):
            with pytest.raises(ValueError, match="codex_config_version_required"):
                rpc.request("config/batchWrite", {"expectedVersion": version, "edits": []})
    methods = [json.loads(line)["method"] for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert "config/batchWrite" not in methods


def test_depth_limit_ignores_brackets_and_escaped_quotes_inside_strings():
    payload = json.dumps({"description": "[" * 1000 + '\\"' + "}" * 1000}).encode()
    _check_json_depth(payload)
    _check_json_depth(b"[" * 64 + b"0" + b"]" * 64)
    with pytest.raises(ValueError, match="codex_config_rpc_invalid"):
        _check_json_depth(b"[" * 65 + b"0" + b"]" * 65)
