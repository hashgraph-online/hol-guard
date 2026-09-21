"""The private native experiment cannot bypass framing, freshness or failure."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.proxy.framing import (
    ProxyIoLimitError,
    ProxyIoTimeoutError,
    operation_budget,
    remaining_timeout,
)

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("guard_mcp_text_facts_pilot", SCRIPTS / "guard_mcp_text_facts_pilot.py")
assert SPEC and SPEC.loader
pilot_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pilot_module
SPEC.loader.exec_module(pilot_module)


def _fake_helper(tmp_path, monkeypatch, reply):
    executable = tmp_path / "synthetic-helper"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import struct, sys, time\n"
        "while True:\n"
        "    header = sys.stdin.buffer.read(16)\n"
        "    if not header: break\n"
        "    magic, sequence, length = struct.unpack('>4sQI', header)\n"
        "    text = sys.stdin.buffer.read(length)\n" + "\n".join("    " + line for line in reply.splitlines()) + "\n"
    )
    executable.chmod(0o700)
    original_identity = pilot_module.executable_identity

    def identity(path):
        # Fault fixtures are scripts. Only this test shim treats their
        # interpreter identity as the requested program's identity.
        return original_identity(executable if str(path).startswith("/proc/") else path)

    monkeypatch.setattr(pilot_module, "executable_identity", identity)
    return pilot_module.TextFactsPilot(executable, minimum_characters=0)


def _artifact():
    return calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="echo_0",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        tool_schema={"type": "object", "properties": {"text": {"type": "string"}}},
        tool_description="Echo text.",
    )


def test_declared_small_unsupported_and_oversize_selections_do_not_spawn(tmp_path, monkeypatch):
    pilot = pilot_module.TextFactsPilot(tmp_path / "absent")
    assert pilot.classify("small") is None
    pilot.minimum_characters = 0
    assert pilot.classify("\ud800") is None
    monkeypatch.setattr(pilot_module, "MAX_PACKET_BYTES", 64)
    assert pilot.classify("€" * 17) is None
    assert pilot.classify("x" * 49) is None
    assert pilot.process is None
    assert pilot.counters["native_attempts"] == 0
    assert pilot.counters["python_small_text"] == 1
    assert pilot.counters["python_unsupported_utf8"] == 1
    assert pilot.counters["python_packet_bound"] == 2


def test_exact_complete_reply_and_packet_accounting(tmp_path, monkeypatch):
    pilot = _fake_helper(
        tmp_path,
        monkeypatch,
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence, 15))\nsys.stdout.flush()",
    )
    try:
        assert pilot.classify("curl .env sudo subprocess") == 15
        assert pilot.classify("€") == 15
        assert pilot.counters["starts"] == 1
        assert pilot.counters["native_completed"] == 2
        assert pilot.counters["response_bytes_read"] == 26
        assert pilot.counters["request_bytes_written"] == 32 + len(b"curl .env sudo subprocess") + 3
        assert pilot.max_helper_rss_bytes > 0
    finally:
        pilot.close()
    assert pilot.counters["reaped"] == 1


@pytest.mark.parametrize(
    "reply",
    [
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'BAD1', sequence, 0))\nsys.stdout.flush()",
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence + 1, 0))\nsys.stdout.flush()",
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence, 16))\nsys.stdout.flush()",
        "sys.stdout.buffer.write(b'MFR1')\nsys.stdout.flush()\nraise SystemExit(0)",
        "raise SystemExit(1)",
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence, 0) + b'extra')\nsys.stdout.flush()",
    ],
)
def test_failed_selected_helper_is_reaped_and_never_becomes_python_fallback(tmp_path, monkeypatch, reply):
    pilot = _fake_helper(tmp_path, monkeypatch, reply)
    with pytest.raises(ProxyIoLimitError):
        pilot.classify("private synthetic text")
    assert pilot.closed and pilot.process is None
    assert pilot.counters["native_failures"] == 1
    assert pilot.counters["reaped"] == 1
    pilot.minimum_characters = 1024
    with pytest.raises(ProxyIoLimitError, match="stream_retired"):
        pilot.classify("small")
    assert pilot.counters["python_small_text"] == 0
    assert "private synthetic text" not in json.dumps(pilot.evidence())


def test_trickled_reply_cannot_extend_the_original_operation_deadline(tmp_path, monkeypatch):
    pilot = _fake_helper(
        tmp_path,
        monkeypatch,
        "for value in struct.pack('>4sQB', b'MFR1', sequence, 0):\n"
        "    sys.stdout.buffer.write(bytes([value]))\n"
        "    sys.stdout.flush()\n"
        "    time.sleep(0.05)",
    )
    started = time.monotonic()
    with operation_budget(0.25, source="outer-test"):
        time.sleep(0.1)
        with pytest.raises(ProxyIoTimeoutError):
            pilot.classify("text")
    assert time.monotonic() - started < 2.0
    assert pilot.counters["response_bytes_read"] < 13
    assert pilot.counters["reaped"] == 1


def test_concurrent_callers_admit_only_one_packet_and_keep_response_identity(tmp_path, monkeypatch):
    pilot = _fake_helper(
        tmp_path,
        monkeypatch,
        "time.sleep(0.03)\n"
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence, int(text)))\n"
        "sys.stdout.flush()",
    )
    outcomes = {}

    def run(value):
        outcomes[value] = pilot.classify(str(value))

    threads = [threading.Thread(target=run, args=(value,)) for value in range(1, 5)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert all(not thread.is_alive() for thread in threads)
        assert outcomes == {value: value for value in range(1, 5)}
        assert pilot.counters["native_completed"] == 4
        assert pilot.sequence == 4
        assert pilot.evidence()["inflight_packet_limit"] == 1
    finally:
        pilot.close()


def test_rss_diagnostics_cannot_return_success_after_the_operation_deadline(tmp_path, monkeypatch):
    import psutil

    pilot = _fake_helper(
        tmp_path,
        monkeypatch,
        "sys.stdout.buffer.write(struct.pack('>4sQB', b'MFR1', sequence, 0))\nsys.stdout.flush()",
    )
    original_process = psutil.Process
    sampled = []

    class SlowProcess:
        def __init__(self, pid):
            self.original = original_process(pid)

        def memory_info(self):
            result = self.original.memory_info()
            sampled.append(True)
            time.sleep(remaining_timeout(1.0, source="slow-sampling-test") + 0.02)
            return result

    monkeypatch.setattr(psutil, "Process", SlowProcess)
    with operation_budget(1.0, source="outer-test"), pytest.raises(ProxyIoTimeoutError):
        pilot.classify("text")
    assert sampled == [True]
    assert pilot.counters["native_completed"] == 0
    assert pilot.counters["native_failures"] == 1
    assert pilot.counters["reaped"] == 1


def test_adapter_matches_all_four_source_groups_once_per_owned_analysis(monkeypatch):
    seen_groups = set()
    original_matches = calls._matches_any

    def observe(value, patterns):
        expressions = tuple(pattern.expression if hasattr(pattern, "expression") else pattern for pattern in patterns)
        seen_groups.add(expressions)
        return original_matches(value, patterns)

    monkeypatch.setattr(calls, "_matches_any", observe)
    artifact = _artifact()
    arguments = {"text": "ordinary"}
    expected = calls.tool_call_risk_categories(artifact, arguments)
    assert set(pilot_module.pattern_groups()) <= seen_groups

    class ExactPythonOracle:
        invocations = 0

        def classify(self, text):
            self.invocations += 1
            return sum(
                flag
                for patterns, flag in pilot_module.pattern_groups().items()
                if any(re.search(p, text) for p in patterns)
            )

        def close(self):
            pass

    oracle = ExactPythonOracle()
    restore = pilot_module.install_adapter(calls, oracle)
    try:
        assert calls.tool_call_risk_categories(artifact, arguments) == expected
        assert oracle.invocations == 1
        arguments["text"] = "subprocess https://example.invalid .env sudo"
        assert set(calls.tool_call_risk_categories(artifact, arguments)) >= {
            "command_execution",
            "outbound_network",
            "secret_access",
            "privileged_system_mutation",
        }
        assert oracle.invocations == 2
    finally:
        restore()


def test_real_native_bits_match_frozen_python_regexes():
    path = os.environ.get("GUARD_MCP_TEXT_PILOT")
    if not path:
        pytest.skip("explicit compiled pilot required; no installed/native claim")
    pilot = pilot_module.TextFactsPilot(Path(path), minimum_characters=0)
    groups = pilot_module.pattern_groups()
    tokens = (
        "subprocess",
        "spawn",
        "execfile",
        "system",
        "http://",
        "https://",
        "curl",
        "requests",
        "socket",
        "dns",
        "getaddrinfo",
        "sendto",
        "urllib.request",
        "http.client",
        "proxy",
        "port-forward",
        ".env",
        ".ssh",
        "id_rsa",
        "token",
        ".npmrc",
        "sudo",
        "systemctl",
    )
    probes = ["", "€", "éÉ Σσ ıİ", "subprocess curl .env sudo"]
    for token in tokens:
        for prefix in ("", "_", "a", "\u03b1", "-", " "):
            for suffix in ("", "_", "1", "β", ".", "(", "\x1c(", "\u2003("):
                probes.append(prefix + token + suffix)
    try:
        for text in probes:
            expected = sum(flag for patterns, flag in groups.items() if any(re.search(p, text) for p in patterns))
            assert pilot.classify(text) == expected
        assert pilot.counters["native_completed"] == len(probes)
        assert pilot.counters["python_small_text"] == 0
    finally:
        pilot.close()


def _profile_module():
    spec = importlib.util.spec_from_file_location("native_mcp_pipe_profile", SCRIPTS / "profile_guard_mcp_session.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_proxy_native_failure_never_forwards_a_tool_call():
    false = Path("/bin/false")
    if os.name != "posix" or not false.is_file():
        pytest.skip("POSIX process-failure fixture required")
    profile = _profile_module()
    with pytest.raises(profile.BenchmarkCaseError) as captured:
        profile.run_case(catalog_size=10, samples=1, native_text_helper=false, native_minimum_characters=0)
    evidence = captured.value.evidence
    assert evidence["attempted_tool_requests"] == 1
    assert evidence["accepted"] == 0
    assert evidence["observed_child_forwarded_count"] == 0
    assert evidence["native_text_pilot"]["counters"]["native_failures"] == 1
    assert evidence["native_text_pilot"]["counters"]["reaped"] == 1


@pytest.mark.parametrize("approval", ["none", "accept", "cancel", "invalidate"])
def test_real_proxy_native_facts_preserve_refresh_approval_and_final_barrier(approval):
    path = os.environ.get("GUARD_MCP_TEXT_PILOT")
    if not path:
        pytest.skip("explicit compiled pilot required; no native route claim")
    profile = _profile_module()
    result = profile.run_case(
        catalog_size=10,
        payload_bytes=1024,
        samples=1,
        profile=True,
        approval=approval,
        refresh_every=1 if approval == "none" else 0,
        native_text_helper=Path(path),
        native_minimum_characters=0,
    )
    counts = result["native_text_pilot"]["counters"]
    assert counts["native_completed"] >= 2
    assert counts.get("native_failures", 0) == 0
    assert result["correctness"]["forwarded_ids_exact"] is True
    assert result["correctness"]["quiet_barrier_seconds"] == 0.005
    if approval in {"cancel", "invalidate"}:
        assert result["correctness"]["accepted"] == 0
    else:
        assert result["correctness"]["accepted"] == 2
        assert result["exclusive_phases"]["prewrite_quiet_barrier"]["calls"] == 1
    if approval == "invalidate":
        assert result["correctness"]["invalidated"] == 2
    assert (
        result["native_text_pilot"]["requested_executable"]["sha256"]
        == (result["native_text_pilot"]["executed_executable"]["sha256"])
    )
