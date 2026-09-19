"""Read-only witnesses retain bounded categories and reap only owned children."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.ci import native_loopback_lookup as lookup


class Responder:
    received = 2
    port = 53535

    def snapshot(self):
        return {"received": self.received}


def test_stack_summary_recognizes_only_allowlisted_call_graph_frames() -> None:
    trace = b"""Process: private-fixture-name
Path: /private/fixture/DNSServiceProcessResult
  999 mach_msg (in header)
Call graph:
    + 999 gethostbyaddr (in libsystem_info.dylib) + 4 [0x1234]
    + ! 998 _mdns_search_ex (in libsystem_info.dylib) + 8 [0x5678]
    + ! : 997 kevent (in libsystem_kernel.dylib) + 12 [0x9abc]
    + ! : 996 private_symbol (in private-fixture-name) + 16
    + ! : 995 DNSServiceProcessResult_suffix (in image) + 20
Total number in stack (recursive counted multiple, when >=5):
  999 mach_msg (in footer)
"""
    report = lookup.stack_summary(trace)
    assert report["categories"] == ["kevent_wait", "libinfo_search", "mdns_query"]
    assert report["recognized_frames"] == 3
    assert report["stack_sha256"] == hashlib.sha256(trace).hexdigest()
    assert report["stack_bytes"] == len(trace)
    assert "private" not in json.dumps(report) and "0x1234" not in json.dumps(report)
    assert lookup.stack_summary(b"100 gethostbyaddr (in private-header)")["recognized_frames"] == 0


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_numeric_control_is_fixed_local_and_reaped() -> None:
    report = lookup.lookup_probe("numeric_control", Responder())
    assert report["status"] == "completed" and report["return_code"] == 0
    assert report["contained"] is True
    assert report["lookup"] == {"status": "completed", "loopback_label": True}
    assert report["responder_packet_delta"] == 0
    assert "native_sample" not in report


@pytest.mark.parametrize(
    ("code", "status", "limit"),
    [("import time; time.sleep(30)", "deadline_exceeded", 64), ("print('x' * 4096, flush=True)", "size_limit", 17)],
)
@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_process_deadline_and_output_limit_reap_child(code: str, status: str, limit: int) -> None:
    timeout = 0.15 if status == "deadline_exceeded" else 2.0
    report, data = lookup._bounded_process([sys.executable, "-I", "-c", code], timeout=timeout, limit=limit)
    assert report["status"] == status and report["contained"] is True
    assert type(report["return_code"]) is int
    assert len(data) <= limit
    assert report["stdout_bytes"] + report["stderr_bytes"] <= limit
    assert report["elapsed_ms"] < 4000


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_sampler_receives_only_owned_unreaped_child_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen
    processes = []
    sample_pids = []
    trace = "Call graph:\n  + 999 kevent (in image) + 4\nprivate-fixture-name"

    def popen(argv, **kwargs):
        assert kwargs["start_new_session"] is True
        if argv[0] == "/usr/bin/sample":
            assert argv == ["/usr/bin/sample", str(processes[0].pid), "1", "10", "-mayDie", "-file", "/dev/stdout"]
            assert processes[0].poll() is None
            os.kill(processes[0].pid, 0)
            sample_pids.append(int(argv[1]))
            argv = [sys.executable, "-I", "-c", "print(" + repr(trace) + ")"]
        process = real_popen(argv, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(lookup.subprocess, "Popen", popen)
    report, _data = lookup._bounded_process(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout=0.6, limit=1024, sample_owned=True
    )
    assert sample_pids == [processes[0].pid]
    assert report["status"] == "deadline_exceeded" and report["contained"] is True
    assert report["native_sample"]["categories"] == ["kevent_wait"]
    assert report["native_sample"]["contained"] is True
    assert all(process.poll() is not None for process in processes)
    assert "private-fixture-name" not in json.dumps(report)


@pytest.mark.parametrize(
    ("child", "expected"),
    [
        (
            {"status": "completed", "loopback_label": False, "raw": "private-answer"},
            {"status": "completed", "loopback_label": False},
        ),
        (
            {"status": "lookup_error", "category": "gaierror", "errno": 8, "raw": "private-answer"},
            {"status": "lookup_error", "category": "gaierror", "errno": 8},
        ),
        ({"status": "completed", "loopback_label": 1}, {"status": "invalid_child_evidence"}),
        ([], {"status": "invalid_child_evidence"}),
        ({}, {"status": "invalid_child_evidence"}),
    ],
)
def test_lookup_keeps_only_safe_child_projection_and_packet_window(
    monkeypatch: pytest.MonkeyPatch, child, expected
) -> None:
    responder = Responder()

    def process(argv, **kwargs):
        assert argv[:3] == [sys.executable, "-I", "-c"]
        assert "socket.gethostbyaddr('127.0.0.1')" in argv[-1]
        assert kwargs == {"timeout": 5.0, "limit": 1024, "sample_owned": True}
        responder.received += 2
        return {"status": "completed", "return_code": 0}, json.dumps(child).encode()

    monkeypatch.setattr(lookup, "_bounded_process", process)
    report = lookup.lookup_probe("gethostbyaddr", responder)
    assert report["lookup"] == expected
    assert report["responder_packet_delta"] == 2
    assert "private-answer" not in json.dumps(report)


def test_witness_uses_only_three_fixed_operations_outside_measurements(monkeypatch: pytest.MonkeyPatch) -> None:
    operations = []
    with pytest.raises(KeyError):
        lookup.lookup_probe("external.example", Responder())

    def probe(operation, responder):
        operations.append(operation)
        return {"operation": operation}

    monkeypatch.setattr(lookup, "lookup_probe", probe)
    monkeypatch.setattr(lookup, "hosts_mapping_witness", lambda: {"status": "fixture"})
    monkeypatch.setattr(lookup, "dns_service_probe", lambda _responder: {"status": "fixture"})
    monkeypatch.setattr(lookup, "_bounded_process", lambda *_args, **_kwargs: ({"status": "fixture"}, b""))
    report = lookup.lookup_witness(Responder())
    assert operations == ["numeric_control", "gethostbyaddr", "getnameinfo"]
    assert report["phase"] == "after_qualification_before_resolver_cleanup"
    assert report["process_deadline_seconds"] == 5
    assert report["fixed_loopback_only"] is True
    assert report["packet_delta_scope"] == "responder_window_including_system_activity"
    assert all(
        report[key] is False for key in ("qualification_outcomes_changed", "qualification_sample", "baseline_modified")
    )
    assert report["probe_order"] == [
        "numeric_control",
        "gethostbyaddr",
        "getnameinfo",
        "hosts_mapping",
        "matched_resolver",
        "dns_service_reverse_ptr",
    ]


def test_dns_service_callback_projection_retains_answers_without_exporting_them() -> None:
    output = b"""DATE: ---private-date---
Timestamp A/R Flags IF Name Type Class Rdata
12:01:01.001 Add 2 0 1.0.0.127.in-addr.arpa. PTR IN localhost.
12:01:01.002 Add 3 0 1.0.0.127.in-addr.arpa PTR IN private-fixture.example.
12:01:01.003 Add 2 0 1.0.0.127.in-addr.arpa. PTR IN 0.0.0.0    No Such Record
12:01:01.004 Rmv 0 0 1.0.0.127.in-addr.arpa. PTR IN private-fixture.example.
12:01:01.005 Add 2 0 private-query.example. PTR IN localhost.
12:01:01.006 Add 2 0 1.0.0.127.in-addr.arpa. A IN 127.0.0.1
"""
    report = lookup.dns_service_summary(output, b"private-stderr")
    assert report["counts"] == {
        "callbacks": 4,
        "positive": 2,
        "negative": 1,
        "removed": 1,
        "unclassified": 0,
        "loopback_label": 1,
    }
    assert report["callback_flags"] == [0, 2, 3]
    assert "private" not in json.dumps(report)
    assert "localhost" not in json.dumps(report)


@pytest.mark.parametrize(
    ("stdout", "stderr", "errors", "unsupported"),
    [
        (b"...STARTING...\n", b"", [], False),
        (b"", b"DNSServiceQueryRecord failed -65563 (Service Not Running)\n", [-65563], False),
        (b"", b"/usr/bin/dns-sd -Q <name> <rrtype> <rrclass> (Generic query)\n", [], True),
        (b"", b"dns-sd: illegal option -- m\n", [], True),
    ],
)
def test_dns_service_distinguishes_no_captured_callback_api_error_and_unsupported(stdout, stderr, errors, unsupported):
    report = lookup.dns_service_summary(stdout, stderr)
    assert report["callback_observation"] == "none_in_captured_output"
    assert report["api_errors"] == errors
    assert report["unsupported_syntax_observed"] is unsupported


def test_dns_service_keeps_callback_even_when_owned_process_times_out(monkeypatch):
    responder = Responder()

    def process(argv, **kwargs):
        assert argv == ["/usr/bin/dns-sd", "-m", "-Q", lookup.REVERSE_NAME, "PTR", "IN"]
        assert kwargs["timeout"] == 5 and kwargs["limit"] == 128 * 1024
        responder.received += 1
        data = b"12:01:01.001 Add 2 0 1.0.0.127.in-addr.arpa. PTR IN localhost.\n"
        return {
            "status": "deadline_exceeded",
            "return_code": -9,
            "contained": True,
            "observation": kwargs["output_observer"](data, b""),
        }, data

    monkeypatch.setattr(lookup, "_bounded_process", process)
    report = lookup.dns_service_probe(responder)
    assert report["status"] == "deadline_exceeded"
    assert report["observation"]["counts"]["positive"] == 1
    assert report["responder_packet_delta"] == 1
    assert report["libc_equivalence_claimed"] is False
    assert "passed" not in report


def test_matched_resolver_retains_only_exact_block_reachability_and_allowlisted_flags():
    data = b"""resolver #1
 domain : private-network.example
 nameserver[0] : 192.0.2.80
 flags : private-flag
 reach : 0x000000ff (private-state)
resolver #2
 domain : 1.0.0.127.in-addr.arpa
 nameserver[0] : 127.0.0.1
 port : 53535
 flags : Supplemental, Request A records, private-flag
 reach : 0x00000002 (Reachable)
resolver #3
 domain : 1.0.0.127.in-addr.arpa
 nameserver[0] : 127.0.0.1
 port : 11111
 reach : 0x000000ff (private-state)
"""
    report = lookup.matched_resolver_summary(data, b"private-stderr", 53535)
    assert report["exact_configuration_match_count"] == 1
    assert report["matched_blocks"] == [
        {
            "reachability_value": 2,
            "reachability_field_count": 1,
            "flags": ["Request A records", "Supplemental"],
            "unknown_flag_count": 1,
        }
    ]
    assert report["actual_query_routing_proven"] is False
    assert "private" not in json.dumps(report)


def test_hosts_projection_counts_exact_tokens_comments_duplicates_and_conflicts():
    content = b"""# 127.0.0.1 localhost
127.0.0.1 localhost private-alias
127.0.0.1 other-label localhost # comment
127.0.0.1 notlocalhost
::1 localhost
0:0:0:0:0:0:0:1 localhost
192.0.2.8 localhost
invalid-address localhost
invalid-record
\xff localhost
"""
    report = lookup.hosts_mapping_summary(content)
    assert report["ipv4_records"] == 3 and report["ipv4_localhost"] == 2
    assert report["ipv6_localhost"] == 1 and report["localhost_conflicts"] == 1
    assert report["duplicate_ipv4_localhost_records"] == 1 and report["malformed"] == 3
    assert "private" not in json.dumps(report) and "192.0.2.8" not in json.dumps(report)


@pytest.mark.skipif(os.name != "posix", reason="held POSIX descriptors")
def test_hosts_read_is_bounded_held_and_refuses_symlink_fifo_and_replacement(tmp_path, monkeypatch):
    monkeypatch.setattr(lookup, "_HOSTS_DIRECTORY", tmp_path)
    path = tmp_path / "hosts"
    content = b"127.0.0.1 localhost\n"
    path.write_bytes(content)
    report = lookup.hosts_mapping_witness()
    assert report["content_sha256"] == hashlib.sha256(content).hexdigest()
    assert report["mapping"]["exact_ipv4_localhost_present"] is True
    assert path.read_bytes() == content
    monkeypatch.setattr(lookup, "_SYSTEM_OUTPUT_BYTES", 4)
    assert lookup.hosts_mapping_witness()["status"] == "size_limit"
    path.unlink()
    path.symlink_to(tmp_path / "absent")
    assert lookup.hosts_mapping_witness()["status"] == "unavailable"
    path.unlink()
    os.mkfifo(path)
    assert lookup.hosts_mapping_witness()["status"] == "not_regular"
    path.unlink()
    path.write_bytes(content)
    monkeypatch.setattr(lookup, "_SYSTEM_OUTPUT_BYTES", 1024)
    original = lookup.os.read

    def read(descriptor, size):
        data = original(descriptor, size)
        if path.exists():
            path.unlink()
            path.write_bytes(content)
        return data

    monkeypatch.setattr(lookup.os, "read", read)
    assert lookup.hosts_mapping_witness()["status"] == "changed_during_read"


@pytest.mark.skipif(os.name != "posix", reason="held POSIX descriptors")
def test_hosts_read_rejects_replaced_canonical_parent(tmp_path, monkeypatch):
    directory = tmp_path / "canonical"
    directory.mkdir()
    content = b"127.0.0.1 localhost\n"
    (directory / "hosts").write_bytes(content)
    monkeypatch.setattr(lookup, "_HOSTS_DIRECTORY", directory)
    original = lookup.os.read
    moved = False

    def read(descriptor, size):
        nonlocal moved
        data = original(descriptor, size)
        if not moved:
            moved = True
            directory.rename(tmp_path / "original")
            directory.mkdir()
            (directory / "hosts").write_bytes(content)
        return data

    monkeypatch.setattr(lookup.os, "read", read)
    assert lookup.hosts_mapping_witness()["status"] == "changed_during_read"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux source witness checks descendant zombie state through proc")
@pytest.mark.parametrize("held_pipes", [False, True])
def test_exited_leader_is_unreaped_until_owned_descendants_are_retired(monkeypatch, held_pipes):
    real_killpg = os.killpg
    observed = []

    def killpg(group, signum):
        terminal = os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert terminal is not None and terminal.si_pid == group
        observed.append(group)
        real_killpg(group, signum)

    monkeypatch.setattr(lookup.os, "killpg", killpg)
    code = (
        "import os,time\nchild=os.fork()\nif child==0:\n"
        + (" os.close(1);os.close(2)\n" if not held_pipes else "")
        + " time.sleep(30)\nelse:\n print(child,flush=True)\n os._exit(7)\n"
    )
    report, data = lookup._bounded_process([sys.executable, "-I", "-c", code], timeout=0.4, limit=1024)
    assert report["status"] == ("deadline_exceeded" if held_pipes else "completed")
    assert report["return_code"] == 7 and report["contained"] is True and len(observed) == 1
    descendant = int(data)
    path = Path(f"/proc/{descendant}/stat")
    for _attempt in range(100):
        try:
            state = path.read_text().split(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            break
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("owned descendant survived process-group retirement")
