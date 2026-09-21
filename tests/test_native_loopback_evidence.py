"""Diagnostic omissions stay observable without changing lookup or containment."""

from __future__ import annotations

import errno
import json
import os
import socket
import struct
import sys

import pytest

from scripts.ci import native_loopback_dns as dns
from scripts.ci import native_loopback_lookup as lookup


def _query(name: str = dns.REVERSE_NAME, kind: int = 12) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return struct.pack("!6H", 313, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", kind, 1)


def test_rejected_packets_have_fixed_private_safe_shape_counters() -> None:
    questions = [_query(kind=6), _query("private-fixture.example", kind=1), b"x" * 513]
    with dns.LoopbackPTRResponder() as responder, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        for query in questions:
            client.sendto(query, ("127.0.0.1", responder.port))
        client.sendto(_query(), ("127.0.0.1", responder.port))
        response, peer = client.recvfrom(513)
        assert peer == ("127.0.0.1", responder.port)
        assert response == dns.ptr_response(_query())
    report = responder.rejection_snapshot()
    assert responder.snapshot() == {"received": 4, "answered": 1, "rejected": 3, "errors": 0}
    assert report["reasons"]["question_type"] == 1
    assert report["reasons"]["question_name"] == 1
    assert report["reasons"]["packet_size"] == 1
    assert report["question_types"]["soa"] == 1
    assert report["question_types"]["a"] == 1
    assert report["question_types"]["unparsed"] == 1
    assert sum(report["reasons"].values()) == sum(report["question_types"].values()) == 3
    assert "private-fixture" not in json.dumps(report)
    assert "127.0.0.1" not in json.dumps(report)
    assert "313" not in json.dumps(report)


@pytest.mark.parametrize(
    ("packet", "reason"),
    [
        (struct.pack("!6H", 9, 0x8000, 1, 0, 0, 0), "header_flags"),
        (struct.pack("!6H", 9, 0x0100, 2, 0, 0, 0), "header_counts"),
        (_query()[:12] + b"\xc0\x0c" + struct.pack("!HH", 12, 1), "question_encoding"),
        (_query()[:-1], "question_encoding"),
        (_query()[:-2] + struct.pack("!H", 3), "question_class"),
        (_query() + b"private-trailing-data", "additional_or_trailing"),
    ],
)
def test_rejection_projection_never_changes_the_answer(packet: bytes, reason: str) -> None:
    assert dns.ptr_response(packet) is None
    category, question_type = dns.rejected_query_shape(packet)
    assert category == reason
    assert question_type in {"unparsed", "ptr"}
    assert "private" not in json.dumps((category, question_type))
    assert dns.ptr_response(packet) is None


def test_unknown_dns_service_rows_are_counted_without_reclassifying_callbacks() -> None:
    output = b"""12:01:01.001 Add 2 -1 1.0.0.127.in-addr.arpa. PTR IN private-fixture.example.
12:01:01.002 Add 2 0 1.0.0.127.in-addr.arpa. PTR CH private-fixture.example.
12:01:01.003 Add 2 -1 private-fixture.example. PTR IN private-fixture.example.
12:01:01.004 Add 2 0 1.0.0.127.in-addr.arpa. PTR IN localhost.
"""
    report = lookup.dns_service_summary(output, b"private-stderr")
    assert report["counts"]["callbacks"] == report["counts"]["positive"] == 1
    assert report["unparsed_fixed_question_rows"] == {
        "rows": 2,
        "negative_interface_prefix": 1,
        "ptr_in_columns": 1,
        "negative_answer_suffix": 0,
    }
    assert "private" not in json.dumps(report)
    assert "localhost" not in json.dumps(report)


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX diagnostic child")
def test_successful_exit_does_not_erase_retirement_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(group: int, _signum: int) -> None:
        terminal = os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert terminal is not None and terminal.si_pid == group
        raise PermissionError(errno.EPERM, "private-retirement-reason")

    monkeypatch.setattr(lookup.os, "killpg", denied)
    report, _ = lookup._bounded_process([sys.executable, "-I", "-c", "print('done')"], timeout=2, limit=128)
    assert report["return_code"] == 0 and report["leader_reaped"] is True
    assert report["status"] == "containment_failed" and report["contained"] is False
    assert report["group_retirement_errno"] == errno.EPERM
    assert report["terminal_observation"] == "observed"
    assert report["terminal_observation_pid_matches"] is True
    assert report["terminal_si_code"] == os.CLD_EXITED and report["terminal_si_status"] == 0
    assert "private" not in json.dumps(report)


@pytest.mark.skipif(os.name != "posix", reason="owned POSIX diagnostic child")
def test_wait_observation_errno_is_separate_from_actual_group_retirement(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*_args: object) -> None:
        raise OSError(errno.EIO, "private-wait-reason")

    monkeypatch.setattr(lookup.os, "waitid", unavailable)
    report, _ = lookup._bounded_process([sys.executable, "-I", "-c", "print('done')"], timeout=2, limit=128)
    assert report["status"] == "unavailable"
    assert report["terminal_observation"] == "not_observed"
    assert report["terminal_wait_errno"] == errno.EIO
    assert report["terminal_observation_pid_matches"] is None
    assert report["terminal_si_code"] is report["terminal_si_status"] is None
    assert report["leader_reaped"] is True and report["contained"] is True
    assert "private" not in json.dumps(report)
