"""Diagnostics distinguish installed bytes, system selection, and UDP health."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.ci import native_loopback_diagnostics as diagnostics
from scripts.ci.native_loopback_dns import REVERSE_NAME, LoopbackPTRResponder, resolver_configuration


def _configuration(*, domain=REVERSE_NAME, address="127.0.0.1", port=53123):
    return f"resolver #1\n  domain : {domain}\n  nameserver[0] : {address}\n  port : {port}\n"


@pytest.mark.parametrize("mutation", [{}, {"domain": "unrelated.private"}, {"address": "192.0.2.1"}, {"port": 1234}])
def test_only_exact_zone_and_loopback_port_are_selected(mutation) -> None:
    raw = _configuration(**mutation) + "resolver #2\n  domain : confidential.internal\n  nameserver[0] : 192.0.2.7\n"
    report = diagnostics.selected_configuration(raw, 53123)
    assert report["exact_resolver_selected"] is (not mutation)
    assert "confidential" not in json.dumps(report) and "192.0.2" not in json.dumps(report)


def test_resolver_dump_is_bounded() -> None:
    assert diagnostics.selected_configuration("x" * (256 * 1024 + 1), 53123)["status"] == "size_limit"


def test_scutil_is_read_only_bounded_and_drops_private_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(argv, **kwargs):
        assert argv == ["/usr/sbin/scutil", "--dns"]
        assert kwargs == {"capture_output": True, "timeout": 5, "check": False}
        raise subprocess.TimeoutExpired(argv, 5, output=b"confidential.internal")

    monkeypatch.setattr(diagnostics.subprocess, "run", run)
    report = diagnostics.system_configuration(53123)
    assert report["status"] == "deadline_exceeded"
    assert "confidential" not in json.dumps(report)


def test_owned_file_readback_requires_complete_original_bytes(tmp_path: Path) -> None:
    path = tmp_path / REVERSE_NAME
    assert diagnostics.owned_configuration(53123, "a" * 32, directory=tmp_path)["status"] == "absent"
    path.write_bytes(resolver_configuration(53123, "a" * 32))
    assert diagnostics.owned_configuration(53123, "a" * 32, directory=tmp_path)["owned_bytes_match"] is True
    path.write_bytes(resolver_configuration(53124, "a" * 32))
    assert diagnostics.owned_configuration(53123, "a" * 32, directory=tmp_path)["owned_bytes_match"] is False
    path.unlink()
    path.symlink_to(tmp_path / "private-unrelated")
    assert diagnostics.owned_configuration(53123, "a" * 32, directory=tmp_path)["owned_bytes_match"] is False


def test_direct_udp_self_probe_reaches_only_the_private_responder() -> None:
    with LoopbackPTRResponder() as responder:
        assert diagnostics.responder_probe(responder.port) == {"passed": True, "status": "completed", "requests": 1}
        assert responder.snapshot()["received"] == 1
