"""The hook path carries no third-party network client, model SDK or background assessment code.

Hooks answer from local state. Loading the daemon hook worker and the adapters
it resolves on start must not pull in a third-party HTTP client or model SDK,
and must not load the background workspace assessment worker, whose scheduling
happens in the daemon, never in a hook. The standard library HTTP client is
allowed here because the daemon client speaks HTTP over loopback; that it never
leaves the host is checked at runtime by ``outbound_network_attempts``, which
the benign gate wraps around every review.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys

import pytest

from tests.outbound_network_guard import outbound_network_attempts

_FORBIDDEN = (
    "aiohttp",
    "anthropic",
    "httpx",
    "openai",
    "requests",
    "urllib3",
    "codex_plugin_scanner.guard.runtime.runner",
    "codex_plugin_scanner.guard.workspace_assessment_admissions",
    "codex_plugin_scanner.guard.workspace_assessment_runner",
    "codex_plugin_scanner.guard.workspace_assessment_worker",
)

# Constructing the worker resolves every adapter module, so the probe does that
# too and the check covers what a running daemon has loaded.
_PROBE = """
import json, sys
import codex_plugin_scanner.guard.daemon.hook_worker
from codex_plugin_scanner.guard.adapters import list_adapters
list_adapters()
print(json.dumps(sorted(sys.modules)))
"""


def _forbidden(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in _FORBIDDEN)


def test_loading_the_hook_worker_and_its_adapters_loads_no_network_client_or_assessment_worker() -> None:
    # A fresh interpreter, so modules other tests imported do not count.
    completed = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True, timeout=120)
    loaded = set(json.loads(completed.stdout))
    assert "codex_plugin_scanner.guard.daemon.hook_worker" in loaded
    reached = sorted(name for name in loaded if _forbidden(name))
    assert not reached, f"the hook path loads network or background assessment code: {reached}"


def test_the_outbound_guard_refuses_remote_hosts_and_allows_loopback() -> None:
    with outbound_network_attempts() as attempts:
        with pytest.raises(ConnectionRefusedError):
            socket.getaddrinfo("example.com", 443)
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(ConnectionRefusedError):
                remote.connect(("93.184.216.34", 443))
        finally:
            remote.close()
        datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(ConnectionRefusedError):
                datagram.sendto(b"x", ("93.184.216.34", 53))
            with pytest.raises(ConnectionRefusedError):
                datagram.sendto(b"x", 0, ("93.184.216.34", 53))
            if hasattr(datagram, "sendmsg"):
                with pytest.raises(ConnectionRefusedError):
                    datagram.sendmsg([b"x"], [], 0, ("93.184.216.34", 53))
            datagram.sendto(b"x", ("127.0.0.1", 9))
        finally:
            datagram.close()
        socket.getaddrinfo("127.0.0.1", 0)
    sends = 3 if hasattr(socket.socket, "sendmsg") else 2
    assert attempts == ["resolve example.com", "connect 93.184.216.34:443"] + ["send 93.184.216.34:53"] * sends
