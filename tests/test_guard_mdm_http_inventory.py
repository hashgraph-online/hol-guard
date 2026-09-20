from __future__ import annotations

from pathlib import Path

from tests.http_client_inventory_support import HttpClientInventory

ROOT = Path(__file__).parents[1]
GUARD_SOURCE = ROOT / "src" / "codex_plugin_scanner" / "guard"

_RAW_HTTP_CALLS = frozenset(
    {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "requests.Session",
        "urllib.request.urlopen",
        "urllib.request.build_opener",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
    }
)

_RAW_HTTP_BOUNDARIES = frozenset(
    {
        "mdm/network_transport.py",
        "daemon/client.py",
        "daemon/live_identity.py",
        "daemon/manager_live.py",
        "daemon/manager_locator.py",
        "bridge/__init__.py",
        "adapters/bounded_cli_hook_daemon.py",
        "adapters/claude_daemon_hook_bridge.py",
        "adapters/claude_daemon_hook_transport.py",
        "adapters/cursor_hook_script_template_head.py",
        "adapters/codex_daemon_hook_transport.py",
    }
)


def test_raw_http_clients_are_confined_to_enterprise_transport_or_loopback_ipc() -> None:
    violations: list[str] = []
    observed_boundaries: set[str] = set()
    manager_calls: dict[str, list[str]] = {}
    inventory = HttpClientInventory(GUARD_SOURCE)

    for path in sorted(GUARD_SOURCE.rglob("*.py")):
        relative = path.relative_to(GUARD_SOURCE).as_posix()
        for line, call_name in inventory.calls(path):
            if call_name not in _RAW_HTTP_CALLS:
                continue
            observed_boundaries.add(relative)
            if relative.startswith("daemon/manager_"):
                manager_calls.setdefault(relative, []).append(call_name)
            if relative not in _RAW_HTTP_BOUNDARIES:
                violations.append(f"{relative}:{line}:{call_name}")

    assert violations == []
    assert manager_calls == {
        "daemon/manager_live.py": ["urllib.request.urlopen"] * 3,
        "daemon/manager_locator.py": ["urllib.request.urlopen"],
    }
    assert "mdm/network_transport.py" in observed_boundaries
    assert "runtime/verified_github_reads.py" not in observed_boundaries


def test_external_runtime_paths_import_the_managed_transport() -> None:
    expected_managed_paths = {
        "cli/connect_flow.py",
        "cli/remote_pair_flow.py",
        "cli/update_commands.py",
        "local_supply_chain.py",
        "provenance.py",
        "proxy/remote.py",
        "runtime/runner.py",
        "runtime/verified_github_reads.py",
    }
    missing: list[str] = []
    for relative in sorted(expected_managed_paths):
        source = (GUARD_SOURCE / relative).read_text(encoding="utf-8")
        if "mdm.network" not in source and "managed_urlopen" not in source and "managed_opener" not in source:
            missing.append(relative)
    assert missing == []


def test_bridge_external_egress_uses_managed_session_and_daemon_ipc_is_loopback_guarded() -> None:
    source = (GUARD_SOURCE / "bridge" / "__init__.py").read_text(encoding="utf-8")

    assert "managed_requests_session().post" in source
    assert "_RAW_REQUESTS_POST" not in source
    assert "managed_requests_required" not in source
    assert "_validate_guard_daemon_url" in source
    assert "Guard Bridge daemon URL must target loopback." in source
