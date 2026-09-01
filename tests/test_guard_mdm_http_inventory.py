from __future__ import annotations

import ast
from pathlib import Path

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
        "daemon/manager.py",
        "bridge/__init__.py",
        "adapters/bounded_cli_hook_bridge.py",
        "adapters/claude_daemon_hook_bridge.py",
        "adapters/cursor_hook_script_template_head.py",
        "adapters/codex_daemon_hook_transport.py",
    }
)


def _aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                binding = alias.asname or alias.name.split(".", 1)[0]
                aliases[binding] = alias.name if alias.asname else binding
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def test_raw_http_clients_are_confined_to_enterprise_transport_or_loopback_ipc() -> None:
    violations: list[str] = []
    observed_boundaries: set[str] = set()

    for path in sorted(GUARD_SOURCE.rglob("*.py")):
        relative = path.relative_to(GUARD_SOURCE).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = _aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = _qualified_name(node.func, aliases)
            if call_name not in _RAW_HTTP_CALLS:
                continue
            observed_boundaries.add(relative)
            if relative not in _RAW_HTTP_BOUNDARIES:
                violations.append(f"{relative}:{node.lineno}:{call_name}")

    assert violations == []
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
