from __future__ import annotations

import argparse

from codex_plugin_scanner.guard.cli import commands_dispatch_local
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_parser


def _parse(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    add_guard_parser(subparsers)
    return parser.parse_args(arguments)


def test_network_status_reports_truthful_backend_capabilities(monkeypatch) -> None:
    emitted: list[tuple[str, object, bool]] = []
    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda title, payload, as_json: emitted.append((title, payload, as_json)),
        raising=False,
    )
    args = _parse(["guard", "network", "status", "--json"])

    result = commands_dispatch_local._run_guard_network_command(args)

    assert result == 0
    title, raw_payload, as_json = emitted.pop()
    assert title == "network"
    assert as_json is True
    assert isinstance(raw_payload, dict)
    payload = raw_payload
    assert payload["schema"] == "guard.network-status.v1"
    assert tuple(item["backend_id"] for item in payload["backends"]) == (
        "linux.oci-proxy",
        "macos.observe",
        "windows.observe",
        "kubernetes.network-policy",
    )
    assert all(item["production_ready"] is False for item in payload["backends"])


def test_network_parser_defaults_to_status(monkeypatch) -> None:
    emitted: list[tuple[str, object, bool]] = []
    monkeypatch.setattr(
        commands_dispatch_local,
        "_emit",
        lambda title, payload, as_json: emitted.append((title, payload, as_json)),
        raising=False,
    )
    args = _parse(["guard", "network", "--json"])

    assert commands_dispatch_local._run_guard_network_command(args) == 0
    assert emitted[0][0] == "network"
