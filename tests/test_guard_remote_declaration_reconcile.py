"""A remote connector removed from a harness config stops declaring its origin."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import persist_discovered_harness_mcp_servers
from codex_plugin_scanner.guard.adapters.harness_mcp_remote import (
    MAX_DISCOVERED_MCP_SERVERS,
    _remote_servers,
    remote_scan_harnesses,
)
from codex_plugin_scanner.guard.daemon import local_cli_api
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


class _Store:
    def __init__(self, *, refuse: bool = False) -> None:
        self.refuse = refuse
        self.reconciled: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def ensure_local_mcp_observation(self, identity: object, **kwargs: object) -> str | None:
        if self.refuse:
            return None
        return f"local-cli.{kwargs['source_label']}.{kwargs['remote_origin']}"

    def reconcile_remote_mcp_declarations(self, *, harnesses: object, declared_cli_ids: object) -> int:
        self.reconciled.append((tuple(harnesses), tuple(declared_cli_ids)))  # type: ignore[arg-type]
        return 0


def _detection(harness: str, *servers: tuple[str, str]) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=tuple(
            GuardArtifact(
                artifact_id=f"{harness}:global:mcp_server:{name}",
                name=name,
                harness=harness,
                artifact_type="mcp_server",
                source_scope="global",
                config_path="/home/user/.config/harness.json",
                url=url,
                transport="http",
            )
            for name, url in servers
        ),
    )


def _persist(store: _Store, detections: list[HarnessDetection]) -> None:
    remote = _remote_servers(detections)
    persist_discovered_harness_mcp_servers(
        store,
        (),
        seen_at="2026-01-01T00:00:00Z",
        remote=remote,
        remote_harnesses=remote_scan_harnesses(detections, remote),
    )


def test_a_full_scan_reconciles_every_harness_it_read() -> None:
    store = _Store()
    _persist(store, [_detection("codex", ("echo-mcp", "https://mcp.example.test/mcp")), _detection("cursor")])
    assert len(store.reconciled) == 1
    harnesses, declared = store.reconciled[0]
    assert harnesses == ("codex", "cursor")
    assert len(declared) == 1


def test_a_harness_with_no_remote_servers_still_forgets_old_ones() -> None:
    store = _Store()
    _persist(store, [_detection("codex")])
    assert store.reconciled == [(("codex",), ())]


def test_a_failed_record_skips_reconciliation() -> None:
    store = _Store(refuse=True)
    _persist(store, [_detection("codex", ("echo-mcp", "https://mcp.example.test/mcp"))])
    assert store.reconciled == []


def test_no_scan_means_no_reconciliation() -> None:
    store = _Store()
    persist_discovered_harness_mcp_servers(store, (), seen_at="2026-01-01T00:00:00Z")
    assert store.reconciled == []


def test_a_capped_scan_is_not_a_full_scan() -> None:
    origin = "https://mcp.example.test/mcp"
    servers = tuple((f"echo-mcp-{index}", origin) for index in range(MAX_DISCOVERED_MCP_SERVERS))
    detections = [_detection("codex", *servers)]
    assert remote_scan_harnesses(detections, _remote_servers(detections)) is None


class _FailingReconcileStore(_Store):
    def reconcile_remote_mcp_declarations(self, *, harnesses: object, declared_cli_ids: object) -> int:
        raise sqlite3.OperationalError("database is locked")


def test_a_failed_reconcile_keeps_the_recorded_servers() -> None:
    store = _FailingReconcileStore()
    detections = [_detection("codex", ("echo-mcp", "https://mcp.example.test/mcp"))]
    remote = _remote_servers(detections)
    labels = persist_discovered_harness_mcp_servers(
        store,
        (),
        seen_at="2026-01-01T00:00:00Z",
        remote=remote,
        remote_harnesses=remote_scan_harnesses(detections, remote),
    )
    assert len(labels) == 1


class _ServiceStore:
    guard_home = Path("/nonexistent-guard-home")

    def get_managed_install(self, harness: str) -> None:
        return None


def test_a_failed_daemon_scan_forgets_its_remote_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    service = object.__new__(LocalCliApiService)
    service._store = _ServiceStore()  # type: ignore[attr-defined]
    service._discovery_cache = None  # type: ignore[attr-defined]
    detections = [_detection("codex", ("echo-mcp", "https://mcp.example.test/mcp"))]
    service._remote_discovery_cache = (  # type: ignore[attr-defined]
        0.0,
        _remote_servers(detections),
        ("codex",),
    )

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("unreadable")

    monkeypatch.setattr(local_cli_api, "configured_harness_detections", fail)
    assert service._discovered_servers() == ()
    assert service._remote_scan() == ((), None)
