from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard import aibom_detection
from codex_plugin_scanner.guard.aibom_detection import enrich_mcp_server_metadata
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


def _unavailable_native(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(kind: str, args: object, guard_home: object = None, **_kwargs: object) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(aibom_detection, "native_runner_authority", refuse)


def test_mcp_metadata_degrades_to_unbound_sentinels_without_native(monkeypatch: pytest.MonkeyPatch) -> None:
    _unavailable_native(monkeypatch)
    explicit = "sha256:" + "a" * 64

    enriched = enrich_mcp_server_metadata(
        {"name": "svc", "env": {"TOKEN": "secret"}, "header_values_hash": f"  {explicit} "},
        command="npx",
        args=("-y", "svc"),
        url=None,
        transport="stdio",
    )

    assert enriched["env_keys"] == ["TOKEN"]
    assert enriched["env_values_hash"] == "guard-context-unbound:configured-environment"
    assert enriched["header_values_hash"] == explicit
    assert str(enriched["content_hash"]).startswith("guard-context-unbound:")
    assert "secret" not in json.dumps(enriched["versionInfo"])
    assert enriched["versionInfo"]["versionLabel"] == "svc"
    assert enriched["versionInfo"]["contentHash"] == enriched["content_hash"]


def test_mcp_metadata_one_outage_short_circuits_the_rest_of_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def refuse(kind: str, args: object, guard_home: object = None, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise NativeRunnerAuthorityError("native_runner_authority_resident_unavailable")

    monkeypatch.setattr(aibom_detection, "native_runner_authority", refuse)
    monkeypatch.setattr(aibom_detection, "_mcp_native_backoff_until", 0.0)
    for _ in range(3):
        enriched = enrich_mcp_server_metadata(
            {"name": "svc"},
            command="npx",
            args=(),
            url=None,
            transport="stdio",
        )
        assert str(enriched["content_hash"]).startswith("guard-context-unbound:")
    assert calls == 1


def test_mcp_metadata_per_request_errors_do_not_open_the_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def refuse(kind: str, args: object, guard_home: object = None, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise NativeRunnerAuthorityError("native_runner_authority_request_too_large")

    monkeypatch.setattr(aibom_detection, "native_runner_authority", refuse)
    monkeypatch.setattr(aibom_detection, "_mcp_native_backoff_until", 0.0)
    for _ in range(3):
        enriched = enrich_mcp_server_metadata(
            {"name": "svc"},
            command="npx",
            args=(),
            url=None,
            transport="stdio",
        )
        assert str(enriched["content_hash"]).startswith("guard-context-unbound:")
    assert calls == 3


def test_mcp_metadata_retries_after_the_backoff_window(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    now = 1000.0

    def refuse(kind: str, args: object, guard_home: object = None, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise NativeRunnerAuthorityError("native_runner_authority_resident_unavailable")

    monkeypatch.setattr(aibom_detection, "native_runner_authority", refuse)
    monkeypatch.setattr(aibom_detection, "_mcp_native_backoff_until", 0.0)
    monkeypatch.setattr(aibom_detection.time, "monotonic", lambda: now)
    enrich_mcp_server_metadata({"name": "a"}, command="c", args=(), url=None, transport="stdio")
    enrich_mcp_server_metadata({"name": "b"}, command="c", args=(), url=None, transport="stdio")
    assert calls == 1
    now += aibom_detection._MCP_NATIVE_RETRY_SECONDS
    enrich_mcp_server_metadata({"name": "c"}, command="c", args=(), url=None, transport="stdio")
    assert calls == 2
