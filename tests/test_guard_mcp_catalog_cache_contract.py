from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.local_mcp_stdio import run_mcp_catalog
from tests.test_guard_mcp_catalog_coverage import _discovery, _requests, _server, _tools

pytestmark = pytest.mark.usefixtures("native_mcp_probe")


@pytest.mark.parametrize("missing", ["ttlMs", "cacheScope"])
@pytest.mark.parametrize("invalid_page", ["<root>", "next"])
def test_modern_catalog_requires_cache_hints_on_every_page(tmp_path: Path, missing: str, invalid_page: str) -> None:
    first, second = _tools(1, prefix="first"), _tools(1, prefix="second")
    pages: dict[str, dict[str, object]] = {
        "<root>": {
            "resultType": "complete",
            "tools": first,
            "nextCursor": "next",
            "ttlMs": 1000,
            "cacheScope": "private",
        },
        "next": {"resultType": "complete", "tools": second, "ttlMs": 1000, "cacheScope": "private"},
    }
    del pages[invalid_page][missing]
    catalog = run_mcp_catalog(_server(tmp_path, pages, discovery=_discovery()))
    assert not catalog.complete
    assert catalog.reason == "invalid_cache_hints"
    assert catalog.tools == (() if invalid_page == "<root>" else tuple(first))


@pytest.mark.parametrize("error_code", [-32601, -32000, -32603])
def test_nonmodern_discovery_errors_preserve_legacy_compatibility(tmp_path: Path, error_code: int) -> None:
    catalog = run_mcp_catalog(
        _server(
            tmp_path,
            {"<root>": {"tools": _tools(1)}},
            discovery={"error": {"code": error_code, "message": "Synthetic legacy rejection"}},
        )
    )
    assert catalog.complete
    assert catalog.protocol_version == "2024-11-05"
    assert catalog.cache_ttl_ms == 0
    assert catalog.cache_scope == "private"
    assert [request["method"] for request in _requests(tmp_path)] == [
        "server/discover",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
