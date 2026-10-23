"""The CI-sized MCP batches must retain the complete native decision matrix."""

import importlib.util
from collections import Counter
from pathlib import Path

import pytest

from tests.mcp_case_batches import package_case_batches


@pytest.mark.parametrize("package_count", [1, 34, 80])
def test_native_mcp_batches_cover_every_original_case_exactly_once(package_count):
    original = [
        (f"mcp.example{index}", "npx", f"@example/server{index}", f"tool{tool}", "review")
        for index in range(package_count)
        for tool in range(3 + index % 2)
    ]
    batches = package_case_batches(original)
    flattened = [case for batch in batches for case in batch]
    packages = Counter(case[0] for case in original)
    assert len(batches) == min(64, len(packages))
    assert all(batches)
    assert Counter(flattened) == Counter(original)
    assert max(map(len, batches)) - min(map(len, batches)) <= max(packages.values())
    for identity in packages:
        assert sum(any(case[0] == identity for case in batch) for batch in batches) == 1


def test_empty_native_mcp_inventory_fails_instead_of_skipping_the_matrix():
    with pytest.raises(ValueError, match="must contain package cases"):
        package_case_batches([])


def test_native_mcp_matrix_collects_without_installed_native_metadata(monkeypatch):
    from codex_plugin_scanner.guard.runtime import mcp_server_contribution

    load = mcp_server_contribution.load_mcp_contribution_payloads

    def source_only(root=None):
        assert root is not None, "collection must not request installed native metadata"
        return load(root)

    monkeypatch.setattr(mcp_server_contribution, "load_mcp_contribution_payloads", source_only)
    path = Path(__file__).with_name("test_guard_contributed_mcp_native.py")
    spec = importlib.util.spec_from_file_location("tests._mcp_collection_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._SOURCE_PACKAGE_CASES
    loads = []

    def native_cases():
        loads.append(True)
        return module._SOURCE_PACKAGE_CASES

    monkeypatch.setattr(module, "_package_cases", native_cases)
    loader = module.native_package_cases.__wrapped__()
    assert loads == []
    assert loader() is loader()
    assert loads == [True]
