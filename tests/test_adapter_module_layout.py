"""Keep adapter helpers discoverable to Python, static analysis, and freezers."""

from __future__ import annotations

from fnmatch import fnmatchcase
from importlib import import_module, util
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import adapters
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from scripts.ci.hook_data_plane_ownership_contract import load_manifest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(adapters.__file__).parent
FAMILIES = ("claude", "cline", "codex", "copilot", "cursor", "devin", "grok", "opencode", "pi", "zcode")


@pytest.mark.parametrize("family", FAMILIES)
def test_grouped_adapter_modules_are_regular_packages(family: str) -> None:
    directory = PACKAGE / "_modules" / family
    assert (PACKAGE / "_modules" / "__init__.py").is_file()
    assert (directory / "__init__.py").is_file()
    modules = sorted(path for path in directory.glob("*.py") if path.name != "__init__.py")
    assert modules, f"missing grouped adapter modules: {family}"
    for module_file in modules:
        name = f"{adapters.__name__}._modules.{family}.{module_file.stem}"
        spec = util.find_spec(name)
        assert spec is not None and spec.origin is not None
        assert Path(spec.origin).resolve() == module_file.resolve()
        assert import_module(name).__name__ == name
        assert not (PACKAGE / module_file.name).exists(), f"duplicate implementation: {name}"


def test_adapter_search_path_contains_only_the_public_package() -> None:
    assert [Path(path).resolve() for path in adapters.__path__] == [PACKAGE.resolve()]


def test_public_adapter_registry_and_aliases_remain_unchanged() -> None:
    registered = adapters.list_adapters()
    assert {adapter.harness for adapter in registered} == {contract.harness for contract in HARNESS_CONTRACTS}
    for adapter in registered:
        assert adapters.get_adapter(adapter.harness) is adapter
        for alias in adapter.aliases:
            assert adapters.get_adapter(alias) is adapter


def test_grouped_adapter_sources_remain_in_native_ownership_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    manifest = load_manifest(ROOT / "docs/guard/contracts/hook-data-plane-ownership.v2.json")
    owner_globs = [pattern for node in manifest["nodes"] for pattern in node.get("paths", [])]
    protected_globs = manifest["protected_change_globs"]
    for module_file in sorted((PACKAGE / "_modules").rglob("*.py")):
        relative = module_file.relative_to(ROOT).as_posix()
        assert any(fnmatchcase(relative, pattern) for pattern in owner_globs), relative
        assert any(fnmatchcase(relative, pattern) for pattern in protected_globs), relative
