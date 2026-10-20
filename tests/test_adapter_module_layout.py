"""Verify grouped adapter files keep stable imports and native ownership coverage."""

from __future__ import annotations

import json
from fnmatch import fnmatchcase
from importlib import import_module, util
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import adapters

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(adapters.__file__).parent
FAMILIES = ("claude", "cline", "codex", "copilot", "cursor", "devin", "grok", "opencode", "pi", "zcode")


@pytest.mark.parametrize("family", FAMILIES)
def test_grouped_adapter_modules_preserve_public_import_path(family: str) -> None:
    directory = PACKAGE / "_modules" / family
    modules = sorted(directory.glob("*.py"))
    assert modules, f"missing grouped adapter modules: {family}"

    for module_file in modules:
        name = f"{adapters.__name__}.{module_file.stem}"
        spec = util.find_spec(name)
        assert spec is not None
        assert spec.origin is not None
        assert Path(spec.origin).resolve() == module_file.resolve()
        assert not (PACKAGE / module_file.name).exists(), f"duplicate import candidate: {name}"


@pytest.mark.parametrize(
    "module_name",
    (
        "claude_daemon_state",
        "cline_hook_payload",
        "codex_hook_response",
        "copilot_state_paths",
        "cursor_hook_events",
        "devin_hooks",
        "grok_hook_invocation_template",
        "opencode_config_lock",
        "pi_extension_source_body",
        "zcode_hooks",
    ),
)
def test_grouped_adapter_imports_use_original_namespace(module_name: str) -> None:
    name = f"{adapters.__name__}.{module_name}"
    assert import_module(name).__name__ == name


def test_grouped_adapter_sources_remain_in_native_ownership_contract() -> None:
    contract_file = ROOT / "docs/guard/contracts/hook-data-plane-ownership.v2.json"
    manifest = json.loads(contract_file.read_text(encoding="utf-8"))
    nodes = manifest["nodes"]
    owner_globs = [pattern for node in nodes for pattern in node.get("paths", [])]
    protected_globs = manifest["protected_change_globs"]

    for module_file in sorted((PACKAGE / "_modules").glob("*/*.py")):
        relative = module_file.relative_to(ROOT).as_posix()
        assert any(fnmatchcase(relative, pattern) for pattern in owner_globs), relative
        assert any(fnmatchcase(relative, pattern) for pattern in protected_globs), relative
