from __future__ import annotations

import importlib.util
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "rust_authority_ownership_gate.py"
SPEC = importlib.util.spec_from_file_location("hook_data_plane_ownership_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_changed_path_gate_accepts_mapped_native_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        MODULE,
        "_changed_files",
        lambda _base_ref: ("rust/crates/guard-runtime/src/hook_edge.rs",),
    )

    changed = MODULE._changed_path_gate(MODULE._manifest(), "base")

    assert changed == ("rust/crates/guard-runtime/src/hook_edge.rs",)


def test_changed_path_gate_maps_live_cli_hook_support(monkeypatch: pytest.MonkeyPatch) -> None:
    path = "src/codex_plugin_scanner/guard/cli/commands_support_interaction.py"
    monkeypatch.setattr(MODULE, "_changed_files", lambda _base_ref: (path,))

    changed = MODULE._changed_path_gate(MODULE._manifest(), "base")

    assert changed == (path,)


def test_changed_path_gate_maps_every_production_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    path = "src/codex_plugin_scanner/guard/adapters/antigravity.py"
    monkeypatch.setattr(MODULE, "_changed_files", lambda _base_ref: (path,))

    changed = MODULE._changed_path_gate(MODULE._manifest(), "base")

    assert changed == (path,)


def test_contract_inventory_matches_registered_harnesses() -> None:
    manifest = MODULE._manifest()

    assert set(manifest["supported_harnesses"]) == MODULE._registered_harnesses()


def test_contract_inventory_rejects_unknown_route_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = MODULE._manifest()
    harness_routes = manifest["harness_routes"]
    assert isinstance(harness_routes, dict)
    codex_route = harness_routes["codex"]
    assert isinstance(codex_route, dict)
    codex_route["pre_tool_use"] = "installed_canoncal"
    contract = tmp_path / "hook-data-plane-ownership.v2.json"
    contract.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(MODULE, "MANIFEST", contract)

    with pytest.raises(RuntimeError, match="route has an invalid status: codex"):
        MODULE._manifest()


def test_changed_path_gate_rejects_unmapped_native_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        MODULE,
        "_changed_files",
        lambda _base_ref: ("rust/new-native-edge/src/main.rs",),
    )

    with pytest.raises(RuntimeError, match="has no ownership mapping"):
        MODULE._changed_path_gate(MODULE._manifest(), "base")


def test_changed_path_gate_uses_base_scope_when_head_contract_is_narrowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = MODULE._manifest()
    head = deepcopy(base)
    head["protected_change_globs"] = []
    head["nodes"] = [node for node in head["nodes"] if node["id"] == "ownership_governance"]
    monkeypatch.setattr(MODULE, "_manifest_at_ref", lambda _base_ref: base)
    monkeypatch.setattr(
        MODULE,
        "_changed_files",
        lambda _base_ref: ("rust/new-native-edge/src/main.rs",),
    )

    with pytest.raises(RuntimeError, match=r"protection|ownership|mapping"):
        MODULE._changed_path_gate(head, "base")


def test_contract_only_change_cannot_remove_live_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = MODULE._manifest()
    head = deepcopy(base)
    head["nodes"] = [node for node in head["nodes"] if node["id"] != "harness_adapter_registry_and_installation"]
    monkeypatch.setattr(MODULE, "_manifest_at_ref", lambda _base_ref: base)
    monkeypatch.setattr(
        MODULE,
        "_changed_files",
        lambda _base_ref: ("docs/guard/contracts/hook-data-plane-ownership.v2.json",),
    )

    with pytest.raises(RuntimeError, match="live hook data-plane ownership was removed"):
        MODULE._changed_path_gate(head, "base")


def test_recursive_coverage_narrowing_detects_live_files_on_python_312() -> None:
    with pytest.raises(RuntimeError, match="live hook data-plane protection was removed"):
        MODULE._coverage_narrowing_gate(
            base_protected=("rust/**",),
            base_owners=(),
            head_protected=(),
            head_owners=(),
        )


def test_changed_files_includes_deletions_and_disables_rename_collapsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.extend(args)
        return subprocess.CompletedProcess(args, 0, stdout="rust/crates/guard-runtime/src/removed.rs\n", stderr="")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    assert MODULE._changed_files("base") == ("rust/crates/guard-runtime/src/removed.rs",)
    assert "--diff-filter=ACMRD" in observed
    assert "--no-renames" in observed


def test_self_protected_contract_requires_an_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    head = MODULE._manifest()
    head["nodes"] = [node for node in head["nodes"] if node["id"] != "ownership_governance"]
    monkeypatch.setattr(MODULE, "_manifest_at_ref", lambda _base_ref: None)
    monkeypatch.setattr(
        MODULE,
        "_changed_files",
        lambda _base_ref: ("docs/guard/contracts/hook-data-plane-ownership.v2.json",),
    )

    with pytest.raises(RuntimeError, match="has no ownership mapping"):
        MODULE._changed_path_gate(head, "base")


def test_authority_workflow_is_always_selected() -> None:
    source = (ROOT / ".github" / "workflows" / "rust-authority-ownership.yml").read_text(encoding="utf-8")
    trigger = source.split("permissions:", maxsplit=1)[0]

    assert "pull_request:\n    branches: [main]" in trigger
    assert "paths:" not in trigger
    assert "paths-ignore:" not in trigger
    assert "--base-ref" in source
    assert "fetch-depth: 0" in source


def test_native_wheel_workflow_is_always_selected() -> None:
    source = (ROOT / ".github" / "workflows" / "native-wheel-ci.yml").read_text(encoding="utf-8")
    trigger = source.split("permissions:", maxsplit=1)[0]

    assert "pull_request:\n    branches: [main, release/3.2]" in trigger
    assert "paths:" not in trigger
    assert "paths-ignore:" not in trigger
    assert "HOL_GUARD_HOOK_FAST_PATH" in source
    assert "probe_native_default_auto.py --json native-default-auto.json" in source
