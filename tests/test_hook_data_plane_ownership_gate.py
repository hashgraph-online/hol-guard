from __future__ import annotations

import importlib.util
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci.hook_data_plane_ownership_contract import NATIVE_PROOF_OVERRIDES

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


def _copy_pretool_graph_sources(root: Path) -> None:
    for relative in (
        "src/codex_plugin_scanner/guard/daemon/server.py",
        "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_hook_payload.py",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")


def test_pretool_graph_gate_covers_server_entrypoint_and_cli() -> None:
    assert MODULE._graph_failures(ROOT) == []


def test_pretool_graph_gate_rejects_unguarded_server_legacy_escape(tmp_path: Path) -> None:
    _copy_pretool_graph_sources(tmp_path)
    server = tmp_path / "src/codex_plugin_scanner/guard/daemon/server.py"
    source = server.read_text(encoding="utf-8")
    marker = "            if _native_mode_requires_rust():\n                self._write_json(\n"
    assert marker in source
    server.write_text(
        source.replace(marker, "            if False:\n                self._write_json(\n", 1),
        encoding="utf-8",
    )

    failures = MODULE._graph_failures(tmp_path)

    assert any("server execute path" in failure for failure in failures)


def test_pretool_graph_gate_rejects_unknown_event_compatibility_escape(tmp_path: Path) -> None:
    _copy_pretool_graph_sources(tmp_path)
    entrypoint = tmp_path / "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py"
    source = entrypoint.read_text(encoding="utf-8")
    marker = "        _native_mode_requires_rust()\n"
    assert marker in source
    entrypoint.write_text(
        source.replace(marker, "        False\n", 1),
        encoding="utf-8",
    )

    failures = MODULE._graph_failures(tmp_path)

    assert any("unknown events" in failure for failure in failures)


def test_pretool_graph_gate_rejects_cli_normalization_before_native(tmp_path: Path) -> None:
    _copy_pretool_graph_sources(tmp_path)
    cli = tmp_path / "src/codex_plugin_scanner/guard/cli/commands_hook.py"
    source = cli.read_text(encoding="utf-8")
    assert "normalize=False" in source
    cli.write_text(source.replace("normalize=False", "normalize=True", 1), encoding="utf-8")

    failures = MODULE._graph_failures(tmp_path)

    assert any("normalizes payload before native authority" in failure for failure in failures)


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


@pytest.fixture
def workflow_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for relative in (
        ".github/workflows/rust-authority-ownership.yml",
        ".github/workflows/native-wheel-ci.yml",
        "scripts/ci/native-proof-environment.sh",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_authority_workflow_gate_accepts_sourced_native_proof_environment(workflow_sources: Path) -> None:
    MODULE._workflow_gate()


@pytest.mark.parametrize("name", sorted(NATIVE_PROOF_OVERRIDES))
def test_authority_workflow_gate_rejects_each_missing_cleanup_override(workflow_sources: Path, name: str) -> None:
    helper = workflow_sources / "scripts/ci/native-proof-environment.sh"
    source = helper.read_text(encoding="utf-8")
    # A comment must not stand in for an actual unset, including single-name lines.
    lines = [" ".join(token for token in line.split() if token != name) for line in source.splitlines()]
    helper.write_text("\n".join(line for line in lines if line != "unset") + f"\n# unset {name}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="must clear exactly the established overrides"):
        MODULE._workflow_gate()


@pytest.mark.parametrize(
    "command",
    ["export HOL_GUARD_NATIVE=off", "return 0", "unset PATH", "unset $(echo PATH)", "unset HOL_GUARD_NATIVE#suffix"],
)
def test_authority_workflow_gate_rejects_helper_side_effects(workflow_sources: Path, command: str) -> None:
    helper = workflow_sources / "scripts/ci/native-proof-environment.sh"
    helper.write_text(helper.read_text(encoding="utf-8") + command + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="installed proof environment helper"):
        MODULE._workflow_gate()


def test_authority_workflow_gate_rejects_missing_cleanup_helper(workflow_sources: Path) -> None:
    (workflow_sources / "scripts/ci/native-proof-environment.sh").unlink()

    with pytest.raises(RuntimeError, match="required authority source is missing"):
        MODULE._workflow_gate()


@pytest.mark.parametrize("job_id", ["linux-x64", "macos"])
@pytest.mark.parametrize("replacement", ["# source", "echo source", "bash"])
def test_authority_workflow_gate_requires_sourcing_in_each_proof_shell(
    workflow_sources: Path, job_id: str, replacement: str
) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    before, job = workflow.read_text(encoding="utf-8").split(f"\n  {job_id}:\n", maxsplit=1)
    job = job.replace(
        "source scripts/ci/native-proof-environment.sh", f"{replacement} scripts/ci/native-proof-environment.sh", 1
    )
    workflow.write_text(before + f"\n  {job_id}:\n" + job, encoding="utf-8")

    with pytest.raises(RuntimeError, match="must be sourced before each proof"):
        MODULE._workflow_gate()


def test_authority_workflow_gate_rejects_cleanup_after_default_proof(workflow_sources: Path) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    source = workflow.read_text(encoding="utf-8")
    helper = "          source scripts/ci/native-proof-environment.sh\n"
    probe = (
        "          .venv/bin/python ci/native_runtime/probe_native_default_auto.py --json native-default-auto.json\n"
    )
    assert helper + probe in source
    workflow.write_text(source.replace(helper + probe, probe + helper, 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match="must be sourced before each proof"):
        MODULE._workflow_gate()


@pytest.mark.parametrize("call_index", range(7))
def test_authority_workflow_gate_rejects_cleanup_omitted_from_any_proof(
    workflow_sources: Path, call_index: int
) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    source = workflow.read_text(encoding="utf-8")
    call = "          source scripts/ci/native-proof-environment.sh\n"
    sections = source.split(call)
    assert len(sections) == 8
    workflow.write_text(call.join(sections[: call_index + 1]) + call.join(sections[call_index + 1 :]), encoding="utf-8")

    with pytest.raises(RuntimeError, match="must be sourced before each proof"):
        MODULE._workflow_gate()


@pytest.mark.parametrize("operation", [")", "export HOL_GUARD_NATIVE=off"])
def test_authority_workflow_gate_rejects_cleanup_lost_before_proof(workflow_sources: Path, operation: str) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    source = workflow.read_text(encoding="utf-8")
    call = "          source scripts/ci/native-proof-environment.sh\n"
    replacement = ("          (\n" if operation == ")" else "") + call + f"          {operation}\n"
    workflow.write_text(source.replace(call, replacement, 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match="must be sourced before each proof"):
        MODULE._workflow_gate()


def test_authority_workflow_gate_rejects_missing_windows_cleanup(workflow_sources: Path) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    source = workflow.read_text(encoding="utf-8")
    source = source.replace(
        "Remove-Item Env:HOL_GUARD_HOOK_FAST_PATH -ErrorAction",
        "# Remove-Item Env:HOL_GUARD_HOOK_FAST_PATH -ErrorAction",
        1,
    )
    workflow.write_text(source, encoding="utf-8")

    with pytest.raises(RuntimeError, match="cleanup is incomplete: windows"):
        MODULE._workflow_gate()


def test_authority_workflow_gate_rejects_default_proof_only_in_comments(workflow_sources: Path) -> None:
    workflow = workflow_sources / ".github/workflows/native-wheel-ci.yml"
    source = workflow.read_text(encoding="utf-8")
    source = source.replace(
        ".venv/bin/python ci/native_runtime/probe_native_default_auto.py",
        "# .venv/bin/python ci/native_runtime/probe_native_default_auto.py",
        1,
    )
    workflow.write_text(source, encoding="utf-8")

    with pytest.raises(RuntimeError, match="missing its default proof: linux-x64"):
        MODULE._workflow_gate()
