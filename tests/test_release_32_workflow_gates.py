"""Branch contracts for release/3.2 pull-request validation."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_BRANCH = "release/3.2"

PR_GATE_WORKFLOWS = (
    ".github/workflows/cline-contract-ci.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/native-release-contract.yml",
    ".github/workflows/native-wheel-ci.yml",
    ".github/workflows/guard-network-remediation-proof.yml",
    ".github/workflows/guard-gvisor-reference.yml",
    ".github/workflows/extension-control-center-installed-ci.yml",
)

NATIVE_VALIDATION_WORKFLOWS = (
    "decision-critical-io.yml",
    "native-release-contract.yml",
    "native-wheel-ci.yml",
    "rust-authority-ownership.yml",
    "rust-command-model-differential.yml",
    "rust-command-shadow.yml",
    "rust-daemon-edge-hardening.yml",
    "rust-migration-tree-hygiene.yml",
    "rust-native-identity.yml",
    "rust-posttool-authority-acceptance.yml",
    "rust-pretool-adversarial.yml",
    "rust-pretool-authority-acceptance.yml",
    "rust-runtime-differential.yml",
    "rust-runtime-mutation-differential.yml",
    "rust-runtime-performance.yml",
    "rust-runtime-recovery.yml",
    "rust-runtime-rule-contract.yml",
    "rust-runtime-windows-resident.yml",
    "rust-runtime.yml",
)

_NATIVE_BOUNDARY_CHANGES = (
    "rust/crates/guard-runtime/src/policy_store.rs",
    "src/codex_plugin_scanner/guard/native_resident_stream.py",
    "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
    "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py",
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
    "src/codex_plugin_scanner/guard/config_mutation.py",
    "src/codex_plugin_scanner/guard/runtime/extension_control_runtime.py",
    "src/codex_plugin_scanner/guard/runtime/command_common_cli_matchers.py",
    "src/codex_plugin_scanner/guard/store_native_decision_receipts.py",
    "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
    "src/codex_plugin_scanner/guard/adapters/pi_hooks.py",
    "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
)

_MEASUREMENT_HELPER_CHANGES = (
    "scripts/native_benchmark_oracle.py",
    "scripts/native_slo_launcher.py",
    "scripts/native_slo_resources.py",
    "scripts/native_slo_offered_load.py",
    "scripts/native_slo_phases.py",
    "scripts/native_slo_qualification.py",
    "scripts/qualify_guard_native.py",
    "ci/native_runtime/installed_hook_client.py",
    "tests/test_guard_native_release_gate_benchmark.py",
)


def _triggers(relative_path: str) -> dict[str, object]:
    workflow = cast(
        dict[object, object],
        yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8")),
    )
    return cast(dict[str, object], workflow[True])


def _branches(trigger: object) -> list[str]:
    return cast(list[str], cast(dict[str, object], trigger)["branches"])


def test_release_32_pull_requests_receive_required_product_gates() -> None:
    for relative_path in PR_GATE_WORKFLOWS:
        triggers = _triggers(relative_path)

        assert RELEASE_BRANCH in _branches(triggers["pull_request"]), relative_path


def test_release_32_gate_expansion_does_not_authorize_push_publication() -> None:
    publish_triggers = _triggers(".github/workflows/publish.yml")

    assert RELEASE_BRANCH not in _branches(publish_triggers["push"])


def _selects(workflow: str, event: str, changed_path: str) -> bool:
    trigger = cast(dict[str, object], _triggers(f".github/workflows/{workflow}")[event])
    branches = cast(list[str] | None, trigger.get("branches"))
    paths = cast(list[str] | None, trigger.get("paths"))
    branch_selected = branches is None or RELEASE_BRANCH in branches
    return branch_selected and (paths is None or any(fnmatchcase(changed_path, pattern) for pattern in paths))


@pytest.mark.parametrize("workflow", NATIVE_VALIDATION_WORKFLOWS)
@pytest.mark.parametrize("event", ("pull_request", "push"))
def test_release_32_receives_native_validation(workflow: str, event: str) -> None:
    assert _selects(workflow, event, f".github/workflows/{workflow}")


@pytest.mark.parametrize(
    "workflow", ("native-wheel-ci.yml", "rust-authority-ownership.yml", "decision-critical-io.yml")
)
def test_installed_and_ownership_checks_do_not_depend_on_changed_file_filters(workflow: str) -> None:
    trigger = cast(dict[str, object], _triggers(f".github/workflows/{workflow}")["pull_request"])
    assert "paths" not in trigger
    assert "paths-ignore" not in trigger


@pytest.mark.parametrize("changed_path", _NATIVE_BOUNDARY_CHANGES)
@pytest.mark.parametrize("workflow", ("rust-runtime.yml", "rust-runtime-performance.yml", "rust-runtime-recovery.yml"))
def test_native_boundary_changes_select_runtime_performance_and_recovery(workflow: str, changed_path: str) -> None:
    assert _selects(workflow, "pull_request", changed_path)


@pytest.mark.parametrize("changed_path", _MEASUREMENT_HELPER_CHANGES)
@pytest.mark.parametrize("workflow", ("rust-runtime-performance.yml", "rust-runtime-recovery.yml"))
def test_measurement_helper_changes_select_performance_and_recovery(workflow: str, changed_path: str) -> None:
    assert _selects(workflow, "pull_request", changed_path)


@pytest.mark.parametrize("workflow", ("rust-runtime-performance.yml", "rust-runtime-recovery.yml"))
@pytest.mark.parametrize(
    "changed_path",
    ("contracts/extensions/contribution.v1.schema.json", "contracts/mcp-servers/contribution.v1.schema.json"),
)
def test_extension_contract_changes_select_performance_and_recovery(workflow: str, changed_path: str) -> None:
    assert _selects(workflow, "pull_request", changed_path)


@pytest.mark.parametrize(
    "workflow", ("rust-command-model-differential.yml", "rust-command-shadow.yml", "rust-runtime-rule-contract.yml")
)
def test_command_reference_changes_select_native_differential_validation(workflow: str) -> None:
    assert _selects(workflow, "pull_request", "src/codex_plugin_scanner/guard/runtime/command_common_cli_matchers.py")


@pytest.mark.parametrize("workflow", ("native-release-contract.yml", "rust-native-identity.yml"))
@pytest.mark.parametrize("changed_path", ("scripts/release/stage_guard_cloud_review_artifacts.py", "pyproject.toml"))
def test_packaging_helpers_select_native_identity_and_release_contract(workflow: str, changed_path: str) -> None:
    assert _selects(workflow, "pull_request", changed_path)


@pytest.mark.parametrize(
    "workflow",
    (
        "desktop-contract-ci.yml",
        "extension-control-center-installed-ci.yml",
    ),
)
@pytest.mark.parametrize(
    "changed_path",
    (
        "rust/crates/guard-runtime/src/policy_store.rs",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "pyproject.toml",
        "uv.lock",
    ),
)
def test_native_and_package_changes_select_desktop_and_extension_contracts(workflow: str, changed_path: str) -> None:
    assert _selects(workflow, "pull_request", changed_path)


@pytest.mark.parametrize(
    "workflow",
    ("desktop-contract-ci.yml", "extension-control-center-installed-ci.yml"),
)
def test_release_32_pushes_receive_desktop_and_installed_extension_validation(workflow: str) -> None:
    assert _selects(workflow, "push", f".github/workflows/{workflow}")


@pytest.mark.parametrize(
    "changed_path",
    (
        "src/codex_plugin_scanner/guard/cli/desktop_bootstrap.py",
        "src/codex_plugin_scanner/guard/presentation_settings.py",
        "src/codex_plugin_scanner/guard/settings_write_lock.py",
    ),
)
def test_desktop_projection_inputs_select_desktop_contracts(changed_path: str) -> None:
    assert _selects("desktop-contract-ci.yml", "pull_request", changed_path)


@pytest.mark.parametrize(
    "changed_path",
    (
        "src/codex_plugin_scanner/guard/config_mutation.py",
        "src/codex_plugin_scanner/guard/runtime/command_common_cli_matchers.py",
    ),
)
def test_extension_policy_inputs_select_installed_extension_controls(changed_path: str) -> None:
    assert _selects("extension-control-center-installed-ci.yml", "pull_request", changed_path)
