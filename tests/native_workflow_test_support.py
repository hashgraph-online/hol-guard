"""Offline native observations for workflow control-plane unit tests.

The fixture simulates transport binding to the test's protected snapshot. It
does not supply authenticated resident receipts or replace installed proofs.
Matcher observations and command models still come from the native binaries.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import CompositeCommandEvaluation, evaluate_command
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import GitHubWorkflowAuthorization
from tests.native_command_test_support import real_native_review_fixture


def evaluate_native_workflow_command(
    command: str,
    *,
    guard_home: Path | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    workflow_authorization: GitHubWorkflowAuthorization | None = None,
) -> CompositeCommandEvaluation:
    del guard_home
    snapshot = extension_control_snapshot
    controls: tuple[tuple[str, str, str], ...] = ()
    if snapshot is not None:
        # These workflow tests exercise local controls. Never silently flatten
        # managed policy or lockdown into an unrelated local fixture.
        assert not any(layer.global_lockdown for layer in snapshot.layers)
        assert all(layer.kind is ControlLayerKind.LOCAL_ADMIN or not layer.controls for layer in snapshot.layers)
        controls = tuple(
            (control.target.kind.value, control.target.target_id, control.state.value)
            for layer in snapshot.layers
            for control in layer.controls
        )
    fixture = real_native_review_fixture(command, controls=controls)
    snapshot = snapshot or fixture.snapshot
    assert snapshot.catalog_digest == fixture.snapshot.catalog_digest
    extensions = fixture.payload["command_extensions"]
    assert isinstance(extensions, dict)
    binding = extensions["binding"]
    assert isinstance(binding, dict)
    binding["control_revision"] = snapshot.revision
    binding["managed_control_revision"] = snapshot.managed_revision
    binding["control_effective_digest"] = snapshot.effective_digest
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    return evaluate_command(
        command,
        canonical_command=canonical,
        cwd=cwd,
        home_dir=home_dir,
        extension_control_snapshot=snapshot,
        native_extension_evidence=fixture.payload,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        workflow_authorization=workflow_authorization,
    )
