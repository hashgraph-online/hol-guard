"""Host orchestration tests only; simulated responses prove no containment."""
import ast
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import native_pytest_control as control


class Plane:
    supports_contained_execution = True
    pytest_available = True
    response: ClassVar = {"decision": "deny", "policy_action": "sandbox-required",
                "reason_code": "native_workspace_containment_required",
                "required_execution_profile": control.PROFILE}
    instances: ClassVar = []
    cleanup_complete = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.root = kwargs["runtime_root"]
        self.workspace = kwargs["workspace_source"]
        self.captures, self.hooks, self.executions = [], [], []
        self.instances.append(self)

    def start(self):
        self.root.mkdir()
        (self.root / "guard").mkdir()

    def _capture(self, argv, **bounds):
        self.captures.append((argv, bounds))
        if control.PYTEST_PROBE in argv:
            row, rc = {"pytest_available": self.pytest_available}, 0 if self.pytest_available else 3
        elif control.SCOPED_PLAN_PROBE in argv:
            row, rc = {"ok": False, "guard_home": "/product/guard",
                       "reason_code": "pytest_restricted_sandbox_unavailable",
                       "message": "native_request_context_unavailable"}, 4
        else:
            assert "extensions" not in argv
            row, rc = {"status": "native_unavailable", "minimum_action": "review",
                       "policy_evaluation": "not_run", "extensions": [], "rules": []}, 2
        return SimpleNamespace(returncode=rc, stdout=json.dumps(row).encode(), stderr=b"typed probe stderr")

    def invoke_hook(self, payload):
        self.hooks.append(payload)
        return dict(self.response) if payload["hook_event_name"] == "PreToolUse" else {"decision": "allow"}

    def execute_contained(self, payload, **kwargs):
        self.executions.append(payload)
        return {"exit_code": 5, "stdout": "simulated failure", "stderr": ""}

    def close(self):
        self.cleanup_complete = True

    def declaration(self):
        return {"test_double": True, "cleanup_complete": self.cleanup_complete}


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(control.os, "chown", lambda *args: None)
    Plane.instances = []

    def invoke(factory=Plane, **kwargs):
        return control.run_control(root=tmp_path / "fresh", python=Path("/installed/python"),
                                   prefix_digest="a" * 64, bwrap_digest="b" * 64,
                                   plane_factory=factory, **kwargs)
    return invoke


def test_seed_is_public_distinct_contract_and_no_host_execution(run, monkeypatch):
    monkeypatch.setattr(Plane, "pytest_available", False)
    old = os.umask(0o077)
    try:
        result = run()
    finally:
        os.umask(old)
    plane = Plane.instances[-1]
    source = (plane.workspace / "tests/test_contained_contract.py").read_text()
    tree = ast.parse(source)
    assert any(isinstance(node, ast.FunctionDef) and node.name == "test_contained_contract"
               for node in ast.walk(tree))
    assert "os.open(path, os.O_RDONLY | os.O_NOFOLLOW)" in source
    assert "GIT_CONFIG_GLOBAL" in source and "config.read_bytes() == b''" in source
    assert "os.close(fd)" in source and "raise AssertionError" in source
    assert "artifacts" in source and "hol-guard-workspace-" in source
    assert plane.workspace.stat().st_mode & 0o777 == 0o700
    assert (plane.workspace / "tests/test_contained_contract.py").stat().st_mode & 0o777 == 0o600
    assert result["status"] == "pytest-prerequisite-absent"
    assert plane.executions == plane.hooks == []
    assert result["fixture_unchanged"] and result["cleanup_complete"]
    assert not result["containment_conformance_established"]
    assert not result["sdk_bridge_exercised"] and not result["model_exercised"]


def test_supported_scoped_inspection_is_diagnostic_and_context_failure_not_overlay_result(run):
    result = run()
    plane = Plane.instances[-1]
    diagnostic = result["prerequisites"]["normal_command_inspection"]
    assert diagnostic["returncode"] == 2 and diagnostic["stderr_excerpt"] == "typed probe stderr"
    assert diagnostic["summary"]["status"] == "native_unavailable"
    assert diagnostic["policy_authorization"] is False
    argv, bounds = plane.captures[-1]
    assert argv[-3:] == ["test", control.COMMAND, "--json"]
    assert argv[argv.index("--guard-home") + 1] == "/product/guard"
    assert bounds == {"limit": 4 * 1024 * 1024, "timeout": 30}
    assert all("extensions" not in argv for argv, _ in plane.captures)
    assert result["overlay_capability"] == "not_independently_measured"
    assert "native_workspace_plan" not in result["prerequisites"]
    assert result["status"] == "native-sink-negative"


def test_optional_scoped_plan_binds_real_context_and_retains_typed_unavailability(run):
    result = run()
    diagnostic = result["prerequisites"]["scoped_planning_diagnostic"]
    assert diagnostic["returncode"] == 4
    assert diagnostic["parsed"]["message"] == "native_request_context_unavailable"
    assert diagnostic["policy_authorization"] is diagnostic["execution_requested"] is False
    assert diagnostic["overlay_inference"].startswith("none")
    assert result["overlay_capability"] == "not_independently_measured"
    assert result["status"] == "native-sink-negative"
    tree = ast.parse(control.SCOPED_PLAN_PROBE)
    scopes = [node for node in ast.walk(tree) if isinstance(node, ast.With)]
    assert len(scopes) == 1
    assert scopes[0].items[0].context_expr.func.id == "bound_context_digest_home"
    native_calls = [node for node in ast.walk(scopes[0]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "restricted_native"]
    assert len(native_calls) == 1 and native_calls[0].args[0].value == "prepare_workspace_contained"
    assert "Path('/product/guard')" in control.SCOPED_PLAN_PROBE
    assert "k.startswith('GIT_CONFIG') or k=='XDG_CONFIG_HOME'" in control.SCOPED_PLAN_PROBE


def test_optional_positive_plan_cannot_authorize_original_native_denial(run):
    class PositivePlan(Plane):
        response: ClassVar = {"decision": "deny", "policy_action": "review"}
        def _capture(self, argv, **bounds):
            if control.SCOPED_PLAN_PROBE in argv:
                return SimpleNamespace(returncode=0, stderr=b"", stdout=json.dumps({
                    "ok": True, "summary": {"profile_version": control.PROFILE},
                    "policy_authorization": False}).encode())
            return super()._capture(argv, **bounds)
    result = run(PositivePlan)
    assert result["prerequisites"]["scoped_planning_diagnostic"]["parsed"]["ok"] is True
    assert result["status"] == "native-pre-did-not-request-workspace-containment"
    assert Plane.instances[-1].executions == [] and "route_observations" not in result


def test_missing_pytest_does_not_run_optional_catalog_or_context_diagnostics(run):
    class Missing(Plane):
        pytest_available = False
        def _capture(self, argv, **bounds):
            if control.PYTEST_PROBE not in argv:
                raise AssertionError("optional diagnostic would exceed budget")
            return super()._capture(argv, **bounds)
    result = run(Missing)
    assert result["status"] == "pytest-prerequisite-absent"
    assert set(result["prerequisites"]) == {"pytest"}
    assert result["cleanup_complete"] and "controller_error" not in result


def test_optional_diagnostic_capture_failure_cannot_replace_actual_native_refusal(run):
    class Refused(Plane):
        response: ClassVar = {"decision": "deny", "policy_action": "review"}
        def _capture(self, argv, **bounds):
            if control.PYTEST_PROBE not in argv:
                raise ValueError("product capture exceeded byte budget")
            return super()._capture(argv, **bounds)
    result = run(Refused)
    assert result["status"] == "native-pre-did-not-request-workspace-containment"
    assert result["actual_pre_response"] == Refused.response
    assert result["prerequisites"]["normal_command_inspection"]["available"] is False
    assert "controller_error" not in result and Plane.instances[-1].executions == []


def test_large_inspection_catalog_is_hashed_and_summarized_not_exported():
    class Catalog:
        def _capture(self, argv, **bounds):
            assert bounds["limit"] == 4 * 1024 * 1024
            self.raw = json.dumps({"status": "review", "extensions": [
                {"id": "public-rule", "metadata": "catalog-content-" * 1000} for _ in range(30)]}).encode()
            return SimpleNamespace(returncode=0, stdout=self.raw, stderr=b"")
    plane = Catalog()
    result = control._inspection_summary(plane, Path("/installed/python"))
    assert result["stdout_bytes"] == len(plane.raw) > 262144
    assert len(result["stdout_sha256"]) == 64
    assert len(json.dumps(result)) < 4096
    assert "catalog-content" not in json.dumps(result)


@pytest.mark.parametrize("patch", [
    {"decision": "allow"}, {"policy_action": "review"},
    {"reason_code": "native_command_review_required"},
    {"required_execution_profile": "pytest-readonly-v2"}, {"observe_mode": True},
])
def test_sink_never_runs_without_exact_actual_native_workspace_receipt(run, monkeypatch, patch):
    monkeypatch.setattr(Plane, "response", {**Plane.response, **patch})
    result = run()
    assert result["status"] == "native-pre-did-not-request-workspace-containment"
    assert Plane.instances[-1].executions == []
    assert "route_observations" not in result
    assert not result["containment_conformance_established"]


def test_real_router_consumes_once_and_failure_still_postreviewed(run):
    result = run()
    plane = Plane.instances[-1]
    assert len(plane.executions) == 1
    assert result["replay_rejected"] is True
    assert result["status"] == "native-sink-negative"
    assert [row["kind"] for row in result["route_observations"]] == [
        "contained-route-prepared", "contained-route-consumed", "actual-contained-result"]
    assert plane.hooks[-1]["hook_event_name"] == "PostToolUse"
    assert plane.hooks[-1]["is_error"] is True
    assert plane.hooks[-1]["tool_response"][0]["text"] == "simulated failure"
    assert not result["containment_conformance_established"]


def test_setup_failure_retains_primary_error_and_cleanup(run):
    class Failed(Plane):
        def start(self):
            raise RuntimeError("actual startup failed")
    result = run(Failed)
    assert result["controller_error"] == "actual startup failed"
    assert result["fixture_unchanged"] and result["cleanup_complete"]
    assert result["prerequisites"] == {}


def test_successful_exit_without_actual_artifact_cannot_earn_conformance(run):
    class MissingArtifact(Plane):
        def execute_contained(self, payload, **kwargs):
            self.executions.append(payload)
            return {"exit_code": 0, "stdout": "1 passed", "stderr": ""}
    result = run(MissingArtifact)
    assert result["status"] == "failed-control-retained"
    assert result["exception_type"] == "FileNotFoundError"
    assert not result["containment_conformance_established"]
    assert result["replay_rejected"] and result["cleanup_complete"]


def test_private_product_fixture_not_exported_as_canary_contents(run, monkeypatch):
    monkeypatch.setattr(Plane, "pytest_available", False)
    result = run()
    plane = Plane.instances[-1]
    private = next((plane.root / "guard").iterdir())
    secret = private.read_text()
    assert len(secret) == 64 and secret not in json.dumps(result)
    assert str(private) not in result["dummy_canary_paths"]
    assert "/product/guard/" + private.name in result["dummy_canary_paths"]


def test_artifact_parent_symlink_is_rejected_without_outside_read(tmp_path):
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "contained-observation.json").write_text("outside canary")
    (workspace / "artifacts").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError) as failure:
        control._read_artifact(workspace)
    assert failure.value.errno in (errno.ENOTDIR, errno.ELOOP)


def test_external_anchor_is_stable_and_contains_no_private_signing_material():
    key = Ed25519PrivateKey.generate()
    anchor = control.anchor_record(key, prefix_digest="a" * 64, bwrap_digest="b" * 64)
    assert anchor == control.anchor_record(key, prefix_digest="a" * 64, bwrap_digest="b" * 64)
    assert set(anchor) == {"public_key", "expected_source_sha", "expected_image_id",
                           "expected_prefix_digest", "expected_bwrap_sha256", "qualification_eligible"}
    assert not anchor["qualification_eligible"]


def test_explicit_new_image_pin_binds_preanchor_report_and_actual_plane(run):
    pin = "sha256:" + "c" * 64
    key = Ed25519PrivateKey.generate()
    anchor = control.anchor_record(key, prefix_digest="a" * 64, bwrap_digest="b" * 64, image_id=pin)
    result = run(image_id=pin)
    assert anchor["expected_image_id"] == result["expected_image_id"] == pin
    assert Plane.instances[-1].kwargs["image_id"] == pin
    default = control.anchor_record(key, prefix_digest="a" * 64, bwrap_digest="b" * 64)
    assert default["expected_image_id"] == control.IMAGE


@pytest.mark.parametrize("pin", ["latest", "localhost/pytest:latest", "sha256:abc",
                                 "sha256:" + "A" * 64, "sha256:" + "c" * 64 + "\n", None])
def test_invalid_image_pin_rejected_before_resources_or_anchor(run, pin):
    with pytest.raises(ValueError, match="executor image pin"):
        run(image_id=pin)
    assert Plane.instances == []
    with pytest.raises(ValueError, match="executor image pin"):
        control.anchor_record(Ed25519PrivateKey.generate(), prefix_digest="a" * 64,
                              bwrap_digest="b" * 64, image_id=pin)


def test_actual_plane_image_mismatch_failure_retained_without_sink(run):
    class Mismatched(Plane):
        def start(self):
            raise ValueError("actual image differs from frozen image")
    result = run(Mismatched, image_id="sha256:" + "d" * 64)
    assert result["expected_image_id"] == "sha256:" + "d" * 64
    assert result["controller_error"] == "actual image differs from frozen image"
    assert not result["containment_conformance_established"]
    assert result["cleanup_complete"] and Plane.instances[-1].executions == []
