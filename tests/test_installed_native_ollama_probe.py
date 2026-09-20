"""Frozen native lifecycle oracles and real local approval/control mutations."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store import GuardStore
from scripts import build_native_qualification_artifacts as builds
from scripts.ci import installed_native_ollama_probe as probe
from scripts.ci import verify_native_ollama_install as driver
from scripts.ci.native_ollama_contract import (
    ACTIVE_CASES,
    INACTIVE_CASES,
    RESTRICTED_CASES,
    OllamaCase,
    validate_review,
)
from scripts.ci.verify_native_ollama_install import builder_evidence
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from tests.test_native_command_observations import _edge, _evidence, _observations, _receipt, _rehash


def _wire(case: OllamaCase) -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    if case.rule is None:
        observations["observations"] = []
        observations["binding"]["observation_count"] = 0
    else:
        item = observations["observations"][0]
        item["rule_id"] = case.rule
        if case.safe_variant:
            item["effective_segment_indexes"] = []
            item["safe_variants"] = [
                {"match_class": "safe-variant", "variant_id": "help", "matcher_evidence": [_evidence()]}
            ]
    if case.uncertainty_rule is not None:
        observations["observations"].append(
            {
                "extension_id": "command.shell-mutations",
                "extension_version": "1.0.0",
                "rule_id": case.uncertainty_rule,
                "rule_version": "1.0.0",
                "match_class": "uncertainty",
                "match_classes": ["unsafe", "uncertainty"],
                "matcher_evidence": [{**_evidence(), "segment_index": 1, "executable": "rm"}],
                "safe_variants": [],
                "uncertainty_reasons": ["matcher-failure"],
                "effective_segment_indexes": [1],
            }
        )
        observations["binding"]["observation_count"] += 1
        observations["binding"]["uncertainty_count"] = 1
    _rehash(observations)
    edge = _edge(observations)
    edge["authority"] = "rust"
    edge["result"].update(minimum_action=case.action, policy_action=case.action, reason_code=case.reason)
    receipt = _receipt(observations)
    receipt.update(policy_action=case.action, reason_code=case.reason)
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge["receipt"] = receipt
    response = {
        "policy_action": case.action,
        "reason_code": case.reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask" if case.action == "review" else "deny",
        },
    }
    if case.action == "review":
        response["approval_request_id"] = "synthetic-approval"
    return edge, response


@pytest.mark.parametrize("case", (*INACTIVE_CASES, *ACTIVE_CASES, *RESTRICTED_CASES), ids=lambda case: case.name)
def test_frozen_installed_oracle_requires_attributed_native_evidence(case: OllamaCase) -> None:
    edge, response = _wire(case)
    expected = edge["result"]["command_extensions"]["binding"]
    assert validate_review(case, edge, response, expected_binding=expected) == edge["receipt"]


@pytest.mark.parametrize(
    "mutation",
    ("wrong_rule", "wrong_revision", "missing_receipt", "wrong_route_authority", "allowed_floor", "wrong_delivery"),
)
def test_native_oracle_rejects_plausible_but_wrong_outcomes(mutation: str) -> None:
    edge, response = _wire(ACTIVE_CASES[0])
    expected = copy.deepcopy(edge["result"]["command_extensions"]["binding"])
    if mutation == "wrong_rule":
        edge["result"]["command_extensions"]["observations"][0]["rule_id"] = "command.ollama.rm"
        _rehash(edge["result"]["command_extensions"])
    elif mutation == "wrong_revision":
        expected["control_revision"] += 1
    elif mutation == "missing_receipt":
        edge.pop("receipt")
    elif mutation == "wrong_route_authority":
        edge["authority"] = "python"
    elif mutation == "allowed_floor":
        edge["result"]["minimum_action"] = "allow"
    else:
        response["hookSpecificOutput"]["permissionDecision"] = "allow"
    with pytest.raises(AssertionError, match="installed_ollama_"):
        validate_review(ACTIVE_CASES[0], edge, response, expected_binding=expected)


@pytest.mark.parametrize("case", (ACTIVE_CASES[0], RESTRICTED_CASES[0]))
def test_legacy_approval_allow_cannot_replace_review_or_independent_block(case) -> None:
    edge, response = _wire(case)
    expected = edge["result"]["command_extensions"]["binding"]
    response.pop("approval_request_id", None)
    response.update(policy_action="allow", approval_reuse_status="accepted")
    response["hookSpecificOutput"]["permissionDecision"] = "allow"
    with pytest.raises(AssertionError, match="installed_ollama_"):
        validate_review(case, edge, response, expected_binding=expected)


@pytest.mark.parametrize("mutation", ("owner", "segment", "extra"))
def test_independent_floor_requires_exact_owned_uncertainty(mutation: str) -> None:
    case = ACTIVE_CASES[-1]
    edge, response = _wire(case)
    observations = edge["result"]["command_extensions"]
    uncertain = observations["observations"][1]
    if mutation == "owner":
        uncertain.update(extension_id="command.other", rule_id="command.other.destructive-shell")
    elif mutation == "segment":
        uncertain["matcher_evidence"][0]["segment_index"] = 0
        uncertain["effective_segment_indexes"] = [0]
    else:
        observations["permission_observations"] = [
            {
                "extension_id": "command.github",
                "permission_id": "command.github.permission.read-remote",
                "matcher_evidence": [],
                "uncertainty_reasons": ["matcher-failure"],
            }
        ]
        observations["binding"]["observation_count"] += 1
        observations["binding"]["uncertainty_count"] += 1
    _rehash(observations)
    edge["receipt"]["command_extensions"] = copy.deepcopy(observations["binding"])
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert validate_native_decision_receipt(edge["receipt"]) == edge["receipt"]
    with pytest.raises(AssertionError, match="installed_ollama_uncertainty_"):
        validate_review(case, edge, response, expected_binding=observations["binding"])


def test_fixture_controls_use_real_password_proofs_and_monotonic_rollback(tmp_path: Path) -> None:
    from scripts.native_slo_command_fixture import prepare_empty_command_authority

    store = GuardStore(tmp_path)
    prepare_empty_command_authority(store)
    password = probe.prepare_fixture_authority(store)
    enabled = probe.control_layer(enabled=True)
    assert probe.commit_controls(store, password, enabled, revision=0) == 1
    assert (
        probe.commit_controls(store, password, probe.control_layer(enabled=True, restrict_push=True), revision=1) == 2
    )
    assert probe.commit_controls(store, password, enabled, revision=2) == 3
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.layers == (enabled,)
    with pytest.raises(ExtensionControlAuthorityError):
        probe.commit_controls(store, password, probe.control_layer(enabled=False), revision=1)
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 3
    with pytest.raises(ApprovalGateError):
        probe.commit_controls(store, "incorrect-synthetic-password", probe.control_layer(enabled=False), revision=3)
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 3


def test_installed_checks_continue_after_a_failed_independent_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> str:
        seen.append(argv)
        if argv == ["paired"]:
            raise subprocess.CalledProcessError(1, argv)
        return ""

    monkeypatch.setattr(builds, "_run", run)
    with pytest.raises(RuntimeError, match="installed qualification failed: paired_sampling"):
        builds._run_required_checks((("paired_sampling", ["paired"]), ("installed_ollama", ["ollama"])), cwd=tmp_path)
    assert seen == [["paired"], ["ollama"]]


def test_builder_qualification_requires_every_witness_and_the_same_wheel() -> None:
    document: dict[str, Any] = {
        "passed": True,
        "sourceFallback": False,
        "guardStateCreated": False,
        "wheelSha256": "a" * 64,
        "builderVersion": "1.0.0",
        "maximumInventory": {"operations": 256},
        "examples": [
            {"kind": kind, "generated": True, "validated": True, "identicalReplay": True, "idempotentApply": True}
            for kind in ("cli", "mcp")
        ],
    }
    assert builder_evidence(document, "a" * 64)["passed"] is True
    assert builder_evidence(document, "b" * 64)["passed"] is False
    for field in ("generated", "validated", "identicalReplay", "idempotentApply"):
        changed = copy.deepcopy(document)
        changed["examples"][0][field] = False
        assert builder_evidence(changed, "a" * 64)["passed"] is False


def test_lifecycle_failure_publishes_identifier_without_private_context() -> None:
    evidence = failure_evidence(AssertionError("installed_ollama_binding_mismatch"))
    assert evidence["reason"] == "installed_ollama_binding_mismatch"
    evidence = failure_evidence(AssertionError("installed_ollama_/private/live-credential"))
    assert evidence["reason"] == "unclassified_failure"
    assert "live-credential" not in json.dumps(evidence)


@pytest.mark.parametrize("failure", ("timeout", "containment", "limit", "identity"))
def test_installed_worker_success_cannot_hide_process_failure_or_wrong_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    expected = {"wheel_sha256": "a" * 64, "build_sha": "b" * 40}
    document = {
        "schema": "hol-guard.installed-native-ollama.v1",
        "passed": True,
        "identity": {"wheel_sha256": ("b" if failure == "identity" else "a") * 64, "build_sha": "b" * 40},
    }

    def run(argv: tuple[str, ...], **kwargs: Any) -> BoundedHookProcessResult:
        assert argv[1] == "-I"
        assert Path(kwargs["cwd"]) != Path.cwd()
        assert kwargs["timeout_seconds"] == 180
        assert kwargs["output_limit"] == 256 * 1024
        assert "PYTHONPATH" not in kwargs["environment"]
        return BoundedHookProcessResult(
            0,
            json.dumps(document),
            output_limit_exceeded=failure == "limit",
            timed_out=failure == "timeout",
            containment_failed=failure == "containment",
            stderr="unpublished fixture context",
        )

    monkeypatch.setattr(driver, "run_isolated_hook_process", run)
    okay, report = driver.installed_native_evidence(tmp_path / "python", expected)
    assert okay is False
    assert "unpublished fixture context" not in json.dumps(report)


def test_builder_runs_when_installed_worker_cannot_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(driver, "_sha256", lambda _: "a" * 64)
    monkeypatch.setattr(driver, "wheel_package_digest", lambda _: "a" * 64)

    def native(*_: Any) -> tuple[bool, dict[str, object]]:
        raise OSError(1, "unpublished fixture context")

    def builder(*_: Any) -> dict[str, object]:
        called.append(True)
        raise RuntimeError("independent fixture failure")

    monkeypatch.setattr(driver, "installed_native_evidence", native)
    monkeypatch.setattr(driver, "verify_builder", builder)
    report = driver.verify(tmp_path / "python", tmp_path / "wheel", tmp_path, "a" * 40)
    assert report["passed"] is False and called == [True]
    assert "native_failure" in report and "builder_failure" in report
    assert "unpublished fixture context" not in json.dumps(report)


@pytest.mark.parametrize("change", [None, "mismatch", "removed", "malformed"])
def test_complete_sanitized_qualification_roundtrip_preserves_exact_build_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str | None
) -> None:
    monkeypatch.setattr(driver, "_sha256", lambda _: "a" * 64)
    monkeypatch.setattr(driver, "wheel_package_digest", lambda _: "a" * 64)

    def worker(argv, **_kwargs):
        expected = json.loads(Path(argv[-1]).read_text())
        assert "source_sha" not in expected and expected["build_sha"] == "b" * 40
        identity = dict(expected)
        if change == "removed":
            identity.pop("build_sha")
        elif change is not None:
            identity["build_sha"] = "c" * 40 if change == "mismatch" else "not_a_commit"
        # Exercise the same child, driver and outer report sanitization boundaries.
        child = assert_privacy_safe(
            {"schema": "hol-guard.installed-native-ollama.v1", "passed": True, "identity": identity}
        )
        return BoundedHookProcessResult(0, json.dumps(child), output_limit_exceeded=False, timed_out=False)

    monkeypatch.setattr(driver, "run_isolated_hook_process", worker)
    monkeypatch.setattr(driver, "verify_builder", lambda *_: {})
    monkeypatch.setattr(driver, "builder_evidence", lambda *_: {"passed": True})
    report = driver.verify(tmp_path / "python", tmp_path / "wheel", tmp_path, "b" * 40)
    assert "native_failure" not in report and report["native"]["passed"] is True
    assert report["passed"] is (change is None), report
    assert report["identity"]["build_sha"] == "b" * 40
    assert "source_sha" not in json.dumps(report)
    if change is None:
        assert report["native"]["identity"]["build_sha"] == "b" * 40


@pytest.mark.parametrize("value", [None, "", "a" * 39, "a" * 41, "g" * 40, "A" * 40, True])
def test_expected_build_identity_requires_an_exact_canonical_commit(value, tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="installed_ollama_build_sha_invalid"):
        driver.installed_native_evidence(tmp_path / "python", {"build_sha": value})


@pytest.mark.parametrize(
    ("snapshot", "elapsed", "last_error", "expected_error"),
    [
        (None, 0.4, "native_policy_snapshot_ack_invalid", "native_policy_snapshot_ack_invalid"),
        (None, 0.01, "private-fixture-diagnostic", "unclassified"),
        (None, 0.0, "native_policy_windows_acl_verify_failed", "unclassified"),
        (None, 0.0, "native_policy_snapshot_generation_lock_timeout", "unclassified"),
        (None, 0.0, "native_policy_windows_acl_not_private:protected=0,count=3", "unclassified"),
        (None, 0.0, "", "none"),
        ({"generation": 2}, 0.425, None, "none"),
    ],
)
def test_readiness_failure_keeps_phase_and_fixed_budget_without_publisher_private_context(
    monkeypatch: pytest.MonkeyPatch, snapshot, elapsed: float, last_error, expected_error: str
) -> None:
    from scripts.native_slo_publisher_diagnostic import publisher_error_diagnostic

    clock = iter((100.0, 100.0 + elapsed))
    calls = []

    def monotonic():
        calls.append("clock")
        return next(clock)

    monkeypatch.setattr(probe.time, "monotonic", monotonic)

    class Publisher:
        @property
        def last_error(self):
            calls.append("last_error")
            return last_error

        @property
        def closed(self):
            calls.append("closed")
            return False

        def is_ready(self):
            calls.append("is_ready")
            return snapshot is not None

    publisher = Publisher()

    def prepare(workspace, *, deadline):
        calls.append("prepare")
        assert workspace == Path("synthetic-workspace")
        assert deadline == 100.0 + probe.MAX_READINESS_P95_MS / 1000
        return snapshot

    worker = SimpleNamespace(prepare_workspace_policy=prepare, policy_snapshot_publisher=publisher)
    session = SimpleNamespace(
        workspace=Path("synthetic-workspace"), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    )
    with pytest.raises(FixtureFailureError) as error:
        probe.ready_binding(session, 1, phase="enabled")
    evidence = failure_evidence(error.value)
    assert evidence["phase"] == "enabled"
    readiness = evidence["readiness"]
    assert readiness == {
        "expected_revision": 1,
        "budget_ms": 400.0,
        "elapsed_ms": round(elapsed * 1000, 3),
        "snapshot_returned": snapshot is not None,
        "budget_exhausted": elapsed > 0.4,
        "publisher_ready_after_failure": snapshot is not None,
        "publisher_closed_after_failure": False,
        "publisher_error": expected_error,
        **publisher_error_diagnostic(last_error),
    }
    assert calls == ["clock", "prepare", "clock", "last_error", "is_ready", "closed"]
    assert_privacy_safe({"native": {"failure": evidence}})
    assert "private-fixture-diagnostic" not in json.dumps(evidence)
    assert "protected=" not in json.dumps(evidence)
    assert evidence["reason"] == "qualification_fixture.installed_ollama_native_readiness_failed"


def test_optional_publisher_diagnostic_failure_keeps_original_readiness_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def diagnostic_failed(_error):
        raise RuntimeError("private diagnostic failure")

    clock = iter((100.0, 100.0))
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(probe, "publisher_error_diagnostic", diagnostic_failed)
    publisher = SimpleNamespace(
        last_error="native_policy_windows_acl_verify_failed", closed=False, is_ready=lambda: False
    )
    worker = SimpleNamespace(
        prepare_workspace_policy=lambda *_args, **_kwargs: None, policy_snapshot_publisher=publisher
    )
    session = SimpleNamespace(
        workspace=Path("synthetic"), daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    )
    with pytest.raises(FixtureFailureError) as caught:
        probe.ready_binding(session, 1, phase="enabled")
    evidence = failure_evidence(caught.value)
    assert evidence["reason"] == "qualification_fixture.installed_ollama_native_readiness_failed"
    assert evidence["readiness"]["elapsed_ms"] == 0.0
    assert evidence["readiness"]["publisher_error"] == "unclassified"
    assert evidence["readiness"]["publisher_error_state"] == "collection_failed"
    assert evidence["readiness"]["budget_exhausted"] is False
