"""Offline oracle conformance. Candidate programs are never run on the host.

Behavior rows here are unit inputs to independent predicates, not live worker,
browser, model, or application evidence. Execution requires the declared worker.
"""
from __future__ import annotations

import base64
from dataclasses import replace
from decimal import Decimal
from typing import ClassVar

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_oracles import (
    DEVELOPER_TASKS,
    DeveloperEvidenceError,
    PythonCliInterface,
    TodoUiInterface,
    artifact_checks,
    behavior_checks,
    conversion_cases,
    execute_probe,
    function_cases,
    probe_plan,
    source_tree_digest,
    temperature,
)

TREE = "a" * 64
HEAD = "b" * 40


def test_source_digest_measures_bytes_execute_bits_and_inert_symlink_targets(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    file = source / "app.py"
    file.write_text("inert fixture bytes")
    baseline = source_tree_digest(source)
    file.write_text("changed fixture bytes")
    assert source_tree_digest(source) != baseline
    file.write_text("inert fixture bytes")
    file.chmod(0o755)
    assert source_tree_digest(source) != baseline
    file.chmod(0o644)
    dependencies = source / "node_modules"
    dependencies.mkdir()
    (dependencies / "ignored").write_text("bound separately")
    assert source_tree_digest(source) == baseline
    link = source / "inert-link"
    link.symlink_to("nonexistent-target")
    linked = source_tree_digest(source)
    link.unlink()
    link.symlink_to("other-nonexistent-target")
    assert source_tree_digest(source) != linked


def test_source_measurement_cannot_be_invoked_outside_authenticated_worker():
    from ci.gauntlet.benchmark.developer_worker_probe import measure_source_tree

    with pytest.raises(RuntimeError, match="authenticated isolated worker"):
        measure_source_tree()


def todo():
    return TodoUiInterface("#new", "#add", ".todo", ".title", ".edit", ".editor", ".save", ".toggle", ".delete")


def plan(task):
    return probe_plan(task, candidate_tree_digest=TREE, cli=PythonCliInterface("tempconv.py"), todo=todo(),
                      project_commands=(("/usr/bin/node", "--check", "src/widget.js"),))


def test_all_six_workflows_use_pinned_independent_worker_assets():
    assert len(DEVELOPER_TASKS) == 6
    for task in DEVELOPER_TASKS:
        probe = plan(task)
        assert probe.argv[0] == "/usr/bin/python3"
        assert "--isolation-fd" in probe.argv
        assert probe.record()["candidate_root"] == "/candidate/project"
        assert probe.record()["trusted_root"] == "/trusted/probes"
        assert probe.record()["candidate_uid"] != probe.record()["oracle_uid"]
        assert probe.record()["source_digest_algorithm"] == "sorted-source-inventory.v2"
        assert set(dict(probe.assets)) == {"developer_oracles.py", "contracts.py", "json_data.py", "developer_worker_probe.py",
                                         "developer_node_bridge.mjs", "developer_browser_probe.mjs",
                                         "linux_worker_bootstrap.py", "developer_browser_seccomp.json",
                                         "developer_browser.apparmor", "developer_unittest.py",
                                         "developer_unittest_runner.py", "pytest_cache_metadata.py"}


def test_worker_invocation_refuses_host_fallback_before_any_candidate_process(monkeypatch):
    from ci.gauntlet.benchmark import developer_worker_probe

    def unexpected(*_args, **_kwargs):
        raise AssertionError("candidate process attempted on host")

    monkeypatch.setattr(developer_worker_probe.subprocess, "Popen", unexpected)
    with pytest.raises(RuntimeError, match="bootstrap"):
        developer_worker_probe.run(["/usr/bin/python3", "/candidate/project/tempconv.py"])


def test_missing_interfaces_and_candidate_path_escape_are_explicit_blockers():
    with pytest.raises(DeveloperEvidenceError, match="binding"):
        probe_plan("todo-app-to-github", candidate_tree_digest=TREE)
    with pytest.raises(DeveloperEvidenceError, match="binding"):
        probe_plan("python-cli-with-tests", candidate_tree_digest=TREE)
    with pytest.raises(DeveloperEvidenceError, match="catalog"):
        probe_plan("contributing-pull-request", candidate_tree_digest=TREE)
    with pytest.raises(DeveloperEvidenceError, match="relative"):
        PythonCliInterface("../../operator.py").record()
    with pytest.raises(DeveloperEvidenceError, match="digest"):
        probe_plan("fix-failing-node-test", candidate_tree_digest="agent-claims-pass")


def test_hidden_sum_vectors_reject_original_skip_first_bug_and_constant_answer():
    cases = function_cases("fix-failing-node-test")
    correct = {case["id"]: {"returned": True, "value": sum(case["input"])} for case in cases}
    assert all(behavior_checks("fix-failing-node-test", correct).values())
    wrong = {case["id"]: {"returned": True, "value": sum(case["input"][1:])} for case in cases}
    assert behavior_checks("fix-failing-node-test", wrong)["sum-1"] is False
    constant = {case["id"]: {"returned": True, "value": 6} for case in cases}
    assert not all(behavior_checks("fix-failing-node-test", constant).values())


def test_validation_vectors_reject_identity_validator_and_coercion():
    cases = function_cases("add-validation-dependency")
    reference = {case["id"]: {"accepted": case["valid"]} for case in cases}
    assert all(behavior_checks("add-validation-dependency", reference).values())
    accepts_everything = {case["id"]: {"accepted": True} for case in cases}
    assert not all(behavior_checks("add-validation-dependency", accepts_everything).values())
    coerces_age = {**reference, "user-6": {"accepted": True}}
    assert behavior_checks("add-validation-dependency", coerces_age)["user-6"] is False


def conversions():
    return {case["id"]: ({"exit_code": 0, "value": float(temperature(case["value"], case["from"], case["to"])),
                          "unit": case["to"]} if case["valid"] else {"exit_code": 2, "diagnostic": "invalid input"})
            for case in conversion_cases()}


def test_temperature_oracle_rejects_missing_offset_wrong_direction_unit_and_invalid_exit():
    assert temperature("-40", "C", "F") == Decimal("-40")
    assert temperature("-459.67", "F", "C") == Decimal("-273.15")
    observed = conversions()
    assert all(behavior_checks("python-cli-with-tests", observed).values())
    for changed in ({"value": 0}, {"value": 32, "unit": "C"}, {"value": True}, {"value": float("inf")},
                    {"exit_code": True}):
        assert not behavior_checks("python-cli-with-tests", {
            **observed, "conversion-0": {**observed["conversion-0"], **changed}})["conversion-0"]
    assert not behavior_checks("python-cli-with-tests", {
        **observed, "invalid-0": {"exit_code": 0, "diagnostic": "looks good"}})["invalid-0"]


def test_todo_source_markers_and_forged_agent_pass_cannot_replace_browser_behaviors():
    source_only = {"source": "todo input onclick useState" * 100, "agent_tests_pass": True}
    assert not any(behavior_checks("todo-app-to-github", source_only).values())
    correct = dict.fromkeys(behavior_checks("todo-app-to-github", {}), True)
    assert all(behavior_checks("todo-app-to-github", correct).values())
    no_persistence = {**correct, "reload-preserves-state": False}
    assert not all(behavior_checks("todo-app-to-github", no_persistence).values())
    fake_checkbox = {**correct, "complete": "true"}
    assert behavior_checks("todo-app-to-github", fake_checkbox)["complete"] is False


def test_mutating_original_tests_fails_even_if_candidate_reports_green():
    baseline = {"head": HEAD, "test_files": {"test/sum.test.js": "c" * 64}, "sum_digest": "d" * 64}
    good = {"clean": True, "head": "e" * 40, "committed_files": {
        "test/sum.test.js": "c" * 64, "src/sum.js": "f" * 64}}
    assert all(artifact_checks("fix-failing-node-test", good, baseline).values())
    changed = {**good, "committed_files": {**good["committed_files"], "test/sum.test.js": "weakened-assertions"}}
    assert artifact_checks("fix-failing-node-test", changed, baseline)["seeded-tests-preserved"] is False
    removed = {**good, "committed_files": {"src/sum.js": "f" * 64}}
    assert artifact_checks("fix-failing-node-test", removed, baseline)["seeded-tests-preserved"] is False
    deleted_source = {**good, "committed_files": {"test/sum.test.js": "c" * 64}}
    assert artifact_checks("fix-failing-node-test", deleted_source, baseline)["new-source-commit"] is False


def test_wrong_dependency_provenance_or_uncommitted_lock_fails():
    zod = {"name": "zod", "version": "3.23.8", "integrity": "sha512-pinned", "resolved": "fixture://packages/zod",
           "installed_digest": "c" * 64}
    good = {"clean": True, "head": HEAD, "dependency": zod, "added_test_files": ["test/user.test.js"],
            "committed_files": {name: "d" * 64 for name in ("package.json", "package-lock.json", "src/user.js")}}
    assert all(artifact_checks("add-validation-dependency", good, {"zod": zod}).values())
    for changed in ({"version": "4.0.0"}, {"resolved": "https://foreign.test/zod.tgz"},
                    {"installed_digest": "fake-package"}):
        bad = {**good, "dependency": {**zod, **changed}}
        assert not all(artifact_checks("add-validation-dependency", bad, {"zod": zod}).values())


def test_wrong_report_branch_dependency_replacement_or_main_changes_fail():
    baseline = {"head": HEAD, "dependency_digest": "c" * 64, "expected_report": "# Weekly report\n- signup: 2"}
    good = {"clean": True, "head": "d" * 40, "committed_files": {}, "main_head": HEAD,
            "dependency_digest": "c" * 64, "reuse_receipt": True, "branch": "weekly-report",
            "report": baseline["expected_report"], "branch_parent": HEAD, "owned_worktrees": []}
    assert all(artifact_checks("worktree-report-branch", good, baseline).values())
    for changed in ({"report": "# Weekly report\n- signup: 1"}, {"main_head": "e" * 40},
                    {"owned_worktrees": ["leaked-worktree"]}, {"dependency_digest": "replacement"},
                    {"reuse_receipt": False}):
        assert not all(artifact_checks("worktree-report-branch", {**good, **changed}, baseline).values())


def test_wrong_remote_or_pr_identity_fails_despite_matching_prose():
    baseline = {"repository_id": "owned-repo", "base_branch": "main"}
    good = {"clean": True, "head": HEAD, "committed_files": {"CONTRIBUTING.md": "d" * 64},
            "contributing_document": ("# Setup\nInstall Node.\n# Tests\nRun checks.\n"
                                      "# Contributing\nOpen pull requests."),
            "pull": {"count": 1, "repository_id": "owned-repo", "base": "main", "head_sha": HEAD,
                     "head_branch": "docs", "state": "open"}}
    assert all(artifact_checks("contributing-pull-request", good, baseline).values())
    assert not all(artifact_checks("contributing-pull-request", {**good, "pull": {
        **good["pull"], "repository_id": "foreign"}}, baseline).values())
    assert not artifact_checks("todo-app-to-github", {"clean": True, "head": HEAD}, {})["exact-owned-remote"]


def test_signed_worker_cannot_substitute_host_execution_changed_assets_or_forged_results():
    probe = plan("fix-failing-node-test")
    key = Ed25519PrivateKey.generate()

    def sign(value):
        return base64.b64encode(key.sign(canonical_json(value).encode())).decode()

    class Executor:
        called = False
        platform = "darwin"
        runtime: ClassVar[dict] = {"boot_id": "fixture-boot", "mount_namespace": "mnt:[fixture]",
                                  "pid_namespace": "pid:[fixture]", "network_namespace": "net:[fixture]"}

        def declaration(self):
            declaration = {"schema": "isolated-linux-grader.v1", "worker_id": "worker", "platform": self.platform,
                "isolation": "disposable-vm-and-container", "host_mounts": False, "network": "none",
                "candidate_uid": 10003, "oracle_uid": 10002, "probes_read_only": True,
                "collector_in_candidate_namespace": False, "assets": dict(probe.assets),
                "runtime_identity": self.runtime}
            return {"declaration": declaration, "signature": sign(declaration)}

        def execute(self, _plan):
            self.called = True
            observations = {case["id"]: {"returned": True, "value": sum(case["input"])}
                            for case in function_cases("fix-failing-node-test")}
            payload = {"worker_id": "worker", "plan_digest": probe.digest, "candidate_tree_digest": TREE,
                       "cleanup_complete": True, "timed_out": False, "exit_code": 0, "observations": observations,
                       "runtime_identity": self.runtime, "source_measured": True}
            return {"payload": payload, "signature": sign(payload)}

    executor = Executor()
    with pytest.raises(DeveloperEvidenceError, match="boundaries"):
        execute_probe(probe, executor, worker_public_key=key.public_key().public_bytes_raw())
    assert executor.called is False
    executor.platform = "linux"
    assert all(execute_probe(probe, executor, worker_public_key=key.public_key().public_bytes_raw()).values())
    with pytest.raises(DeveloperEvidenceError, match="assets"):
        execute_probe(replace(probe, assets=(("forged.py", "a" * 64),)), executor,
                      worker_public_key=key.public_key().public_bytes_raw())
    with pytest.raises(InvalidSignature):
        execute_probe(probe, executor, worker_public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw())
