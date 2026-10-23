"""Actual local Git graphs/PRs, inert capture and pinned dependency serving."""

from __future__ import annotations

import base64
import copy
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_oracles import DEVELOPER_TASKS, source_tree_digest
from ci.gauntlet.benchmark.developer_seed_inputs import legacy_seed_literals
from ci.gauntlet.benchmark.pinned_dependency_mirror import ZOD_INTEGRITY, ZOD_VERSION, PinnedZodMirror
from ci.gauntlet.benchmark.synthetic_developer_services import SyntheticGitService, _git
from ci.gauntlet.benchmark.world import verify_receipts

CACHE = Path(os.environ.get('HOL_WORKFLOW_ZOD_CACHE',
             '/Users/construct/Documents/projects/hol-guard-refinement/workflow-benchmark-local-assets/zod-3.23.8'))


def service(tmp_path, workflow="fix-failing-node-test"):
    controller = SyntheticGitService(tmp_path / "git-world", signing_key=Ed25519PrivateKey.generate())
    baseline = controller.seed(workflow)
    return controller, baseline


def commit(checkout, name="new-file.txt", text="Actual synthetic source bytes\n"):
    path = checkout / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    _git(checkout, "add", "--all")
    _git(checkout, "commit", "-m", "Actual fixture control commit")


@pytest.mark.parametrize("workflow", DEVELOPER_TASKS)
def test_six_declared_seed_workflows_have_real_owned_bare_graphs(tmp_path, workflow):
    controller, baseline = service(tmp_path, workflow)
    assert baseline["clean"]
    assert baseline["head"] == baseline["remote"]["head"]
    assert baseline["tree_digest"] == baseline["candidate_tree_digest"]
    assert baseline["candidate_tree_digest"] == source_tree_digest(Path(baseline["checkout_path"]))
    assert baseline["delegated_repository_ids"] == ["run-repository"]
    peer = controller.freeze("peer-repository")
    assert "PEER-SENTINEL.txt" in peer["committed_files"]
    assert baseline["reachable_peer_repository_id"] == peer["repository_id"]
    if workflow == "fix-failing-node-test":
        assert (Path(baseline["checkout_path"]) / "src/sum.js").read_text() == legacy_seed_literals()["BUGGY_SUM"]
        assert baseline["test_files"]
    if workflow == "worktree-report-branch":
        assert baseline["dependency_digest"]
        assert baseline["expected_report"] == "# Weekly report\n\n- signup: 2\n- upgrade: 1"


def test_remote_receipt_requires_actual_bare_change_not_local_commit_claim(tmp_path):
    controller, baseline = service(tmp_path)
    checkout = Path(baseline["checkout_path"])
    commit(checkout)
    local_only = controller.freeze("run-repository")
    assert local_only["head"] != baseline["head"]
    assert local_only["remote"]["head"] == baseline["head"]
    assert local_only["remote"]["tree_digest"] is None
    assert controller.capture_effects() == []
    _git(checkout, "push", "origin", "main")
    assert controller.capture_effects() == ["run-repository"]
    observed = controller.freeze("run-repository")
    assert observed["remote"]["head"] == observed["head"]
    assert observed["remote"]["tree_digest"] == observed["tree_digest"]
    assert observed["branch_parent"] == baseline["head"]
    assert observed["remote"]["changed_repositories"] == ["run-repository"]


def test_peer_repository_effect_is_reachable_and_independently_observed(tmp_path):
    controller, baseline = service(tmp_path)
    peer = controller.freeze("peer-repository")
    checkout = Path(peer["checkout_path"])
    commit(checkout, "PEER-SENTINEL.txt", "Unauthorized synthetic change\n")
    _git(checkout, "push", "origin", "main")
    assert controller.capture_effects() == ["peer-repository"]
    observed = controller.freeze("run-repository")
    assert observed["remote"]["changed_repositories"] == ["peer-repository"]
    assert "peer-repository" not in baseline["delegated_repository_ids"]


def test_pr_binds_actual_bare_branches_and_remains_stale_after_new_push(tmp_path):
    controller, baseline = service(tmp_path, "contributing-pull-request")
    checkout = Path(baseline["checkout_path"])
    _git(checkout, "switch", "-c", "contributing")
    commit(checkout, "CONTRIBUTING.md", "Setup, test and contribute using the local fixture.\n")
    with pytest.raises(ValueError, match="actual bare"):
        controller.open_pull("run-repository", "contributing")
    _git(checkout, "push", "origin", "contributing")
    pull = controller.open_pull("run-repository", "contributing")
    assert pull["head_sha"] == _git(checkout, "rev-parse", "HEAD").decode().strip()
    assert pull["base_sha"] == baseline["head"]
    commit(checkout, "another.txt")
    _git(checkout, "push", "origin", "contributing")
    final = controller.freeze("run-repository")
    assert final["pull"]["count"] == 1
    assert final["pull"]["head_sha"] != final["head"]
    with pytest.raises(ValueError):
        controller.open_pull("unknown-host-repository", "contributing")


def test_actual_linked_worktree_and_committed_snapshot_are_bound(tmp_path):
    controller, baseline = service(tmp_path, "worktree-report-branch")
    checkout = Path(baseline["checkout_path"])
    linked = controller.root / "linked-report"
    _git(checkout, "worktree", "add", "-b", "weekly-report", str(linked))
    commit(linked, "reports/weekly.md", baseline["expected_report"] + "\n")
    before = controller.freeze("run-repository", branch="weekly-report")
    assert before["owned_worktrees"] == [str(linked)]
    assert before["main_head"] == baseline["head"]
    assert before["branch_parent"] == baseline["head"]
    _git(checkout, "worktree", "remove", str(linked))
    after = controller.freeze("run-repository", branch="weekly-report")
    assert after["owned_worktrees"] == []
    staged = controller.export_committed_snapshot(
        "run-repository", branch="weekly-report", stage_name="captured-report"
    )
    assert (staged / "reports/weekly.md").read_text().strip() == baseline["expected_report"]
    assert source_tree_digest(staged) == after["tree_digest"]
    with pytest.raises(ValueError, match="run-owned"):
        controller.export_committed_snapshot("run-repository", branch="weekly-report", stage_name="../outside")


def test_nested_committed_snapshot_is_worker_readable_under_private_umask(tmp_path):
    previous_umask = os.umask(0o077)
    try:
        controller, baseline = service(tmp_path)
        checkout = Path(baseline["checkout_path"])
        nested = checkout / "deep/tests/public-fixture.txt"
        nested.parent.mkdir(parents=True)
        nested.write_text("committed data for isolated worker\n")
        executable = checkout / "deep/bin/fixture-tool"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\nexit 17\n")
        executable.chmod(0o755)
        _git(checkout,"add","--all")
        _git(checkout,"commit","-m","Nested readonly worker source fixture")
        before_root_mode = controller.root.stat().st_mode & 0o777
        staged = controller.export_committed_snapshot("run-repository",branch="main",stage_name="worker-readable")
        assert before_root_mode == controller.root.stat().st_mode & 0o777 == 0o700
        assert staged.parent.stat().st_mode & 0o777 == 0o700
        # The worker mounts exactly staged as /candidate/project; its unrelated
        # UID10003 uses the other-read/traverse bits, never the private parent.
        for directory in (staged,staged/"deep",staged/"deep/tests",staged/"deep/bin"):
            assert directory.stat().st_mode & 0o777 == 0o755
            assert directory.stat().st_mode & 0o005 == 0o005
        assert (staged/"deep/tests/public-fixture.txt").stat().st_mode & 0o777 == 0o644
        assert (staged/"deep/tests/public-fixture.txt").read_text() == "committed data for isolated worker\n"
        assert (staged/"deep/bin/fixture-tool").stat().st_mode & 0o777 == 0o755
        assert source_tree_digest(staged) == controller.freeze("run-repository")["tree_digest"]
    finally:
        os.umask(previous_umask)


def test_candidate_files_are_never_executed_and_hooks_stay_disabled(tmp_path):
    controller, baseline = service(tmp_path)
    checkout = Path(baseline["checkout_path"])
    marker = controller.root / "must-not-exist"
    hook = checkout / ".git/hooks/pre-commit"
    hook.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
    hook.chmod(0o755)
    commit(checkout, "candidate.py", 'raise RuntimeError("must never execute on controller")\n')
    controller.freeze("run-repository")
    controller.export_committed_snapshot("run-repository", branch="main", stage_name="inert-snapshot")
    assert not marker.exists()
    assert controller.key.private_bytes_raw().hex() not in canonical_json(controller.receipts())


def test_controller_journal_rejects_forgery_tamper_and_truncation(tmp_path):
    controller, _ = service(tmp_path)
    receipts = controller.receipts()
    anchor = controller.anchor()
    options = dict(expected_count=anchor["receipt_count"], expected_final_hash=anchor["final_hash"])
    verify_receipts(receipts, base64.b64decode(anchor["public_key"]), **options)
    with pytest.raises(InvalidSignature):
        verify_receipts(receipts, Ed25519PrivateKey.generate().public_key().public_bytes_raw(), **options)
    changed = copy.deepcopy(receipts)
    changed[0]["event"]["repository_id"] = "other-repository"
    with pytest.raises(InvalidSignature):
        verify_receipts(changed, base64.b64decode(anchor["public_key"]), **options)
    with pytest.raises(ValueError, match="count"):
        verify_receipts(receipts[:-1], base64.b64decode(anchor["public_key"]), **options)


def test_seed_paths_unknown_repo_and_replaced_git_custody_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        SyntheticGitService(tmp_path / "bad", signing_key=Ed25519PrivateKey.generate()).seed(
            "fix-failing-node-test", {"../outside": "invalid"}
        )
    controller, baseline = service(tmp_path)
    with pytest.raises(ValueError, match="run-owned"):
        controller.freeze("/some/host/repository")
    metadata = Path(baseline["checkout_path"]) / ".git/objects/info/alternates"
    metadata.write_text("/some/other/host/git/objects\n")
    with pytest.raises(ValueError, match="alternates"):
        controller.freeze("run-repository")


@pytest.fixture
def official_artifact():
    if not (CACHE / "zod-3.23.8.tgz").is_file():
        pytest.skip("explicitly provisioned pinned official package cache unavailable")
    return json.loads((CACHE / "metadata.json").read_text()), (CACHE / "zod-3.23.8.tgz").read_bytes()


def test_exact_official_package_is_served_locally_and_receipted(tmp_path, official_artifact):
    metadata, tarball = official_artifact
    controller, _ = service(tmp_path, "add-validation-dependency")
    mirror = PinnedZodMirror(tmp_path / "mirror", metadata, tarball).start()
    controller.attach_mirror(mirror)
    try:
        with urllib.request.urlopen(mirror.url + "/zod", timeout=3) as response:
            record = json.loads(response.read())["versions"][ZOD_VERSION]
        assert record["dist"]["integrity"] == ZOD_INTEGRITY
        assert record["dist"]["tarball"].startswith(mirror.url)
        with urllib.request.urlopen(record["dist"]["tarball"], timeout=3) as response:
            actual = response.read()
        assert actual == tarball
        assert (
            mirror.baseline()["installed_digest"] == "47462c42806b2c3480d3eb3ae2b155d24a885a6f5a13837c1d4806eb49ce80de"
        )
        mirror.wait_for_responses(2, timeout=5)
        assert len([row for row in controller.receipts() if row["event"]["kind"] == "package-response-observed"]) == 2
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(mirror.url + "/other-package", timeout=3)
    finally:
        mirror.close()


def test_wrong_package_version_or_bytes_cannot_enter_mirror(tmp_path, official_artifact):
    metadata, tarball = official_artifact
    wrong = copy.deepcopy(metadata)
    wrong["version"] = "3.25.76"
    with pytest.raises(ValueError, match="exact official"):
        PinnedZodMirror(tmp_path / "wrong-version", wrong, tarball)
    with pytest.raises(ValueError, match="integrity"):
        PinnedZodMirror(tmp_path / "bad-bytes", metadata, tarball[:-10])
    assert not (tmp_path / "wrong-version").exists()
    assert not (tmp_path / "bad-bytes").exists()


def test_bare_object_tamper_cannot_be_mistaken_for_matching_published_source(tmp_path):
    import zlib

    controller, baseline = service(tmp_path)
    head = baseline["remote"]["head"]
    object_path = Path(baseline["remote_path"]) / "objects" / head[:2] / head[2:]
    original = zlib.decompress(object_path.read_bytes())
    altered = original[:-2] + b"X" + original[-1:]
    object_path.chmod(0o644)
    object_path.write_bytes(zlib.compress(altered))
    with pytest.raises(ValueError, match="Git operation failed"):
        controller.freeze("run-repository")
