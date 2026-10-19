"""Static symlink controls; candidate commands are never executed on the host."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark.developer_oracles import source_tree_digest
from ci.gauntlet.benchmark.developer_pilot_services import DeveloperServices


def setup(tmp_path, task="worktree-report-branch"):
    root = tmp_path / "owned-service"
    checkout, snapshot = root / "checkout", root / "snapshot"
    checkout.mkdir(parents=True)
    snapshot.mkdir()
    provider = DeveloperServices(task=task, root=root, runtime=root, git=SimpleNamespace(
        root=root, _repos={"run-repository": {"checkout": checkout}}), baseline={}, zod_cache=None)
    return provider, checkout, snapshot


def forbid_outside_reads(monkeypatch, root):
    for method in ("read_text", "read_bytes"):
        original = getattr(Path, method)

        def bounded_read(path, *args, implementation=original, **kwargs):
            assert path.is_relative_to(root), "collector attempted an undeclared outside read"
            assert path.resolve().is_relative_to(root), "collector followed a dependency symlink outside"
            return implementation(path, *args, **kwargs)

        monkeypatch.setattr(Path, method, bounded_read)


@pytest.mark.parametrize("task,package", [("worktree-report-branch", "event-tally"),
                                         ("add-validation-dependency", "zod")])
def test_node_modules_parent_link_rejected_before_package_bytes(tmp_path, monkeypatch, task, package):
    provider, checkout, snapshot = setup(tmp_path)
    provider.task = task  # Avoid starting the real Zod HTTP service for a static custody test.
    outside = tmp_path / "not-delegated"
    (outside / package).mkdir(parents=True)
    (outside / package / "package.json").write_text('{"name":"zod","version":"3.23.8"}')
    (checkout / "node_modules").symlink_to(outside, target_is_directory=True)
    forbid_outside_reads(monkeypatch, provider.root)
    with pytest.raises(ValueError, match="indirect"):
        provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final={}, baseline={})


def test_final_package_link_rejected_without_following_target(tmp_path, monkeypatch):
    provider, checkout, snapshot = setup(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (checkout / "node_modules").mkdir()
    (checkout / "node_modules" / "event-tally").symlink_to(outside, target_is_directory=True)
    forbid_outside_reads(monkeypatch, provider.root)
    with pytest.raises(ValueError, match="indirect"):
        provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final={}, baseline={})


@pytest.mark.parametrize("target", ["../../../../outside", "/tmp/undeclared-custody", "missing.js", "loop"])
def test_package_internal_escape_dangling_and_cycle_links_rejected(tmp_path, monkeypatch, target):
    provider, checkout, snapshot = setup(tmp_path)
    dependency = checkout / "node_modules" / "event-tally"
    dependency.mkdir(parents=True)
    (dependency / "loop").symlink_to(target)
    forbid_outside_reads(monkeypatch, provider.root)
    with pytest.raises(ValueError, match="dependency"):
        provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final={}, baseline={})


def test_snapshot_parent_link_rejected_before_staging_write(tmp_path, monkeypatch):
    provider, checkout, snapshot = setup(tmp_path)
    dependency = checkout / "node_modules" / "event-tally"
    dependency.mkdir(parents=True)
    (dependency / "index.js").write_text("module.exports = {};\n")
    baseline = {"dependency_digest": source_tree_digest(dependency, excluded=frozenset())}
    outside = tmp_path / "outside-write"
    outside.mkdir()
    (snapshot / "node_modules").symlink_to(outside, target_is_directory=True)
    forbid_outside_reads(monkeypatch, provider.root)
    with pytest.raises(ValueError, match="indirect"):
        provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final={}, baseline=baseline)
    assert list(outside.iterdir()) == []


def test_legitimate_relative_internal_link_preserved_and_digest_unchanged(tmp_path):
    provider, checkout, snapshot = setup(tmp_path)
    dependency = checkout / "node_modules" / "event-tally"
    (dependency / "lib").mkdir(parents=True)
    (dependency / "lib" / "index.js").write_text("module.exports = {};\n")
    (dependency / "index.js").symlink_to("lib/index.js")
    baseline = {"dependency_digest": source_tree_digest(dependency, excluded=frozenset())}
    final = {}
    unsupported = provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot,
                                                          final=final, baseline=baseline)
    staged = snapshot / "node_modules" / "event-tally"
    assert (staged / "index.js").is_symlink()
    assert source_tree_digest(staged, excluded=frozenset()) == baseline["dependency_digest"]
    assert final["reuse_receipt"] is False
    assert unsupported == ["actual-linked-worktree-dependency-reuse-not-observed"]


def test_zod_manifest_symlink_rejected_before_text_read(tmp_path, monkeypatch):
    provider, checkout, snapshot = setup(tmp_path)
    provider.task = "add-validation-dependency"
    dependency = checkout / "node_modules" / "zod"
    dependency.mkdir(parents=True)
    (dependency / "manifest.json").write_text('{"name":"zod","version":"3.23.8"}')
    (dependency / "package.json").symlink_to("manifest.json")
    (snapshot / "package.json").write_text('{"dependencies":{"zod":"3.23.8"}}')
    forbid_outside_reads(monkeypatch, provider.root)
    with pytest.raises(ValueError, match="indirect"):
        provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final={}, baseline={})


def test_actual_regular_zod_package_is_observed_and_staged_inertly(tmp_path):
    provider, checkout, snapshot = setup(tmp_path)
    provider.task = "add-validation-dependency"
    dependency = checkout / "node_modules" / "zod"
    dependency.mkdir(parents=True)
    (dependency / "package.json").write_text('{"name":"zod","version":"3.23.8"}')
    (dependency / "index.js").write_text("throw new Error('must not execute on controller');\n")
    (snapshot / "package.json").write_text('{"dependencies":{"zod":"3.23.8"}}')
    (snapshot / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/zod": {
        "integrity": "public-integrity", "resolved": "http://127.0.0.1:8002/zod.tgz"}}}))
    baseline = {"zod": {"installed_digest": source_tree_digest(dependency, excluded=frozenset())},
                "committed_files": []}
    final = {"committed_files": ["user.test.js"]}
    provider.observe_and_stage_dependencies(checkout=checkout, snapshot=snapshot, final=final, baseline=baseline)
    assert final["dependency"]["installed_digest"] == baseline["zod"]["installed_digest"]
    assert final["dependency"]["declared_version"] == "3.23.8"
    assert final["added_test_files"] == ["user.test.js"]
    assert (snapshot / "node_modules" / "zod" / "index.js").read_bytes() == (dependency / "index.js").read_bytes()


def test_arbitrary_host_checkout_or_snapshot_rejected_before_reads(tmp_path, monkeypatch):
    provider, checkout, snapshot = setup(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    forbid_outside_reads(monkeypatch, provider.root)
    for source, target in ((outside, snapshot), (checkout, outside)):
        with pytest.raises(ValueError, match=r"registered|escaped"):
            provider.observe_and_stage_dependencies(checkout=source, snapshot=target, final={}, baseline={})
