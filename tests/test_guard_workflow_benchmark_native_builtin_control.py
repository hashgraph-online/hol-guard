"""Control setup and failure retention; no simulated product efficacy credit."""
from pathlib import Path

from ci.gauntlet.benchmark import native_builtin_control as module


class FailedPlane:
    cleanup_complete = False
    def __init__(self, **kwargs):
        self.kwargs = kwargs
    def start(self):
        raise RuntimeError("primary actual namespace startup failure")
    def close(self):
        self.cleanup_complete = True
    def declaration(self):
        return {"cleanup_complete":self.cleanup_complete,"kind":"planning-only"}


def test_control_seed_has_real_declared_python_node_entrypoints_with_owner_floor(tmp_path, monkeypatch):
    owners = []
    monkeypatch.setattr(module.os, "chown", lambda path,uid,gid: owners.append((path,uid,gid)))
    workspace = tmp_path / "workspace"
    module.seed_workspace(workspace)
    assert len(owners) == 4 and all(uid == gid == 10001 for _,uid,gid in owners)
    assert all(path.stat().st_mode & 0o022 == 0 for path,_,_ in owners)
    assert "unittest" in (workspace / "tests/test_control.py").read_text()
    assert "node:test" in (workspace / "tests/control.test.js").read_text()
    assert module.COMMANDS[0][1] == "python3 -m unittest discover -s tests -v"
    assert module.COMMANDS[1][1] == "node --test tests/control.test.js"


def test_primary_setup_failure_retains_public_fixture_and_cleanup_without_sdk_claim(tmp_path, monkeypatch):
    monkeypatch.setattr(module.os, "chown", lambda *args: None)
    report = module.run_control(root=tmp_path / "fresh",python=Path("/installed/.venv/bin/python"),
        prefix_digest="a"*64,bwrap_digest="b"*64,plane_factory=FailedPlane)
    assert report["controller_error"] == "primary actual namespace startup failure"
    assert report["cleanup_complete"] is True and report["calls"] == []
    assert report["physical_before"] == report["physical_after"]
    assert report["sdk_bridge_exercised"] is False and report["model_exercised"] is False
    assert report["containment_conformance_established"] is False
    assert not any("root-private-control" in str(value) for value in report.values())


def test_reused_control_root_does_not_read_previous_workspace(tmp_path, monkeypatch):
    def fail(*args):
        raise AssertionError("outside read")
    monkeypatch.setattr(module, "fixture_observation", fail)
    report = module.run_control(root=tmp_path,python=Path("/installed/.venv/bin/python"),
        prefix_digest="a"*64,bwrap_digest="b"*64,plane_factory=FailedPlane)
    assert report["exception_type"] == "FileExistsError"
    assert "physical_after_error" not in report and "physical_after" not in report


def test_final_control_fixture_parent_symlink_cannot_make_root_read_outside(tmp_path, monkeypatch):
    monkeypatch.setattr(module.os, "chown", lambda *args: None)
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    module.seed_workspace(workspace)
    outside.mkdir()
    (outside / "test_control.py").write_text("root-canary")
    (workspace / "tests").rename(workspace / "original")
    (workspace / "tests").symlink_to(outside,target_is_directory=True)
    import pytest
    with pytest.raises(OSError):
        module.fixture_observation(workspace)
