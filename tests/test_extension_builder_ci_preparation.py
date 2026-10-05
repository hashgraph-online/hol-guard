"""Source-only contributions must not need shared trust-map or main-sync edits."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts import refresh_extension_artifacts as refresh
from scripts.ci import detect_pending_extension_regen as detector

ROOT = Path(__file__).resolve().parents[1]


def write_json(root: Path, relative: str, value: object) -> Path:
    """Write an isolated authored input, never a product or test projection."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """Keep production inputs and the real detector isolated from the tests."""
    trust = write_json(
        tmp_path,
        "contracts/extensions/trust-class-map.v1.json",
        {
            "schemaVersion": "guard.extension-trust-class-map.v1",
            "publishers": {"hol": {"id": "hol"}},
            "classes": {
                "first-party": ["command.git"],
                "trusted-library": ["command.cloud.aws"],
                "external": ["command.existing"],
            },
        },
    )
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "TRUST_MAP", trust)
    monkeypatch.setattr(detector, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_detector", lambda: detector)
    return tmp_path, trust


def add_source(root: Path, identity: str) -> Path:
    """Only identity discovery is exercised here; Rust validates full sources."""
    return write_json(
        root,
        f"contributions/command-sources/{identity}.json",
        {"extension": {"extension_id": identity}},
    )


def test_missing_command_and_mcp_ids_are_external_without_changing_reviewed_classes(checkout):
    root, trust = checkout
    original = json.loads(trust.read_bytes())
    sources = [
        add_source(root, "command.new-cli"),
        add_source(root, "command.git"),
        add_source(root, "command.cloud.aws"),
        write_json(root, "contributions/mcp-servers/mcp.new-server.json", {"id": "mcp.new-server"}),
    ]
    before = {path: path.read_bytes() for path in sources}
    assert refresh.sync_trust_map() is True
    updated = json.loads(trust.read_bytes())
    assert updated["publishers"] == original["publishers"]
    assert updated["classes"] == {
        **original["classes"],
        "external": ["command.existing", "command.mcp-new-server", "command.new-cli"],
    }
    assert all(path.read_bytes() == content for path, content in before.items())
    first = trust.read_bytes()
    assert refresh.sync_trust_map() is False
    assert trust.read_bytes() == first


def test_trust_only_does_not_build_or_read_generated_catalogs(checkout, monkeypatch, capsys):
    root, trust = checkout
    add_source(root, "command.new-cli")

    def unexpected(*args, **kwargs):
        pytest.fail("trust-only staging must not invoke native builds, fixtures, or generated catalogs")

    for name in ("pending_contribution_ids", "regenerate_projections", "refresh_directory_render", "verify", "_run"):
        monkeypatch.setattr(refresh, name, unexpected)
    assert refresh.main(["--trust-only"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "trust_map_changed": True}
    assert "command.new-cli" in json.loads(trust.read_bytes())["classes"]["external"]


def test_malformed_trust_map_is_not_silently_replaced(checkout):
    _, trust = checkout
    trust.write_text("invalid JSON", encoding="utf-8")
    with pytest.raises(ValueError):
        refresh.main(["--trust-only"])
    assert trust.read_text() == "invalid JSON"


def test_stale_contributor_branch_prepares_on_merge_without_rebase(checkout):
    root, trust = checkout

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()

    git("init", "-q", "-b", "main")
    git("config", "user.name", "CI regression")
    git("config", "user.email", "ci@example.invalid")
    for relative in ("scripts/refresh_extension_artifacts.py", "scripts/ci/detect_pending_extension_regen.py"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    git("add", ".")
    git("commit", "-qm", "baseline")
    git("checkout", "-qb", "contributor")
    contribution = write_json(root, "contributions/mcp-servers/mcp.new-server.json", {"id": "mcp.new-server"})
    git("add", ".")
    git("commit", "-qm", "source-only contribution")
    contributor_tip = git("rev-parse", "HEAD")
    git("checkout", "-q", "main")
    add_source(root, "command.unrelated-main")
    git("add", ".")
    git("commit", "-qm", "main advanced independently")
    git("merge", "--no-ff", "-qm", "synthetic PR merge", "contributor")
    completed = subprocess.run(
        [sys.executable, "scripts/refresh_extension_artifacts.py", "--trust-only"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(completed.stdout)["ok"] is True
    assert json.loads(trust.read_bytes())["classes"]["external"] == [
        "command.existing",
        "command.mcp-new-server",
        "command.unrelated-main",
    ]
    assert git("rev-parse", "contributor") == contributor_tip
    assert git("diff", "--name-only") == "contracts/extensions/trust-class-map.v1.json"
    assert json.loads(contribution.read_bytes()) == {"id": "mcp.new-server"}


def test_builder_stages_trust_before_dependency_install_and_native_build():
    workflow = yaml.safe_load((ROOT / ".github/workflows/extension-builder-ci.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert "pull_request" in events and "pull_request_target" not in events
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["authoring"]["steps"]
    checkout_step = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert "ref" not in checkout_step["with"]  # Use GitHub's merge checkout, not the stale PR head.
    trust = next(i for i, step in enumerate(steps) if "--trust-only" in step.get("run", ""))
    install = next(i for i, step in enumerate(steps) if "uv sync" in step.get("run", ""))
    build = next(i for i, step in enumerate(steps) if "cargo build" in step.get("run", ""))
    prepare = next(
        i for i, step in enumerate(steps) if step.get("name") == "Prepare and verify current extension projections"
    )
    tests = next(i for i, step in enumerate(steps) if step.get("name") == "Run builder and contribution trust tests")
    assert trust < install < build < prepare < tests
    assert "continue-on-error" not in steps[trust]
    run = steps[prepare]["run"]
    assert run.count("scripts/prepare_extension_contribution.py") == 2
    assert "scripts/prepare_extension_contribution.py --check" in run
    assert "scripts/render_command_extension_directory.py --check" in run
    assert "verify_native_command_program.py" not in run  # Do not compile/verify the same projections twice.
    for path in (
        "test_guard_extension_trust.py",
        "test_guard_extension_contribution.py",
        "test_guard_mcp_server_contribution.py",
        "test_extension_builder_ci_preparation.py",
    ):
        assert path in steps[tests]["run"]
