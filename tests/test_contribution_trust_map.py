"""Pending contributions cannot change existing trust or activation authority."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci import verify_contribution_trust_map as gate


def _base() -> dict[str, object]:
    return {
        "schemaVersion": "guard.extension-trust-class-map.v1",
        "publishers": {"hol": {"id": "hol", "displayName": "HOL"}},
        "classes": {
            "first-party": ["command.git"],
            "trusted-library": ["command.cloud.aws"],
            "external": ["command.noodle"],
        },
    }


def test_new_cli_and_mcp_contributions_only_add_external_ids() -> None:
    before = _base()
    after = copy.deepcopy(before)
    after["classes"]["external"] += ["command.new-cli", "command.mcp-mail-server"]
    ids = {"command.new-cli", "command.mcp-mail-server"}
    assert set(gate.verify_external_additions(before, after, ids)) == ids
    assert gate.verify_external_additions(before, before, set()) == []


def test_new_source_for_existing_catalog_id_preserves_its_authority() -> None:
    before = _base()
    after = copy.deepcopy(before)
    after["classes"]["external"].append("command.mcp-mail-server")
    assert gate.verify_external_additions(before, after, {"command.git", "command.mcp-mail-server"}) == [
        "command.mcp-mail-server"
    ]


@pytest.mark.parametrize("mutation", ["remove", "promote", "new-first-party", "new-library", "publisher", "schema"])
def test_existing_authority_and_metadata_cannot_change(mutation: str) -> None:
    before = _base()
    after = copy.deepcopy(before)
    after["classes"]["external"].append("command.mcp-mail-server")
    if mutation in {"remove", "promote"}:
        after["classes"]["external"].remove("command.noodle")
        if mutation == "promote":
            after["classes"]["first-party"].append("command.noodle")
    elif mutation.startswith("new-"):
        after["classes"]["external"].remove("command.mcp-mail-server")
        kind = "first-party" if mutation == "new-first-party" else "trusted-library"
        after["classes"][kind].append("command.mcp-mail-server")
    elif mutation == "publisher":
        after["publishers"]["hol"]["displayName"] = "Changed authority"
    else:
        after["schemaVersion"] = "different-schema"
    with pytest.raises(ValueError):
        gate.verify_external_additions(before, after, {"command.mcp-mail-server"})


@pytest.mark.parametrize("mutation", ["unrelated-id", "missing-id", "duplicate", "overlap", "invalid-class"])
def test_external_additions_must_bind_new_canonical_sources(mutation: str) -> None:
    before = _base()
    after = copy.deepcopy(before)
    after["classes"]["external"].append("command.mcp-mail-server")
    if mutation == "unrelated-id":
        after["classes"]["external"].append("command.unrelated")
    elif mutation == "missing-id":
        after["classes"]["external"].remove("command.mcp-mail-server")
    elif mutation == "duplicate":
        after["classes"]["external"].append("command.noodle")
    elif mutation == "overlap":
        after["classes"]["external"].append("command.git")
    else:
        after["classes"]["privileged"] = []
    with pytest.raises(ValueError):
        gate.verify_external_additions(before, after, {"command.mcp-mail-server"})


def test_trust_map_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        gate._object(b'{"classes": {}, "classes": {}}', "fixture")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.PIPE).strip()


def test_cli_binds_external_additions_to_actual_added_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Synthetic Contributor")
    _git(root, "config", "user.email", "synthetic@example.test")
    path = root / gate.TRUST_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_base()))
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "Synthetic base")
    base_sha = _git(root, "rev-parse", "HEAD")
    source = root / "contributions/mcp-servers/mcp.mail-server.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({"id": "mcp.mail-server"}))
    cli_source = root / "contributions/command-sources/command.new-cli.json"
    cli_source.parent.mkdir(parents=True)
    cli_source.write_text(json.dumps({"extension": {"extension_id": "command.new-cli"}}))
    after = _base()
    after["classes"]["external"] += ["command.mcp-mail-server", "command.new-cli"]
    path.write_text(json.dumps(after))
    _git(root, "add", ".")
    monkeypatch.setattr(gate, "ROOT", root)
    monkeypatch.setattr("sys.argv", ["verify", "--changed-from", base_sha])
    assert gate.main() == 0
    assert json.loads(capsys.readouterr().out)["added_external_ids"] == [
        "command.mcp-mail-server",
        "command.new-cli",
    ]
    # A forged ID inside a correctly named source cannot authorize the trust-map entry.
    source.write_text(json.dumps({"id": "mcp.unrelated"}))
    assert gate.main() == 1
    assert "filename/identity mismatch" in capsys.readouterr().err
    monkeypatch.setattr("sys.argv", ["verify", "--changed-from", "0" * 40])
    assert gate.main() == 1
    # An unavailable base never falls back to accepting the head map.
    assert "check failed" in capsys.readouterr().err


def test_builder_workflow_checks_trust_before_regeneration() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/extension-builder-ci.yml").read_text())
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps", [])]
    step = next(item for item in steps if item.get("name") == "Stage external contribution trust defaults")
    script = step["run"]
    assert script.index("refresh_extension_artifacts.py --trust-only") < script.index(
        "verify_contribution_trust_map.py"
    )
    assert '--changed-from "$COMPARISON_BASE"' in script
    assert step["env"]["COMPARISON_BASE"] == "${{ steps.contribution-base.outputs.sha }}"
    assert steps.index(step) < next(
        index for index, item in enumerate(steps) if item.get("name") == "Install the locked development environment"
    )


@pytest.mark.parametrize("mutation", [None, "promote", "remove", "unrelated-id", "new-first-party", "duplicate-key"])
def test_cli_uses_authored_bindings_even_when_published_aggregate_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mutation: str | None
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Synthetic Contributor")
    _git(root, "config", "user.email", "synthetic@example.test")
    bindings = root / gate.TRUST_BINDINGS
    bindings.mkdir(parents=True)

    def binding(identity: str, trust_class: str = "external") -> Path:
        path = bindings / f"{identity}.v1.json"
        path.write_text(
            json.dumps(
                {"schemaVersion": "guard.extension-trust-binding.v1", "extension": identity, "trustClass": trust_class}
            )
        )
        return path

    existing = binding("command.existing")
    binding("command.git", "first-party")
    # Neither the old aggregate nor the head aggregate is an authority input.
    aggregate = root / gate.TRUST_PATH
    aggregate.write_text("stale published projection")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "Synthetic authored base")
    base_sha = _git(root, "rev-parse", "HEAD")
    source = root / "contributions/mcp-servers/mcp.mail-server.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({"id": "mcp.mail-server"}))
    new_binding = binding("command.mcp-mail-server")
    aggregate.write_text("a different stale published projection")
    if mutation == "promote":
        binding("command.existing", "first-party")
    elif mutation == "remove":
        existing.unlink()
    elif mutation == "unrelated-id":
        binding("command.unrelated")
    elif mutation == "new-first-party":
        binding("command.mcp-mail-server", "first-party")
    elif mutation == "duplicate-key":
        new_binding.write_text(
            new_binding.read_text().replace(
                '"trustClass": "external"', '"trustClass": "external", "trustClass": "external"'
            )
        )
    _git(root, "add", ".")
    monkeypatch.setattr(gate, "ROOT", root)
    monkeypatch.setattr("sys.argv", ["verify", "--changed-from", base_sha])
    assert gate.main() == (0 if mutation is None else 1)
    result = capsys.readouterr()
    if mutation is None:
        assert json.loads(result.out)["added_external_ids"] == ["command.mcp-mail-server"]
    else:
        assert "check failed" in result.err
