"""Keep contributor contracts while isolating test expectations from generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import build_native_command_program as builder
from scripts import refresh_extension_artifacts as refresh
from scripts.ci.detect_pending_extension_regen import REGEN_OWNED_PATHS
from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_publication_does_not_rewrite_tests_or_rebuild_runtime(tmp_path, monkeypatch):
    """Verify catalog publication does not rewrite tests or rebuild runtime."""
    trust = tmp_path / "contracts/extensions/trust-class-map.v1.json"
    trust.parent.mkdir(parents=True)
    trust.write_text(json.dumps({"classes": {"external": ["command.demo"]}}))
    (trust.parent / "command-catalog.v1.json").write_text(json.dumps({"catalog_digest": "a" * 64}))
    preserved = {}
    for name in (
        "tests/fixtures/command-source-demo.v1.json",
        "tests/fixtures/extension-controls/catalog-baseline.v1.json",
        "contracts/managed-controls/v1/extension-projection-digest-vector.json",
        "tests/test_guard_extension_trust.py",
        "tests/test_policy_bundle_delivery_runtime.py",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"independently reviewed expectation\n")
        preserved[path] = path.read_bytes()
    calls = []
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "TRUST_MAP", trust)
    monkeypatch.setattr(refresh, "contribution_ids", lambda: ["command.demo"])
    monkeypatch.setattr(refresh, "pending_contribution_ids", lambda: [])
    monkeypatch.setattr(refresh, "_run", lambda command, **kwargs: calls.append(command))
    assert refresh.main([]) == 0
    cargo = [command for command in calls if command[0] == "cargo"]
    assert len(cargo) == 1
    assert cargo[0][-2:] == ["--bin", "guard-command-source"]
    assert cargo[0][cargo[0].index("--target-dir") + 1] == str(refresh.TARGET_DIR)
    assert all("hol-guard-runtime" not in command for command in calls)
    assert all(not any("tests/" in part for part in command) for command in calls)
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.parametrize(
    "name",
    [
        "tests/test_guard_extension_trust.py",
        "tests/test_policy_bundle_delivery_runtime.py",
        "contracts/managed-controls/v1/extension-projection-digest-vector.json",
        "tests/fixtures/command-source-new.v1.json",
    ],
)
def test_independent_expectations_are_not_regeneration_owned(name):
    """Verify independent expectations are not regeneration owned."""
    assert name not in REGEN_OWNED_PATHS


def test_native_identity_changes_for_code_but_not_portable_fixture_snapshots(tmp_path, monkeypatch):
    """Verify native identity changes for code but not portable fixture snapshots."""
    inputs = {
        "rust/Cargo.toml": "[workspace]\n",
        "rust/Cargo.lock": "version = 4\n",
        "rust/crates/example/Cargo.toml": "[package]\n",
        "rust/crates/example/src/lib.rs": "pub fn current() {}\n",
        "rust/build_support/command_identity.rs": "// reviewed build identity\n",
        "tests/fixtures/command-source-example.v1.json": "{}\n",
    }
    for name, content in inputs.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    original = builder.implementation_digest()
    (tmp_path / "tests/fixtures/command-source-example.v1.json").write_text('{"changed":true}\n')
    assert builder.implementation_digest() == original
    (tmp_path / "rust/crates/example/src/lib.rs").write_text("pub fn changed() {}\n")
    assert builder.implementation_digest() != original


def test_catalog_and_contributor_interfaces_remain_in_the_repository():
    """Verify catalog and contributor interfaces remain in the repository."""
    for name in (
        "contributions/command-sources/command.noodle.json",
        "contributions/extensions/command.noodle.json",
        "contributions/mcp-servers/mcp.filesystem.json",
        "scripts/intake_contribution_pr.py",
        "scripts/prepare_extension_contribution.py",
        "docs/guard/extensions/catalog.v1.json",
        "docs/guard/extensions/catalog.v2.json",
        "contracts/extensions/command-catalog.v1.json",
        "src/codex_plugin_scanner/guard/contracts/data/extensions/command-catalog.v1.json",
    ):
        assert (ROOT / name).is_file(), name
    source = json.loads((ROOT / "contributions/command-sources/command.noodle.json").read_bytes())
    descriptor = json.loads((ROOT / "contributions/extensions/command.noodle.json").read_bytes())
    assert descriptor["id"] == source["extension"]["extension_id"] == "command.noodle"
    assert descriptor["nativeSource"]["path"] == "contributions/command-sources/command.noodle.json"
    assert descriptor["trustClass"] == "external"
    assert descriptor["activation"] == "opt-in"


def test_authoring_checks_current_resources_before_tests_and_installed_wheel():
    """Verify authoring checks current resources before tests and installed wheel."""
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/extension-builder-ci.yml").read_text()))
    steps = workflow["jobs"]["authoring"]["steps"]
    prepare = next(
        i for i, step in enumerate(steps) if step.get("name") == "Prepare and verify current extension projections"
    )
    tests = next(i for i, step in enumerate(steps) if step.get("name") == "Run builder and contribution trust tests")
    wheel = next(
        i for i, step in enumerate(steps) if step.get("name") == "Build and install a wheel outside the checkout"
    )
    assert prepare < tests < wheel
    script = steps[prepare]["run"]
    assert "--changed-from" in script
    assert "--check" in script
    assert "git checkout" not in script and "git clean" not in script
    assert "if" not in steps[prepare] and not steps[prepare].get("continue-on-error")


def test_historical_implementation_changes_do_not_replace_independent_corpus_inputs(tmp_path, monkeypatch):
    """Verify historical implementation changes do not replace independent corpus inputs."""
    import hashlib

    from tests import guard_command_corpus_native_contract as contract

    corpus = tmp_path / "corpus.json"
    corpus.write_text('{"case":"review-required"}\n')
    (tmp_path / "implementation.rs").write_text("new implementation\n")
    document = {
        "schema": "guard.command-corpus-native-contract.v1",
        "immutable_input_sha256": {"corpus.json": hashlib.sha256(corpus.read_bytes()).hexdigest()},
        "inherited_source_identities": {"sources": {"implementation.rs": {"candidate_sha256": "a" * 64}}},
    }
    manifest = tmp_path / "contract.json"
    manifest.write_text(json.dumps(document))
    monkeypatch.setattr(contract, "ROOT", tmp_path)
    monkeypatch.setattr(contract, "NATIVE_CONTRACT_PATH", manifest)
    contract._contract_data.cache_clear()
    try:
        assert contract.load_native_contract() == document
        corpus.write_text('{"case":"changed"}\n')
        contract._contract_data.cache_clear()
        with pytest.raises(ValueError, match="immutable input changed"):
            contract.load_native_contract()
    finally:
        contract._contract_data.cache_clear()
