"""Prevent Python matcher retirement from silently removing native contributor coverage.

The 69 original migration candidates remain pinned by the migration inventory.
For contributed Python extensions, rule IDs are frozen independently here and
their enabled native evaluation is exercised, not merely JSON admission.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.native_command_test_support import real_native_command_evaluation

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "contributions" / "command-sources"
DESCRIPTOR_ROOT = ROOT / "contributions" / "extensions"
TRUST_ROOT = ROOT / "contracts" / "extensions" / "trust"

# Independent pre-retirement rule-ID inventory for contributed Python matchers.
# Changing this list requires evidence of an intentional and reviewed rule migration.
CONTRIBUTOR_RULES = {
    "command.blitcp": (
        "remote-destination",
        "privilege-escalation",
        "self-update",
        "unverified-copy",
    ),
    "command.remote.essh": ("group-execution", "cache-removal"),
    "command.noodle": ("run",),
    "command.ollama": ("push", "rm"),
    "command.probe": (
        "request-run",
        "request-output",
        "request-write",
        "request-delete",
        "folder-write",
        "folder-delete",
        "environment-write",
        "environment-delete",
    ),
    "command.repo2nb": ("reverse-force", "sync"),
    "command.skill-sunset": ("audit",),
    "command.tui-runner": ("reconfigure",),
}

# Each row invokes the compiled native evaluator with the extension enabled.
# It is not a Python-side matcher or a test-only semantic fallback.
ENABLED_CASES = (
    ("command.blitcp", "blitcp /data s3://backups/nightly", "remote-destination"),
    ("command.blitcp", "blitcp --use-sudo /var/lib/data /mnt/backup", "privilege-escalation"),
    ("command.blitcp", "blitcp --update", "self-update"),
    ("command.blitcp", "blitcp --no-verify /data /mnt/backup", "unverified-copy"),
    ("command.remote.essh", "essh run web -- sudo systemctl restart api", "group-execution"),
    ("command.remote.essh", "essh hosts remove web-1", "cache-removal"),
    ("command.noodle", "noodle request run users/get --collection ./my-api --env staging", "run"),
    ("command.ollama", "ollama push my-model", "push"),
    ("command.ollama", "ollama rm llama3", "rm"),
    ("command.probe", "probe request run api.yml items/0", "request-run"),
    ("command.probe", "probe request run api.yml items/0 --output response.json", "request-output"),
    (
        "command.probe",
        "probe request create api.yml --name Health --method GET --url https://api.example.test/health",
        "request-write",
    ),
    ("command.probe", "probe request delete api.yml items/0", "request-delete"),
    ("command.probe", "probe folder create api.yml --name Users", "folder-write"),
    ("command.probe", "probe folder delete api.yml items/0", "folder-delete"),
    ("command.probe", "probe environment create api.yml --name production", "environment-write"),
    ("command.probe", "probe environment delete api.yml --environment production", "environment-delete"),
    ("command.repo2nb", "repo2nb reverse notebook.ipynb --force", "reverse-force"),
    ("command.repo2nb", "repo2nb sync ./my-repo", "sync"),
    ("command.skill-sunset", "skill-sunset audit --codex --open", "audit"),
    ("command.tui-runner", "tui-runner --reconfigure", "reconfigure"),
)

SAFE_CASES = (
    ("command.blitcp", "blitcp --dry-run /data s3://backups/nightly"),
    ("command.remote.essh", "essh hosts list"),
    ("command.noodle", "noodle request run --help"),
    ("command.ollama", "ollama push --help"),
    ("command.probe", "probe request run --help"),
    ("command.repo2nb", "repo2nb sync ./my-repo --dry-run"),
    ("command.skill-sunset", "skill-sunset audit --help"),
    ("command.tui-runner", "tui-runner --help"),
)


def _document(path: Path) -> dict:
    assert path.is_file(), f"lost canonical contributor artifact: {path.relative_to(ROOT)}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _source(extension_id: str) -> dict:
    return _document(SOURCE_ROOT / f"{extension_id}.json")["extension"]


def _active_rule_ids(evaluation: object, extension_id: str) -> set[str]:
    """Only effective native matches enforce a rule; raw observations can be safe."""
    return {
        item.match.rule.rule_id
        for item in evaluation.matches
        if item.extension.extension_id == extension_id
    }


def test_pre_rust_command_extensions_survive_as_source_descriptor_trust_and_native_catalog() -> None:
    """A former Python extension cannot disappear behind an unused JSON file."""
    manifest = _document(SOURCE_ROOT / "migration-manifest.json")
    names = manifest["files"]
    assert manifest["command_sources"] == len(names) == 69
    assert len(set(names)) == len(names)

    for filename in sorted(names):
        assert filename.startswith("command.") and filename.endswith(".json")
        extension_id = filename.removesuffix(".json")
        source = _source(extension_id)
        descriptor = _document(DESCRIPTOR_ROOT / filename)
        trust = _document(TRUST_ROOT / f"{extension_id}.v1.json")
        native = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert source["extension_id"] == descriptor["id"] == trust["extension"] == extension_id
        assert native is not None, f"native catalog lost migrated extension {extension_id}"
        assert descriptor["nativeSource"]["path"] == f"contributions/command-sources/{filename}"
        assert descriptor["trustClass"] == trust["trustClass"] == native.trust_class

        native_rules = {rule.rule_id: rule for rule in native.rules}
        source_rules = {rule["rule_id"]: rule for rule in source["rules"]}
        assert native_rules.keys() == source_rules.keys(), extension_id
        assert {permission.permission_id for permission in native.permissions} == {
            permission["permission_id"] for permission in source["permissions"]
        }, extension_id
        for rule_id, original in source_rules.items():
            projected = native_rules[rule_id]
            assert projected.default_mode == original["default_mode"], rule_id
            assert {variant.variant_id for variant in projected.safe_variants} == {
                variant["variant_id"] for variant in original["safe_variants"]
            }, rule_id


@pytest.mark.parametrize("extension_id,suffixes", sorted(CONTRIBUTOR_RULES.items()))
def test_contributor_rules_keep_native_json_trust_and_opt_in(extension_id: str, suffixes: tuple[str, ...]) -> None:
    """Pin every original contributed rule, not merely the extension name."""
    source = _source(extension_id)
    descriptor = _document(DESCRIPTOR_ROOT / f"{extension_id}.json")
    trust = _document(TRUST_ROOT / f"{extension_id}.v1.json")
    native = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

    expected = {f"{extension_id}.{suffix}" for suffix in suffixes}
    assert {rule["rule_id"] for rule in source["rules"]} == expected
    assert native is not None
    assert {rule.rule_id for rule in native.rules} == expected
    assert native.trust_class == trust["trustClass"] == descriptor["trustClass"] == "external"
    assert native.activation == descriptor["activation"] == "opt-in"
    assert source["required"] is False
    assert descriptor["nativeSource"]["path"] == f"contributions/command-sources/{extension_id}.json"


@pytest.mark.parametrize("extension_id,command,suffix", ENABLED_CASES)
def test_each_contributed_rule_remains_live_in_native_runtime(
    tmp_path: Path, extension_id: str, command: str, suffix: str
) -> None:
    rule_id = f"{extension_id}.{suffix}"
    inert = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
    assert rule_id not in _active_rule_ids(inert, extension_id), rule_id

    enabled = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(("extension", extension_id, "enabled"),),
    ).evaluation
    assert rule_id in _active_rule_ids(enabled, extension_id), (
        extension_id,
        command,
        enabled.command.confidence,
        enabled.command.uncertainty_reason,
        sorted(_active_rule_ids(enabled, extension_id)),
    )


@pytest.mark.parametrize("extension_id,command", SAFE_CASES)
def test_contributor_preview_and_read_only_paths_stay_safe_when_enabled(
    tmp_path: Path, extension_id: str, command: str
) -> None:
    enabled = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(("extension", extension_id, "enabled"),),
    ).evaluation
    assert not _active_rule_ids(enabled, extension_id), (extension_id, command)
