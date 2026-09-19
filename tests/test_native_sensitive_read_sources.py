"""Shared identities from the actual normalized sensitive-file request producer."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact

FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-runtime/tests/fixtures/sensitive-read-sources.json"


def produce_sensitive_read(case: dict[str, object]):
    harness = case["harness"]
    assert isinstance(harness, str)
    source = case["source"]
    assert isinstance(source, dict)
    raw = case["payload"]
    assert isinstance(raw, dict)
    home = Path(str(source["home_dir"]))
    workspace = Path(str(source["cwd"]))
    payload = _normalize_hook_payload(raw, harness=harness)
    action = _hook_action_envelope(harness=harness, payload=payload, home_dir=home, workspace=workspace)
    assert action is not None and action.action_type == "file_read"
    artifact = _hook_runtime_artifact(
        harness=harness,
        payload=payload,
        action_envelope=action,
        home_dir=home,
        guard_home=Path(str(source["guard_home"])),
        workspace=workspace,
    )
    assert artifact is not None and artifact.artifact_type == "file_read_request"
    return artifact


def test_shared_sensitive_read_identities_use_actual_hook_producer():
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["contentBinding"] == "request path and tool identity only; no secret file bytes"
    assert len(fixture["cases"]) == 32
    for case in fixture["cases"]:
        artifact = produce_sensitive_read(case)
        assert artifact.artifact_id == case["artifactId"], case["name"]
        assert artifact.metadata["normalized_path"] == case["normalizedPath"], case["name"]
        assert artifact.metadata["path_class"] == case["pathClass"], case["name"]
        assert artifact.command is None and artifact.url is None


def test_supplied_generic_artifact_labels_do_not_replace_sensitive_request_identity():
    case = json.loads(FIXTURE.read_text())["cases"][0]
    original = produce_sensitive_read(case)
    changed: dict[str, object] = {**case, "payload": {**case["payload"], "artifactId": "synthetic:forged"}}
    assert produce_sensitive_read(changed).artifact_id == original.artifact_id


def test_path_identity_does_not_claim_a_secret_file_content_binding(tmp_path: Path):
    case = json.loads(FIXTURE.read_text())["cases"][0]
    case["source"] = {"cwd": str(tmp_path), "home_dir": str(tmp_path), "guard_home": str(tmp_path / "guard")}
    file = tmp_path / ".npmrc"
    file.write_text("SYNTHETIC_FIRST_FILE_CONTENT")
    original = produce_sensitive_read(case)
    file.write_text("SYNTHETIC_REPLACED_FILE_CONTENT")
    changed = produce_sensitive_read(case)
    assert original.artifact_id == changed.artifact_id
    for artifact in (original, changed):
        assert "SYNTHETIC_" not in json.dumps(artifact.metadata)
        assert artifact.metadata["normalized_path"] == str(file)


def test_repeated_slash_home_expansion_requires_its_distinct_producer_contract():
    case = json.loads(FIXTURE.read_text())["cases"][0]
    ordinary = produce_sensitive_read({**case, "payload": {**case["payload"], "tool_input": {"file_path": "~/.npmrc"}}})
    for requested, expected in [("~//.npmrc", "/.npmrc"), ("~///.npmrc", "//.npmrc")]:
        artifact = produce_sensitive_read(
            {**case, "payload": {**case["payload"], "tool_input": {"file_path": requested}}}
        )
        assert artifact.metadata["normalized_path"] == expected
        assert artifact.artifact_id != ordinary.artifact_id
