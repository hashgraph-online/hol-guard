"""Package evaluation keeps parsing, context, and evidence on identical bytes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import lockfile_parse_result as parser
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime import workspace_path_guard as inputs
from codex_plugin_scanner.guard.runtime.workspace_path_guard import (
    path_exists_within_workspace,
    read_bytes_within_workspace,
    resolve_path_within_workspace,
    workspace_input_snapshot,
)
from codex_plugin_scanner.guard.stable_digest import stable_digest_chunks, stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _artifact_for_targets, _bundle_response, _package


@pytest.mark.parametrize(
    ("name", "source", "decoder"),
    (
        ("package-lock.json", '{"packages":{"node_modules/demo":{"version":"1.0.0"}}}', "json"),
        ("composer.lock", '{"packages":[{"name":"vendor/demo","version":"1.0.0"}]}', "json"),
        ("Pipfile.lock", '{"default":{"demo":{"version":"==1.0.0"}}}', "json"),
        ("Cargo.lock", '[[package]]\nname="demo"\nversion="1.0.0"\n', "toml"),
        ("poetry.lock", '[[package]]\nname="demo"\nversion="1.0.0"\n', "toml"),
        ("uv.lock", '[[package]]\nname="demo"\nversion="1.0.0"\n', "toml"),
        ("bun.lock", '{/* comment */"packages":{"demo":["demo@1.0.0","",{}]},}', "jsonc"),
    ),
)
def test_complete_lockfile_uses_one_document_decode(name, source, decoder, monkeypatch):
    from codex_plugin_scanner.guard.runtime import package_manifest_diff

    module, attribute = (
        ((parser.json, "loads") if decoder == "json" else (parser.tomllib, "loads"))
        if decoder != "jsonc"
        else (parser, "loads_jsonc")
    )
    original = getattr(module, attribute)
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(module, attribute, counted)
    if decoder == "jsonc":
        monkeypatch.setattr(package_manifest_diff, "loads_jsonc", counted)
    result = evaluator._parse_lockfile_text_result(name, source)
    assert result.complete
    assert len(result.entries) == 1
    assert result.entries[0].version == "1.0.0"
    assert calls == 1


def test_snapshot_replacement_deletion_and_nested_evaluation(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    first = b'{"packages":{}}\r\n'
    second = b'{"packages":{"node_modules/new":{"version":"2"}}}'
    path.write_bytes(first)
    with workspace_input_snapshot():
        assert read_bytes_within_workspace(tmp_path, path.name) == first
        path.write_bytes(second)
        assert read_bytes_within_workspace(tmp_path, f"./{path.name}") == first
        with workspace_input_snapshot():
            assert read_bytes_within_workspace(tmp_path, path.name) == second
        path.unlink()
        assert path_exists_within_workspace(tmp_path, path.name)
        assert read_bytes_within_workspace(tmp_path, path.name) == first
    assert not path_exists_within_workspace(tmp_path, path.name)
    assert read_bytes_within_workspace(tmp_path, path.name) is None


def test_snapshot_retains_containment_and_missing_input_state(tmp_path: Path):
    outside = tmp_path.parent / "outside-lockfile.json"
    outside.write_text("{}")
    with workspace_input_snapshot():
        assert resolve_path_within_workspace(tmp_path, "../outside-lockfile.json") is None
        assert read_bytes_within_workspace(tmp_path, "../outside-lockfile.json") is None
        assert not path_exists_within_workspace(tmp_path, "new.lock")
        (tmp_path / "new.lock").write_text("new")
        assert read_bytes_within_workspace(tmp_path, "new.lock") is None
    assert read_bytes_within_workspace(tmp_path, "new.lock") == b"new"


def test_evaluation_context_and_fingerprint_use_the_parsed_bytes(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / "package-lock.json"
    source = json.dumps({"packages": {"node_modules/demo": {"version": "1.0.0"}}}).encode() + b"\r\n"
    replacement = json.dumps({"packages": {"node_modules/demo": {"version": "2.0.0"}}}).encode()
    path.write_bytes(source)
    artifact = _artifact_for_targets("demo@1.0.0", lockfile_paths=(path.name,))
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    response = _bundle_response(
        packages=[_package(ecosystem="npm", name="demo", version="1.0.0", default_action="block")]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    original_parser = evaluator.parse_lockfile_with_budget
    sources = []

    def replace_after_parse(*args, **kwargs):
        result = original_parser(*args, **kwargs)
        sources.append(result.source_hash)
        path.write_bytes(replacement)
        return result

    original_cloud = evaluator._evaluate_with_cloud
    contexts = []
    fingerprints = []

    def capture_context(**kwargs):
        contexts.append(evaluator._lockfile_context(kwargs["workspace_dir"], kwargs["artifact"]))
        fingerprints.append(evaluator._hash_paths(kwargs["workspace_dir"], [path.name]))
        return original_cloud(**kwargs)

    monkeypatch.setattr(evaluator, "parse_lockfile_with_budget", replace_after_parse)
    monkeypatch.setattr(evaluator, "_evaluate_with_cloud", capture_context)
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
    )
    assert result.decision == "block"
    assert sources == [stable_digest_hex(source)]
    assert contexts[0]["lockfileHash"] == stable_digest_hex(source)
    assert fingerprints == [[stable_digest_hex(source)]]
    assert read_bytes_within_workspace(workspace, path.name) == replacement


@pytest.mark.parametrize("chunk_size", (1, 7, 65536))
@pytest.mark.parametrize("length", (0, 1, 63, 64, 65, 1024, 65537))
def test_streaming_source_identity_is_byte_equivalent(chunk_size, length):
    source = (b"a\x00\xff\r\n" * ((length // 5) + 1))[:length]
    chunks = (source[offset : offset + chunk_size] for offset in range(0, len(source), chunk_size))
    assert stable_digest_chunks(chunks) == stable_digest_hex(source)


def test_skipped_binary_lockfile_is_metadata_only(tmp_path, monkeypatch):
    path = tmp_path / "bun.lockb"
    path.write_bytes(b"binary content")
    artifact = _artifact_for_targets("demo", lockfile_paths=(path.name,))

    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("Skipped metadata-only input was opened")

    monkeypatch.setattr(Path, "open", unexpected_open)
    with workspace_input_snapshot():
        assert resolve_path_within_workspace(tmp_path, path.name) == path
        assert path_exists_within_workspace(tmp_path, path.name)
        assert evaluator._lockfile_parse_results(tmp_path, artifact) == ()


def test_oversized_input_streams_exact_hash_without_retaining_content(tmp_path, monkeypatch):
    source = b"x" * 129
    path = tmp_path / "package-lock.json"
    path.write_bytes(source)
    monkeypatch.setattr(inputs, "WORKSPACE_INPUT_MAX_BYTES", 128)
    with workspace_input_snapshot():
        with pytest.raises(inputs.WorkspaceInputSnapshotError) as caught:
            read_bytes_within_workspace(tmp_path, path.name)
        assert caught.value.reason == "byte_limit_exceeded"
        assert caught.value.source_hash == stable_digest_hex(source)
        assert caught.value.bytes_observed == 129
        assert inputs._INPUT_SNAPSHOT.get().retained_bytes == 0


def test_snapshot_aggregate_cap_accepts_boundary_and_rejects_next_input(tmp_path):
    for name, source in (("one", b"1234"), ("two", b"5678"), ("three", b"9")):
        (tmp_path / name).write_bytes(source)
    with workspace_input_snapshot(max_retained_bytes=8):
        assert read_bytes_within_workspace(tmp_path, "one") == b"1234"
        assert read_bytes_within_workspace(tmp_path, "two") == b"5678"
        assert read_bytes_within_workspace(tmp_path, "./one") == b"1234"
        with pytest.raises(inputs.WorkspaceInputSnapshotError) as caught:
            read_bytes_within_workspace(tmp_path, "three")
        assert caught.value.reason == "resource_limit_exceeded"
        assert caught.value.source_hash == stable_digest_hex(b"9")
        assert inputs._INPUT_SNAPSHOT.get().retained_bytes == 8


def test_manifest_resource_failure_pauses_whole_evaluation(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = b'{"dependencies":{"demo":"1.0.0"}}'
    (workspace / "package.json").write_bytes(source)
    artifact = _artifact_for_targets(manifest_paths=("package.json",))
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(evaluator, "workspace_input_snapshot", lambda: workspace_input_snapshot(max_retained_bytes=8))
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
    )
    assert result.policy_action in {"block", "require-reapproval"}
    assert result.packages[0]["lockfileParseError"] == "resource_limit_exceeded"
    assert result.packages[0]["lockfileHash"] == stable_digest_hex(source)
    assert result.packages[0]["inputRetainedByteLimit"] == 8


def test_read_deadline_never_publishes_a_partial_hash_as_complete(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package-lock.json").write_text('{"packages":{}}')
    artifact = _artifact_for_targets("demo@1.0.0", lockfile_paths=("package-lock.json",))
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(inputs, "WORKSPACE_INPUT_READ_BUDGET_SECONDS", -1)
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
    )
    assert result.policy_action == "block"
    assert result.packages[0]["lockfileHashComplete"] is False
    assert result.packages[0]["lockfileParseError"] == "deadline_exceeded"
    assert "source_hash_unavailable" in result.packages[0]["lockfileParseWarnings"]


@pytest.mark.parametrize("name", ("package-lock.json", "poetry.lock"))
def test_every_emitted_dependency_view_respects_entry_limit(name, monkeypatch):
    monkeypatch.setattr(parser, "LOCKFILE_MAX_ENTRIES", 3)
    source = (
        json.dumps({"packages": {}, "dependencies": {f"demo-{i}": {"version": "1"} for i in range(4)}})
        if name == "package-lock.json"
        else ('[[package]]\nname="demo"\nversion="1"\n' * 4)
    )
    result = evaluator._parse_lockfile_text_result(name, source)
    assert not result.complete
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == ()
    assert result.manifest_dependencies is None
    assert result.direct_version_candidates == ()
