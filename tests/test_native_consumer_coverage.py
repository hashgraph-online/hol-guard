"""Instrumented coverage consumers must not execute altered or escaped artifacts."""

import json
import os
from copy import deepcopy

import pytest

from scripts.ci import native_consumer_coverage as consumer


def write_metadata(directory, metadata):
    (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


def test_altered_instrumented_executable_is_rejected_before_execution(bundle):
    root, directory, selected, _ = bundle
    (directory / "bin/hol-guard-runtime").write_bytes(b"different executable")
    with pytest.raises(ValueError):
        consumer.verify_bundle(root, directory, selected)


def test_profile_destination_cannot_be_redirected_outside_the_checkout(bundle):
    root, directory, selected, metadata = bundle
    metadata["profile_directory"] = str(root.parent)
    (directory / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        consumer.verify_bundle(root, directory, selected)


def test_stale_attempt_cannot_supply_instrumented_native_code(bundle):
    root, directory, selected, metadata = bundle
    metadata["attempt"] = 1
    (directory / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        consumer.verify_bundle(root, directory, selected)


def test_bundle_parent_symlink_cannot_bless_an_external_native_file(bundle):
    root, directory, selected, _ = bundle
    external = root / "outside-bundle"
    (directory / "bin").rename(external)
    (directory / "bin").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError):
        consumer.verify_bundle(root, directory, selected)


def test_colliding_profile_signatures_cannot_mix_native_code_counters(bundle):
    root, directory, selected, metadata = bundle
    metadata["profile_signatures"] = {name: "101" for name in consumer.BINS}
    (directory / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        consumer.verify_bundle(root, directory, selected)


def test_another_current_successful_producer_cannot_qualify_native_shard(artifact_consumer):
    fixture = artifact_consumer
    directory, metadata = fixture.make_shard(0)
    unrelated = next(item for item in fixture.artifacts if item["id"] == 6000)
    metadata["native_producer"] = {
        "artifact_id": unrelated["id"],
        "name": unrelated["name"],
        "head_sha": unrelated["workflow_run"]["head_sha"],
    }
    write_metadata(directory, metadata)
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(directory, **fixture.entitlements[0])


@pytest.mark.parametrize("boundary", ["failed", "cloned-prior-attempt", "foreign-source"])
def test_factory_rejects_unqualified_current_producer(artifact_consumer, boundary):
    fixture = artifact_consumer
    if boundary == "failed":
        fixture.jobs[0]["conclusion"] = "failure"
    elif boundary == "cloned-prior-attempt":
        fixture.jobs[0].update(
            created_at="2026-10-08T12:00:01Z",
            started_at="2026-10-08T12:00:01Z",
            completed_at="2026-10-08T12:00:10Z",
        )
    else:
        fixture.artifacts[0]["workflow_run"]["head_sha"] = "f" * 40
    with pytest.raises(ValueError):
        consumer.shard_lcov_verifier(fixture.root)


@pytest.mark.parametrize("boundary", ["artifact-id", "source-revision"])
def test_downloaded_authority_must_be_the_current_metadata_artifact(artifact_consumer, boundary):
    fixture = artifact_consumer
    selection = deepcopy(fixture.metadata_selection)
    if boundary == "artifact-id":
        selection["artifact"]["id"] = 4001
    else:
        selection["artifact"]["workflow_run"]["head_sha"] = "f" * 40
    (fixture.root / consumer.METADATA_SELECTION).write_text(json.dumps(selection), encoding="utf-8")
    with pytest.raises(ValueError):
        consumer.shard_lcov_verifier(fixture.root)


@pytest.mark.parametrize("boundary", ["files", "profile_directory", "profile_signatures"])
def test_each_shard_must_match_downloaded_authoritative_native_manifest(artifact_consumer, boundary):
    fixture = artifact_consumer
    directory, metadata = fixture.make_shard(0)
    native = metadata["native_manifest"]
    if boundary == "files":
        native["files"]["tools/llvm-cov"] = "f" * 64
    elif boundary == "profile_directory":
        native["profile_directory"] = str(fixture.root / "other-profile-source-root")
    else:
        native["profile_signatures"][consumer.BINS[1]] = "303"
    write_metadata(directory, metadata)
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(directory, **fixture.entitlements[0])


@pytest.mark.parametrize("boundary", ["report", "tracked-source"])
def test_consumer_rejects_corrupted_report_or_tracked_source_bytes(artifact_consumer, boundary):
    fixture = artifact_consumer
    directory, _metadata = fixture.make_shard(0)
    if boundary == "report":
        report = directory / consumer.coverage.REPORT
        report.write_text(report.read_text().replace("DA:2,0", "DA:2,7"), encoding="utf-8")
    else:
        source = fixture.root / fixture.source_names[0]
        source.write_text("pub fn substituted() {}\n", encoding="utf-8")
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(directory, **fixture.entitlements[0])


@pytest.mark.parametrize("boundary", ["report-symlink", "report-hardlink", "metadata-symlink"])
def test_linked_shard_files_cannot_qualify_even_with_identical_bytes(artifact_consumer, boundary):
    fixture = artifact_consumer
    directory, _metadata = fixture.make_shard(0)
    name = "metadata.json" if boundary == "metadata-symlink" else consumer.coverage.REPORT
    target = directory / name
    outside = fixture.root / "identical-bytes-outside-shard"
    target.rename(outside)
    if boundary == "report-hardlink":
        os.link(outside, target)
    else:
        target.symlink_to(outside)
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(directory, **fixture.entitlements[0])


def test_tracked_source_parent_link_cannot_escape_rust_workspace(artifact_consumer):
    fixture = artifact_consumer
    directory, _metadata = fixture.make_shard(0)
    source_directory = (fixture.root / fixture.source_names[0]).parent
    outside = fixture.root / "identical-sources-outside-rust"
    source_directory.rename(outside)
    source_directory.symlink_to(outside, target_is_directory=True)
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(directory, **fixture.entitlements[0])


def test_rejected_shard_cannot_poison_git_tracked_source_authority(artifact_consumer):
    fixture = artifact_consumer
    untracked_name = "rust/crates/example/src/untracked.rs"
    untracked = fixture.root / untracked_name
    untracked.write_text("pub fn not_in_the_checkout() {}\n", encoding="utf-8")
    text = fixture.zero_lcov + f"SF:{untracked_name}\nDA:1,9\nend_of_record\n"
    first, _first_metadata = fixture.make_shard(0, text)
    second, second_metadata = fixture.make_shard(1, text)
    second_metadata["sources"][untracked_name] = consumer.coverage.digest(untracked)
    write_metadata(second, second_metadata)
    verifier = consumer.shard_lcov_verifier(fixture.root)
    with pytest.raises(ValueError):
        verifier(first, **fixture.entitlements[0])
    with pytest.raises(ValueError):
        verifier(second, **fixture.entitlements[1])


@pytest.mark.parametrize("boundary", ["failed", "cloned-prior-attempt", "foreign-source", "pre-execution-artifact"])
def test_shared_selection_requires_entitlement_for_the_last_of_all_planned_shards(artifact_consumer, boundary):
    fixture = artifact_consumer
    final_job = fixture.jobs[-1]
    final_artifact = fixture.artifacts[-1]
    if boundary == "failed":
        final_job["conclusion"] = "failure"
    elif boundary == "cloned-prior-attempt":
        final_job.update(
            created_at="2026-10-08T12:00:01Z",
            started_at="2026-10-08T12:00:01Z",
            completed_at="2026-10-08T12:00:10Z",
        )
    elif boundary == "foreign-source":
        final_artifact["workflow_run"]["head_sha"] = "f" * 40
    else:
        final_artifact["created_at"] = "2026-10-09T12:00:01Z"
    with pytest.raises(ValueError):
        consumer.coverage.select_shards(fixture.root)


def test_merging_all_planned_empty_profile_shards_preserves_unhit_rust_maps(artifact_consumer, monkeypatch):
    fixture = artifact_consumer
    for shard in range(fixture.shard_total):
        fixture.make_shard(shard)
    rust_expected = {"schema": consumer.coverage.SCHEMA, **fixture.expected}
    monkeypatch.setattr(consumer.coverage, "identity", lambda _root: deepcopy(rust_expected))
    directory = fixture.root / "rust-coverage"
    directory.mkdir()
    report = directory / consumer.coverage.REPORT
    nextest_lcov = (
        fixture.zero_lcov.replace("FNDA:0,covered", "FNDA:3,covered")
        .replace("DA:1,0", "DA:1,3", 1)
        .replace("BRDA:1,0,0,-", "BRDA:1,0,0,3", 1)
    )
    report.write_text(nextest_lcov, encoding="utf-8")
    write_metadata(
        directory,
        {
            **rust_expected,
            "report_hash": consumer.coverage.digest(report),
            "source_hashes": dict(fixture.sources),
        },
    )
    selection_path = fixture.root / "selected-rust-shards.json"
    selection_path.write_text(json.dumps(fixture.shard_selection), encoding="utf-8")

    consumer.coverage.merge(fixture.root, directory, fixture.shard_directory, selection_path)

    text = (fixture.root / "coverage-reports" / consumer.coverage.REPORT).read_text(encoding="utf-8")
    unused = next(record for record in text.split("end_of_record") if f"SF:{fixture.source_names[1]}\n" in record)
    assert "FNDA:0,unused\n" in unused
    assert "FNF:1\nFNH:0\n" in unused
    assert "DA:1,0\nLF:1\nLH:0\n" in unused
    assert "BRDA:1,0,0,-\nBRF:1\nBRH:0\n" in unused
    covered = next(record for record in text.split("end_of_record") if f"SF:{fixture.source_names[0]}\n" in record)
    assert "DA:1,3\nDA:2,0\nLF:2\nLH:1\n" in covered
    assert "BRDA:1,0,0,3\nBRDA:1,0,1,0\nBRF:2\nBRH:1\n" in covered
    assert consumer.coverage.verify(fixture.root, directory, rust_expected) == report
