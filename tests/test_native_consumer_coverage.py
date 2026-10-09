"""Instrumented coverage consumers must not execute altered or escaped artifacts."""

import json
import os
import subprocess
from copy import deepcopy
from functools import partial
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from scripts.ci import native_consumer_coverage as consumer
from scripts.ci import successful_job_artifact


@pytest.fixture
def bundle(tmp_path: Path, monkeypatch):
    identity = {
        "repository": "hashgraph-online/hol-guard",
        "run_id": 17,
        "attempt": 2,
        "checkout_sha": "a" * 40,
        "source_tree_hash": "b" * 64,
        "package_version": "3.36.1",
    }
    monkeypatch.setattr(consumer, "context", lambda _root: identity)
    directory = tmp_path / "bundle"
    files = {}
    for group, names in (("bin", consumer.BINS), ("tools", consumer.TOOLS)):
        for name in names:
            path = directory / group / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"reviewed native artifact " + name.encode())
            files[path.relative_to(directory).as_posix()] = consumer.coverage.digest(path)
    metadata = {
        **identity,
        "schema": consumer.SCHEMA,
        "profile_pattern": consumer.PROFILE_PATTERN,
        "profile_directory": str(consumer.profiles(tmp_path).resolve()),
        "profile_signatures": {"hol-guard-runtime": "101", "guard-command-source": "202"},
        "files": files,
    }
    (directory / "metadata.json").write_text(json.dumps(metadata))
    return tmp_path, directory, identity, metadata


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


@pytest.fixture
def artifact_consumer(bundle, monkeypatch):
    root, directory, identity, manifest = bundle
    source_names = (
        "rust/crates/example/src/lib.rs",
        "rust/crates/example/src/unused.rs",
    )
    for name in source_names:
        source = root / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("pub fn covered() {}\npub fn uncovered() {}\n", encoding="utf-8")

    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=root, env=git_env, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("-c", "init.templateDir=", "init", "--quiet")
    git("add", "--", "rust")
    git(
        "-c",
        "user.name=Coverage Fixture",
        "-c",
        "user.email=coverage@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "--message=isolated coverage sources",
    )
    identity["checkout_sha"] = git("rev-parse", "HEAD")
    identity["source_tree_hash"] = consumer.coverage.source_tree_hash(root)
    expected = deepcopy(identity)
    manifest.update(expected)
    (directory / "metadata.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(consumer, "context", lambda _root: deepcopy(expected))

    environment = MappingProxyType(
        {
            "GITHUB_REPOSITORY": expected["repository"],
            "GITHUB_RUN_ID": str(expected["run_id"]),
            "GITHUB_RUN_ATTEMPT": str(expected["attempt"]),
            "CI_PYTEST_COVERAGE_SHARDS": "128",
        }
    )
    # Replace the module references, not the process-wide os.environ object.
    local_os = SimpleNamespace(environ=environment, fsdecode=os.fsdecode)
    monkeypatch.setattr(consumer, "os", local_os)
    monkeypatch.setattr(consumer.coverage, "os", local_os)

    run = {
        "id": expected["run_id"],
        "run_attempt": expected["attempt"],
        "head_sha": expected["checkout_sha"],
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-09T12:00:00Z",
        "path": ".github/workflows/ci.yml",
        "repository": {"full_name": expected["repository"]},
    }

    def job(job_id, name):
        return {
            "id": job_id,
            "name": name,
            "run_id": run["id"],
            "run_attempt": expected["attempt"],
            "head_sha": run["head_sha"],
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-10-09T12:00:01Z",
            "started_at": "2026-10-09T12:00:02Z",
            "completed_at": "2026-10-09T12:00:10Z",
        }

    def artifact(artifact_id, name):
        return {
            "id": artifact_id,
            "name": name,
            "expired": False,
            "created_at": "2026-10-09T12:00:07Z",
            "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]},
        }

    jobs = [job(70, consumer.PRODUCER), job(71, "native-command-evaluators")]
    artifacts = [
        artifact(5000, f"{consumer.PREFIX}-2"),
        artifact(5001, f"{consumer.PREFIX}-metadata-2"),
        artifact(6000, "native-command-evaluators-2"),
    ]
    for shard in range(128):
        jobs.append(job(1000 + shard, f"coverage (3.12, {shard})"))
        artifacts.append(artifact(7000 + shard, f"rust-consumer-coverage-2-3.12-{shard}"))

    base = f"/repos/{expected['repository']}/actions/runs/{run['id']}"
    jobs_path = f"{base}/attempts/2/jobs?per_page=100&page="
    artifacts_path = f"{base}/artifacts?per_page=100&page="

    def fetch(path, _timeout_seconds):
        if path == base:
            return deepcopy(run)
        for prefix, field, values in ((jobs_path, "jobs", jobs), (artifacts_path, "artifacts", artifacts)):
            if path.startswith(prefix):
                page = int(path.removeprefix(prefix))
                assert 1 <= page <= 2, "fixture API pagination exceeded its bounded inventory"
                start = (page - 1) * 100
                return {"total_count": len(values), field: deepcopy(values[start : start + 100])}
        raise AssertionError(f"Unexpected fixture API endpoint: {path}")

    def unexpected_poll(_seconds):
        pytest.fail("A complete fixture attempt must qualify or fail without polling")

    monkeypatch.setattr(
        consumer,
        "select",
        partial(successful_job_artifact.select, fetch=fetch, sleep=unexpected_poll),
    )
    monkeypatch.setattr(
        consumer.coverage,
        "select_many",
        partial(successful_job_artifact.select_many, fetch=fetch, sleep=unexpected_poll),
    )
    producer_selection = consumer.selection(root)
    metadata_selection = consumer.selection(root, metadata=True)
    (root / consumer.SELECTION).write_text(json.dumps(producer_selection), encoding="utf-8")
    (root / consumer.METADATA_SELECTION).write_text(json.dumps(metadata_selection), encoding="utf-8")
    authoritative_directory = root / consumer.METADATA_DIRECTORY
    authoritative_directory.mkdir()
    (authoritative_directory / "metadata.json").write_text(json.dumps(manifest), encoding="utf-8")
    shard_selection = consumer.coverage.select_shards(root)
    entitlements = [
        {key: item[key] for key in ("shard", "job_id", "artifact_id")} for item in shard_selection["shards"]
    ]
    sources = consumer.source_snapshot(root)
    zero_lcov = (
        f"SF:{source_names[0]}\nFN:1,covered\nFNDA:0,covered\n"
        "DA:1,0\nDA:2,0\nBRDA:1,0,0,-\nBRDA:1,0,1,0\nend_of_record\n"
        f"SF:{source_names[1]}\nFN:1,unused\nFNDA:0,unused\n"
        "DA:1,0\nBRDA:1,0,0,-\nend_of_record\n"
    )
    shard_directory = root / "downloaded-shards"

    def make_shard(shard, text=zero_lcov):
        output = shard_directory / shard_selection["shards"][shard]["name"]
        output.mkdir(parents=True, exist_ok=True)
        report = output / consumer.coverage.REPORT
        report.write_text(text, encoding="utf-8")
        metadata = {
            **deepcopy(expected),
            "schema": consumer.SHARD_SCHEMA,
            "shard": shard,
            "shard_count": 128,
            "native_manifest": deepcopy(manifest),
            "native_producer": deepcopy(producer_selection["artifact"]),
            "report_hash": consumer.coverage.digest(report),
            "sources": dict(sources),
            "raw_profile_count": 0,
            "profiles": {},
        }
        (output / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        return output, metadata

    return SimpleNamespace(
        root=root,
        bundle_directory=directory,
        expected=expected,
        manifest=manifest,
        jobs=jobs,
        artifacts=artifacts,
        run=run,
        sources=sources,
        source_names=source_names,
        metadata_selection=metadata_selection,
        shard_selection=shard_selection,
        entitlements=entitlements,
        shard_directory=shard_directory,
        zero_lcov=zero_lcov,
        make_shard=make_shard,
    )


def write_metadata(directory, metadata):
    (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


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
def test_shared_selection_requires_entitlement_for_the_last_of_all_128_shards(artifact_consumer, boundary):
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


def test_merging_all_128_empty_profile_shards_preserves_unhit_rust_maps(artifact_consumer, monkeypatch):
    fixture = artifact_consumer
    for shard in range(128):
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


@pytest.mark.parametrize("boundary", ["unbound-signature", "same-profile-in-two-groups"])
def test_profiles_cannot_be_assigned_to_unbound_or_aliased_binary_groups(artifact_consumer, boundary):
    fixture = artifact_consumer
    profile_directory = consumer.profiles(fixture.root)
    profile_directory.mkdir(parents=True)
    if boundary == "unbound-signature":
        (profile_directory / "ci-native-999_0.profraw").write_bytes(b"foreign binary counters")
    else:
        first = profile_directory / "ci-native-101_0.profraw"
        first.write_bytes(b"one physical binary profile")
        os.link(first, profile_directory / "ci-native-202_0.profraw")
    output = fixture.root / "unqualified-export"
    with pytest.raises(ValueError):
        consumer.export_shard(fixture.root, fixture.bundle_directory, output, 0)
    assert not (output / "metadata.json").exists()


@pytest.mark.parametrize("reverse", [False, True], ids=["runtime-first", "command-source-first"])
def test_binary_piece_cannot_borrow_another_binarys_function_definition(tmp_path, reverse):
    runtime = tmp_path / "hol-guard-runtime.lcov"
    command_source = tmp_path / "guard-command-source.lcov"
    runtime.write_text(
        "SF:rust/crates/example/src/lib.rs\nFNDA:7,shared_symbol\nDA:1,7\nend_of_record\n",
        encoding="utf-8",
    )
    command_source.write_text(
        "SF:rust/crates/example/src/lib.rs\nFN:1,shared_symbol\nFNDA:0,shared_symbol\nDA:1,0\nend_of_record\n",
        encoding="utf-8",
    )
    pieces = [runtime, command_source]
    if reverse:
        pieces.reverse()
    with pytest.raises(ValueError):
        consumer.lcov.merge(pieces)


def test_binary_function_counters_may_precede_their_own_definitions(tmp_path):
    pieces = []
    for name, hits in (("hol-guard-runtime", 2), ("guard-command-source", 5)):
        path = tmp_path / f"{name}.lcov"
        path.write_text(
            "SF:rust/crates/example/src/lib.rs\n"
            f"FNDA:{hits},shared_symbol\nFN:1,shared_symbol\nDA:1,{hits}\n"
            "BRDA:1,0,0,-\nend_of_record\n",
            encoding="utf-8",
        )
        pieces.append(path)
    text = consumer.lcov.merge(pieces)
    assert "FN:1,shared_symbol\nFNDA:7,shared_symbol\nFNF:1\nFNH:1\n" in text
    assert "DA:1,7\nLF:1\nLH:1\n" in text
    assert "BRDA:1,0,0,-\nBRF:1\nBRH:0\n" in text
