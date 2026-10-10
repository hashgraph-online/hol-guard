"""Shared fixtures for instrumented native consumer coverage tests."""

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

    # The planned inventory size is import-time state shared with the production
    # selector, so the fixture follows it instead of assuming a fixed count.
    shard_total = consumer.coverage.barrier.SHARD_COUNT
    environment = MappingProxyType(
        {
            "GITHUB_REPOSITORY": expected["repository"],
            "GITHUB_RUN_ID": str(expected["run_id"]),
            "GITHUB_RUN_ATTEMPT": str(expected["attempt"]),
            "CI_PYTEST_COVERAGE_SHARDS": str(shard_total),
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
    for shard in range(shard_total):
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
                assert 1 <= page <= -(-len(values) // 100), "fixture API pagination exceeded its bounded inventory"
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
            "shard_count": shard_total,
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
        shard_total=shard_total,
    )
