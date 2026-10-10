"""Fresh Rust coverage cannot qualify stale, foreign or unsuccessful native tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.ci import lcov
from scripts.ci import rust_coverage_report as report

ROOT = Path(__file__).resolve().parents[1]


def coverage_artifact(root: Path, *, absolute: bool = False):
    source = root / "rust/crates/example/src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text("pub fn covered() {}\npub fn uncovered() {}\n", encoding="utf-8")
    directory = root / "rust-coverage"
    directory.mkdir()
    path = directory / report.REPORT
    filename = str(source) if absolute else "rust/crates/example/src/lib.rs"
    path.write_text(
        f"SF:{filename}\nDA:1,4\nDA:2,0\nBRDA:1,0,0,4\nBRDA:1,0,1,0\nend_of_record\n",
        encoding="utf-8",
    )
    expected = {
        "schema": report.SCHEMA,
        "repository": "owner/repo",
        "run_id": 12,
        "attempt": 2,
        "checkout_sha": "a" * 40,
        "toolchain": "rustc 1.88.0 (consumer)",
        "lockfile_hash": "locked",
        "source_tree_hash": "source-tree",
        "llvm_cov_version": "0.6.21",
        "llvm_cov_archive_hash": "coverage-tool",
        "nextest_version": "0.9.100",
        "nextest_archive_hash": "test-tool",
        "profile": dict(report.PROFILE),
        "command": list(report.COMMAND),
        "coverage_target": "rust/target/llvm-cov-target",
    }
    return source, directory, path, expected


def bind_metadata(root: Path, directory: Path, path: Path, expected: dict):
    sources = report.validate_report(path, root)
    (directory / "metadata.json").write_text(
        json.dumps({**expected, "report_hash": report.digest(path), "source_hashes": sources}), encoding="utf-8"
    )


def test_portable_artifact_preserves_covered_uncovered_and_branch_counts(tmp_path, monkeypatch):
    producer = tmp_path / "producer"
    _, directory, _, expected = coverage_artifact(producer, absolute=True)
    for name, value in report.PROFILE.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(report, "identity", lambda root: expected)
    report.bind(producer, directory)
    consumer = tmp_path / "consumer"
    shutil.copytree(producer, consumer)
    path = report.verify(consumer, consumer / "rust-coverage", expected)
    assert path.read_text(encoding="utf-8").splitlines() == [
        "SF:rust/crates/example/src/lib.rs",
        "DA:1,4",
        "DA:2,0",
        "BRDA:1,0,0,4",
        "BRDA:1,0,1,0",
        "end_of_record",
    ]


@pytest.mark.parametrize("changed", ["report", "source"])
def test_report_or_source_tampering_cannot_qualify(tmp_path, changed):
    source, directory, path, expected = coverage_artifact(tmp_path)
    bind_metadata(tmp_path, directory, path, expected)
    if changed == "report":
        path.write_text(path.read_text().replace("DA:2,0", "DA:2,1"), encoding="utf-8")
    else:
        source.write_text("pub fn changed() {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="provenance or digest mismatch"):
        report.verify(tmp_path, directory, expected)


@pytest.mark.parametrize(
    "field",
    [
        "schema",
        "repository",
        "run_id",
        "attempt",
        "checkout_sha",
        "toolchain",
        "lockfile_hash",
        "source_tree_hash",
        "llvm_cov_version",
        "llvm_cov_archive_hash",
        "nextest_version",
        "nextest_archive_hash",
        "profile",
        "command",
        "coverage_target",
    ],
)
def test_artifact_must_match_the_actual_consumer_identity(tmp_path, field):
    _, directory, path, expected = coverage_artifact(tmp_path)
    bind_metadata(tmp_path, directory, path, expected)
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata[field] = "foreign-producer"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance or digest mismatch"):
        report.verify(tmp_path, directory, expected)


@pytest.mark.parametrize("source_name", ["outside.rs", "rust/../outside.rs", "rust/linked.rs"])
def test_sources_cannot_redirect_sonar_outside_the_native_checkout(tmp_path, source_name):
    _, _, path, _ = coverage_artifact(tmp_path)
    outside = tmp_path / "outside.rs"
    outside.write_text("pub fn foreign() {}\n", encoding="utf-8")
    if source_name == "rust/linked.rs":
        (tmp_path / source_name).symlink_to(outside)
    path.write_text(f"SF:{source_name}\nDA:1,1\nend_of_record\n", encoding="utf-8")
    with pytest.raises(ValueError):
        report.validate_report(path, tmp_path)


@pytest.mark.parametrize(
    "data",
    [
        "",
        "DA:1,1\nend_of_record\n",
        "SF:rust/crates/example/src/lib.rs\nDA:1,1\n",
        "SF:rust/crates/example/src/lib.rs\nend_of_record\n",
        "SF:rust/crates/example/src/lib.rs\nDA:1,-1\nend_of_record\n",
    ],
)
def test_invalid_or_partial_lcov_cannot_qualify(tmp_path, data):
    _, _, path, _ = coverage_artifact(tmp_path)
    path.write_text(data, encoding="utf-8")
    with pytest.raises(ValueError):
        report.validate_report(path, tmp_path)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CARGO_PROFILE_TEST_OPT_LEVEL", "0"),
        ("CARGO_PROFILE_TEST_DEBUG_ASSERTIONS", "false"),
        ("CARGO_PROFILE_TEST_OVERFLOW_CHECKS", "false"),
    ],
)
def test_producer_with_different_test_semantics_cannot_bind(tmp_path, monkeypatch, name, value):
    _, directory, _, _ = coverage_artifact(tmp_path)
    for variable, required in report.PROFILE.items():
        monkeypatch.setenv(variable, required)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="required test profile"):
        report.bind(tmp_path, directory)
    assert not (directory / "metadata.json").exists()


def test_failed_native_execution_removes_previous_qualifying_artifact(tmp_path):
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("Rust coverage runs on an Ubuntu Bash runner")
    _, directory, path, expected = coverage_artifact(tmp_path)
    bind_metadata(tmp_path, directory, path, expected)
    script = tmp_path / "scripts/ci/prepare_sonar_rust_coverage.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/ci/prepare_sonar_rust_coverage.sh", script)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name, body in {
        "cargo": "exit 7\n",
        "rustup": "exit 0\n",
        "python3": 'if [[ "$1" == -c ]]; then echo 1.88.0; else echo "$COVERAGE_BIN"; fi\n',
    }.items():
        stub = binaries / name
        stub.write_text(f"#!{bash}\n" + body, encoding="utf-8")
        stub.chmod(0o755)
    result = subprocess.run(
        [bash, str(script)],
        env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"], "COVERAGE_BIN": str(binaries)},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 7, result.stderr
    assert not path.exists()
    assert not (directory / "metadata.json").exists()


def test_lcov_merge_sums_lines_functions_and_branches_without_losing_uncovered_sources(tmp_path):
    first = tmp_path / "nextest.info"
    first.write_text(
        "SF:rust/a.rs\nFN:1,covered\nFNDA:3,covered\nDA:1,3\nDA:2,0\nBRDA:1,0,0,3\nBRDA:1,0,1,-\nend_of_record\n",
        encoding="utf-8",
    )
    second = tmp_path / "consumer.info"
    second.write_text(
        "SF:rust/a.rs\nFN:1,covered\nFN:3,newly_covered\nFNDA:4,covered\nFNDA:2,newly_covered\n"
        "DA:1,4\nDA:3,2\nBRDA:1,0,0,4\nBRDA:1,0,1,0\nBRDA:3,0,0,2\nend_of_record\n"
        "SF:rust/uncovered.rs\nFN:1,uncovered\nFNDA:0,uncovered\nDA:1,0\nBRDA:1,0,0,-\nend_of_record\n",
        encoding="utf-8",
    )
    merged = lcov.merge([first, second])
    records = merged.split("end_of_record\n")
    assert records[0].splitlines() == [
        "SF:rust/a.rs",
        "FN:1,covered",
        "FN:3,newly_covered",
        "FNDA:7,covered",
        "FNDA:2,newly_covered",
        "FNF:2",
        "FNH:2",
        "DA:1,7",
        "DA:2,0",
        "DA:3,2",
        "LF:3",
        "LH:2",
        "BRDA:1,0,0,7",
        "BRDA:1,0,1,0",
        "BRDA:3,0,0,2",
        "BRF:3",
        "BRH:2",
    ]
    assert records[1].splitlines() == [
        "SF:rust/uncovered.rs",
        "FN:1,uncovered",
        "FNDA:0,uncovered",
        "FNF:1",
        "FNH:0",
        "DA:1,0",
        "LF:1",
        "LH:0",
        "BRDA:1,0,0,-",
        "BRF:1",
        "BRH:0",
    ]


@pytest.mark.parametrize(
    "conflict",
    [
        "FN:2,covered\nFNDA:1,covered\n",
        "DA:1,1,another-checksum\n",
        "BRDA:1,0,0,-1\n",
    ],
)
def test_conflicting_or_negative_lcov_cannot_be_merged(tmp_path, conflict):
    first = tmp_path / "first.info"
    first.write_text("SF:rust/a.rs\nFN:1,covered\nFNDA:1,covered\nDA:1,1,checksum\nend_of_record\n")
    second = tmp_path / "second.info"
    second.write_text(f"SF:rust/a.rs\n{conflict}end_of_record\n")
    with pytest.raises(ValueError):
        lcov.merge([first, second])


def complete_shard_selection():
    expected = {"repository": "owner/repo", "run_id": 12, "attempt": 2, "checkout_sha": "a" * 40}
    selection = {
        **expected,
        "schema": report.SHARD_SCHEMA,
        "shards": [
            {
                "shard": index,
                "job_id": index + 100,
                "artifact_id": index + 500,
                "name": f"rust-consumer-coverage-2-3.12-{index}",
            }
            for index in range(report.barrier.SHARD_COUNT)
        ],
    }
    return expected, selection


@pytest.mark.parametrize("boundary", ["missing", "duplicate", "previous-attempt", "foreign-checkout", "foreign-name"])
def test_merged_coverage_requires_every_current_bound_shard(tmp_path, boundary):
    expected, selection = complete_shard_selection()
    if boundary == "missing":
        selection["shards"].pop()
    elif boundary == "duplicate":
        selection["shards"][-1]["artifact_id"] = selection["shards"][0]["artifact_id"]
    elif boundary == "previous-attempt":
        selection["attempt"] = 1
    elif boundary == "foreign-checkout":
        selection["checkout_sha"] = "b" * 40
    else:
        selection["shards"][-1]["name"] = "rust-consumer-coverage-1-3.12-127"
    with pytest.raises(ValueError):
        report.validate_shard_selection(selection, expected)


def test_pinned_toolchain_channel_is_read_only_from_its_own_table(tmp_path):
    directory = tmp_path / "rust"
    directory.mkdir()
    (directory / "rust-toolchain.toml").write_text(
        '[unrelated]\nchannel = "0.0.0"\n[toolchain]\nchannel = "1.88.0" # pinned\nprofile = "minimal"\n',
        encoding="utf-8",
    )
    assert report.toolchain_channel(tmp_path) == "1.88.0"


@pytest.mark.parametrize(
    "config",
    [
        '[unrelated]\nchannel = "1.88.0"\n',
        '[toolchain]\nchannel = "nightly"\n',
        '[toolchain]\nchannel = "1.88.0"\nchannel = "1.89.0"\n',
    ],
)
def test_unpinned_or_ambiguous_toolchain_cannot_qualify(tmp_path, config):
    directory = tmp_path / "rust"
    directory.mkdir()
    (directory / "rust-toolchain.toml").write_text(config, encoding="utf-8")
    with pytest.raises(ValueError):
        report.toolchain_channel(tmp_path)
