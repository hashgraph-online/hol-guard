"""Bind fresh native-required Rust coverage to its successful CI execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from scripts.ci import install_llvm_cov, install_nextest, lcov
from scripts.ci import wait_for_pytest_shards as barrier
from scripts.ci.successful_job_artifact import select, select_many

SCHEMA = "hol-guard.rust-coverage.v1"
REPORT = "rust-lcov.info"
PROFILE_FILENAME = "hol-guard-%2m.profraw"
SHARD_SCHEMA = "hol-guard.rust-consumer-coverage-selection.v1"
SHARD_PREFIX = "rust-consumer-coverage"
PROFILE = {
    "CARGO_PROFILE_TEST_OPT_LEVEL": "1",
    "CARGO_PROFILE_TEST_DEBUG": "0",
    "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS": "true",
    "CARGO_PROFILE_TEST_OVERFLOW_CHECKS": "true",
}
COMMAND = [
    "cargo",
    "llvm-cov",
    "nextest",
    "--locked",
    "--workspace",
    "--all-targets",
    "--no-cfg-coverage",
    "--test-threads",
    "4",
    "--retries",
    "0",
    "--no-fail-fast",
    "--lcov",
    "--output-path",
    "../rust-coverage/rust-lcov.info",
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_hash(root: Path) -> str:
    paths = subprocess.check_output(["git", "ls-files", "-z", "--", "rust"], cwd=root).split(b"\0")
    result = hashlib.sha256()
    for name in sorted(path for path in paths if path):
        source = root / os.fsdecode(name)
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(root.resolve()):
            raise ValueError("Rust build input is missing, linked or outside the checkout")
        result.update(name + b"\0" + digest(source).encode() + b"\n")
    return result.hexdigest()


def toolchain_channel(root: Path) -> str:
    channel = None
    inside = False
    for raw in (root / "rust/rust-toolchain.toml").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if re.fullmatch(r"\[[^\]]+\]\s*(?:#.*)?", line):
            inside = re.fullmatch(r"\[toolchain\]\s*(?:#.*)?", line) is not None
        elif inside and re.match(r"channel\b", line):
            match = re.fullmatch(r"""channel\s*=\s*(["'])(\d+\.\d+\.\d+)\1\s*(?:#.*)?""", line)
            if match is None or channel is not None:
                raise ValueError("Rust toolchain channel must be one pinned version")
            channel = match.group(2)
    if channel is None:
        raise ValueError("Rust toolchain channel is missing")
    return channel


def identity(root: Path) -> dict:
    channel = toolchain_channel(root)
    toolchain = subprocess.check_output(["rustc", f"+{channel}", "--version"], cwd=root, text=True).strip()
    if not toolchain.startswith(f"rustc {channel} "):
        raise ValueError("Rust coverage toolchain is not the pinned Rust version")
    target = install_nextest.host_target()
    return {
        "schema": SCHEMA,
        "repository": os.environ["GITHUB_REPOSITORY"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "checkout_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "toolchain": toolchain,
        "lockfile_hash": digest(root / "rust/Cargo.lock"),
        "source_tree_hash": source_tree_hash(root),
        "llvm_cov_version": install_llvm_cov.VERSION,
        "llvm_cov_archive_hash": install_llvm_cov.CHECKSUMS[target],
        "nextest_version": install_nextest.VERSION,
        "nextest_archive_hash": install_nextest.CHECKSUMS[target],
        "profile": PROFILE,
        "command": [COMMAND[0], f"+{channel}", *COMMAND[1:]],
        "coverage_target": "rust/target/llvm-cov-target",
        "profile_filename": PROFILE_FILENAME,
    }


def validate_report(
    path: Path, root: Path, *, normalize: bool = False, source_hashes: dict[str, str] | None = None
) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Rust coverage report is not a regular file")
    lines = path.read_text(encoding="utf-8").splitlines()
    sources = {}
    source = None
    line_counts = False
    normalized = []
    for line in lines:
        if line.startswith("SF:"):
            if source is not None:
                raise ValueError("Rust coverage record is incomplete")
            raw = line[3:]
            candidate = Path(raw)
            candidate = candidate if candidate.is_absolute() else root / candidate
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError("Rust coverage source is missing or linked")
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root.resolve() / "rust") or resolved.suffix != ".rs":
                raise ValueError("Rust coverage source is outside the native workspace")
            source = resolved.relative_to(root.resolve()).as_posix()
            if not normalize and raw != source:
                raise ValueError("Rust coverage source is not checkout-relative")
            if source_hashes is None:
                sources[source] = digest(resolved)
            else:
                if source not in source_hashes:
                    source_hashes[source] = digest(resolved)
                sources[source] = source_hashes[source]
            line = f"SF:{source}"
        elif line.startswith("DA:"):
            fields = line[3:].split(",")
            if source is None or len(fields) not in {2, 3}:
                raise ValueError("Rust coverage line has no source or invalid counters")
            try:
                number, hits = int(fields[0]), int(fields[1])
            except ValueError as error:
                raise ValueError("Rust coverage line counters are invalid") from error
            if number <= 0 or hits < 0:
                raise ValueError("Rust coverage line counters are invalid")
            line_counts = True
        elif line == "end_of_record":
            if source is None:
                raise ValueError("Rust coverage record has no source")
            source = None
        normalized.append(line)
    if source is not None or not sources or not line_counts:
        raise ValueError("Rust coverage report has no complete source/line coverage")
    if normalize:
        path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
    return sources


def checked_directory(root: Path, directory: Path) -> None:
    if directory.is_symlink() or not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("Rust coverage artifact directory is outside the checkout")


def bind(root: Path, directory: Path) -> None:
    checked_directory(root, directory)
    if any(os.environ.get(name) != value for name, value in PROFILE.items()):
        raise ValueError("Rust coverage producer does not use the required test profile")
    metadata_path = directory / "metadata.json"
    if metadata_path.is_symlink():
        raise ValueError("Rust coverage metadata is linked")
    report = directory / REPORT
    sources = validate_report(report, root, normalize=True)
    metadata = {**identity(root), "report_hash": digest(report), "source_hashes": sources}
    metadata_path.write_text(json.dumps(metadata) + "\n", encoding="utf-8")


def verify(root: Path, directory: Path, expected: dict, *, source_hashes: dict[str, str] | None = None) -> Path:
    checked_directory(root, directory)
    metadata_path = directory / "metadata.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("Missing or linked Rust coverage metadata")
    report = directory / REPORT
    sources = validate_report(report, root, source_hashes=source_hashes)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata != {**expected, "report_hash": digest(report), "source_hashes": sources}:
        raise ValueError("Rust coverage provenance or digest mismatch")
    return report


def select_shards(root: Path) -> dict:
    repository = os.environ["GITHUB_REPOSITORY"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    producers = {
        f"coverage (3.12, {shard})": f"{SHARD_PREFIX}-{attempt}-3.12-{shard}" for shard in range(barrier.SHARD_COUNT)
    }
    selected = select_many(repository, run_id, attempt, producers=producers)
    return {
        "schema": SHARD_SCHEMA,
        "repository": repository,
        "run_id": run_id,
        "attempt": attempt,
        "checkout_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "shards": [
            {
                "shard": shard,
                "job_id": selected[job_name]["job_id"],
                "artifact_id": selected[job_name]["artifact"]["id"],
                "name": producers[job_name],
            }
            for shard, job_name in enumerate(producers)
        ],
    }


def validate_shard_selection(selection: dict, expected: dict) -> list[dict]:
    if (
        selection.get("schema") != SHARD_SCHEMA
        or any(selection.get(field) != expected[field] for field in ("repository", "run_id", "attempt", "checkout_sha"))
        or not isinstance(selection.get("shards"), list)
    ):
        raise ValueError("Rust consumer coverage selection identity mismatch")
    shards = selection["shards"]
    if len(shards) != barrier.SHARD_COUNT or [item.get("shard") for item in shards] != list(range(barrier.SHARD_COUNT)):
        raise ValueError("Rust consumer coverage selection is incomplete")
    for item in shards:
        if item.get("name") != f"{SHARD_PREFIX}-{expected['attempt']}-3.12-{item['shard']}" or any(
            type(item.get(field)) is not int or item[field] <= 0 for field in ("artifact_id", "job_id")
        ):
            raise ValueError("Rust consumer coverage artifact entitlement is invalid")
    if any(len({item[field] for item in shards}) != barrier.SHARD_COUNT for field in ("artifact_id", "job_id")):
        raise ValueError("Rust consumer coverage artifacts or jobs are duplicated")
    return shards


def publish(root: Path, content: bytes) -> Path:
    output = root / "coverage-reports" / REPORT
    checked_directory(root, output.parent)
    output.parent.mkdir(exist_ok=True)
    temporary = output.with_suffix(".tmp")
    if temporary.is_symlink():
        raise ValueError("Rust coverage output temporary is linked")
    temporary.write_bytes(content)
    temporary.replace(output)
    return output


def merge(root: Path, directory: Path, shard_directory: Path, selection_path: Path) -> Path:
    from scripts.ci.native_consumer_coverage import shard_lcov_verifier

    expected = identity(root)
    source_hashes = {}
    nextest_report = verify(root, directory, expected, source_hashes=source_hashes)
    verify_shard = shard_lcov_verifier(root)
    if selection_path.is_symlink() or not selection_path.is_file():
        raise ValueError("Rust consumer coverage selection is missing or linked")
    shards = validate_shard_selection(json.loads(selection_path.read_text(encoding="utf-8")), expected)
    checked_directory(root, shard_directory)
    expected_directories = {item["name"] for item in shards}
    if {path.name for path in shard_directory.iterdir()} != expected_directories:
        raise ValueError("Rust consumer coverage download inventory is incomplete or unexpected")
    reports = [nextest_report]
    inputs = []
    for item in shards:
        artifact_directory = shard_directory / item["name"]
        checked_directory(root, artifact_directory)
        path = verify_shard(
            artifact_directory,
            shard=item["shard"],
            job_id=item["job_id"],
            artifact_id=item["artifact_id"],
        )
        validate_report(path, root, source_hashes=source_hashes)
        reports.append(path)
        inputs.append({**item, "report_hash": digest(path)})
    content = lcov.merge(reports).encode("utf-8")
    if source_tree_hash(root) != expected["source_tree_hash"]:
        raise ValueError("Rust source changed during coverage verification")
    metadata_path = root / "coverage-reports" / "rust-lcov.metadata.json"
    if metadata_path.is_symlink():
        raise ValueError("Merged Rust coverage metadata is linked")
    output = publish(root, content)
    metadata_path.write_text(
        json.dumps(
            {
                "schema": "hol-guard.rust-coverage-merged.v1",
                "source": expected,
                "nextest_report_hash": digest(nextest_report),
                "shards": inputs,
                "report_hash": digest(output),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["bind", "select", "verify", "select-shards", "merge"])
    parser.add_argument("--directory", type=Path, default=Path("rust-coverage"))
    parser.add_argument("--shard-directory", type=Path, default=Path("rust-consumer-coverage"))
    parser.add_argument("--selection", type=Path, default=Path("rust-consumer-coverage-selection.json"))
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if args.operation == "select":
        artifact = select(
            os.environ["GITHUB_REPOSITORY"],
            int(os.environ["GITHUB_RUN_ID"]),
            int(os.environ["GITHUB_RUN_ATTEMPT"]),
            job_name="Rust workspace (test)",
            artifact_prefix="rust-coverage",
        )
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"artifact-id={artifact['id']}\n")
    elif args.operation == "select-shards":
        selection = select_shards(root)
        args.selection.write_text(json.dumps(selection) + "\n", encoding="utf-8")
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write("artifact-ids=" + ",".join(str(item["artifact_id"]) for item in selection["shards"]) + "\n")
    elif args.operation == "bind":
        bind(root, args.directory)
    elif args.operation == "merge":
        merge(root, args.directory, args.shard_directory, args.selection)
    else:
        report = verify(root, args.directory, identity(root))
        publish(root, report.read_bytes())


if __name__ == "__main__":
    main()
