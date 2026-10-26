"""Bind, select and merge complete current-source Rust coverage partitions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from scripts.ci import select_pytest_coverage as provenance
from scripts.ci import wait_for_pytest_shards as api

PARTITIONS = ("core", "command", "runtime-1", "runtime-2")
SCHEMA = "hol-guard.rust-coverage.v1"
REPORT = "rust-lcov.info"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity() -> dict:
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("Invalid Rust coverage source")
    return {"schema": SCHEMA, "source_sha": source, "run_id": int(os.environ["GITHUB_RUN_ID"])}


def validate_report(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size < 64 * 1024 * 1024:
        raise ValueError("Rust coverage must be a bounded regular report")
    content = path.read_text(encoding="utf-8")
    if not re.search(r"^SF:.*\.rs$", content, re.M) or not re.search(r"^DA:[0-9]+,[0-9]+", content, re.M):
        raise ValueError("Rust coverage report is missing source or counters")


def bind(partition: str, directory: Path) -> None:
    report = directory / REPORT
    validate_report(report)
    metadata = {
        **identity(),
        "partition": partition,
        "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "report_sha256": sha256(report),
    }
    (directory / "metadata.json").write_text(json.dumps(metadata, sort_keys=True) + "\n")


def select(repository: str, run_id: int, attempt: int, *, fetch=api.github_json) -> dict:
    if api.REPOSITORY_PATTERN.fullmatch(repository) is None or any(p in {".", ".."} for p in repository.split("/")):
        raise ValueError("Invalid coverage repository")
    if run_id <= 0 or not 1 <= attempt <= provenance.MAX_ATTEMPTS:
        raise ValueError("Invalid coverage run or attempt")
    base = f"/repos/{repository}/actions/runs/{run_id}"
    run = fetch(base, 10.0)
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("path") != provenance.CI_WORKFLOW_PATH
        or not isinstance(run.get("repository"), dict)
        or run["repository"].get("full_name") != repository
        or not isinstance(run.get("head_sha"), str)
        or provenance.SHA.fullmatch(run["head_sha"]) is None
    ):
        raise ValueError("Rust coverage workflow identity mismatch")
    names = frozenset(f"Rust coverage ({p})" for p in PARTITIONS)
    origins = provenance._original_executions(base, run_id, attempt, run["head_sha"], fetch, required=names)
    artifacts = provenance._pages(f"{base}/artifacts", "artifacts", fetch)
    selected = []
    for partition in PARTITIONS:
        origin_attempt, job = origins[f"Rust coverage ({partition})"]
        name = f"rust-coverage-{origin_attempt}-{partition}"
        matches = [artifact for artifact in artifacts if artifact.get("name") == name]
        if not matches:
            raise provenance._InventoryPendingError("Rust coverage artifact inventory is not yet visible")
        if len(matches) != 1:
            raise ValueError("Missing or ambiguous Rust coverage artifact")
        artifact = matches[0]
        source = artifact.get("workflow_run")
        if (
            not isinstance(source, dict)
            or source.get("id") != run_id
            or source.get("head_sha") != run["head_sha"]
            or artifact.get("expired") is not False
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] < 64 * 1024 * 1024
            or not isinstance(artifact.get("digest"), str)
            or provenance.DIGEST.fullmatch(artifact["digest"]) is None
            or not provenance._time(job["started_at"])
            <= provenance._time(artifact.get("created_at"))
            <= provenance._time(job["completed_at"])
        ):
            raise ValueError("Rust coverage artifact does not bind to a successful producer")
        selected.append(
            {
                "partition": partition,
                "name": name,
                "attempt": origin_attempt,
                "artifact_id": artifact["id"],
                "digest": artifact["digest"],
            }
        )
    latest = fetch(base, 10.0)
    if not isinstance(latest, dict) or any(
        latest.get(key) != run.get(key) for key in ("id", "head_sha", "run_attempt", "path")
    ):
        raise ValueError("Coverage workflow changed during selection")
    return {"schema": SCHEMA, "source_sha": run["head_sha"], "run_id": run_id, "partitions": selected}


def select_with_retries(repository: str, run_id: int, attempt: int, *, fetch=api.github_json, sleep=time.sleep) -> dict:
    for retry in range(4):
        try:
            return select(repository, run_id, attempt, fetch=fetch)
        except (api.TransientApiError, provenance._InventoryPendingError):
            if retry == 3:
                raise
            sleep(2**retry)
    raise AssertionError("unreachable")


def merge(selection: dict, directory: Path, output: Path) -> None:
    expected = identity()
    if any(selection.get(key) != value for key, value in expected.items()):
        raise ValueError("Rust coverage selection does not match the analyzed source")
    partitions = selection.get("partitions")
    if not isinstance(partitions, list) or [p.get("partition") for p in partitions] != list(PARTITIONS):
        raise ValueError("Incomplete Rust coverage partition inventory")
    names = {p["name"] for p in partitions}
    if directory.is_symlink() or {p.name for p in directory.iterdir()} != names:
        raise ValueError("Unexpected Rust coverage download inventory")
    reports = []
    for partition in partitions:
        if partition["name"] != f"rust-coverage-{partition['attempt']}-{partition['partition']}":
            raise ValueError("Invalid Rust coverage partition directory")
        parent = directory / partition["name"]
        report, metadata = parent / REPORT, parent / "metadata.json"
        if parent.is_symlink() or metadata.is_symlink() or not metadata.is_file():
            raise ValueError("Missing or linked Rust coverage metadata")
        validate_report(report)
        if json.loads(metadata.read_text()) != {
            **expected,
            "partition": partition["partition"],
            "attempt": partition["attempt"],
            "report_sha256": sha256(report),
        }:
            raise ValueError("Rust coverage report provenance or digest mismatch")
        reports.append(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    # Use the standard LCOV merger, including function and branch counters.
    subprocess.run(
        [
            "lcov",
            "--branch-coverage",
            *[arg for path in reports for arg in ("--add-tracefile", str(path))],
            "--output-file",
            str(output),
        ],
        check=True,
    )
    validate_report(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("bind", "select", "merge"))
    parser.add_argument("partition", nargs="?", choices=PARTITIONS)
    args = parser.parse_args()
    selection = Path("rust-coverage-selection.json")
    if args.operation == "bind":
        if args.partition is None:
            parser.error("bind requires a partition")
        bind(args.partition, Path("coverage-reports") / args.partition)
    elif args.operation == "select":
        result = select_with_retries(
            os.environ["GITHUB_REPOSITORY"], int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
        )
        selection.write_text(json.dumps(result, sort_keys=True) + "\n")
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write("artifact-ids=" + ",".join(str(p["artifact_id"]) for p in result["partitions"]) + "\n")
    else:
        merge(json.loads(selection.read_text()), Path("rust-coverage-data"), Path("coverage-reports/rust-lcov.info"))


if __name__ == "__main__":
    main()
