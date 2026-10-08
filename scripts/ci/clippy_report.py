"""Bind strict Clippy output to one successful current-attempt execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from scripts.ci import wait_for_pytest_shards as barrier
from scripts.ci.select_pytest_coverage import _pages, _time

COMMAND = [
    "cargo",
    "clippy",
    "--manifest-path",
    "rust/Cargo.toml",
    "--locked",
    "--workspace",
    "--all-targets",
    "--message-format=json",
    "--",
    "-D",
    "warnings",
]
SCHEMA = "hol-guard.clippy-report.v1"
TOOLCHAIN = "1.88.0"
REPORT = "clippy.jsonl"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(root: Path) -> dict:
    toolchain = subprocess.check_output(["rustc", "--version"], cwd=root, text=True).strip()
    if not toolchain.startswith(f"rustc {TOOLCHAIN} "):
        raise ValueError("Clippy toolchain is not the pinned Rust version")
    return {
        "schema": SCHEMA,
        "repository": os.environ["GITHUB_REPOSITORY"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "checkout_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "toolchain": toolchain,
        "lockfile_hash": digest(root / "rust/Cargo.lock"),
        "command": COMMAND,
    }


def validate_report(path: Path, root: Path, *, normalize: bool = False) -> None:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 64 * 1024 * 1024:
        raise ValueError("Missing, linked, empty or oversized Clippy report")
    messages = []
    finished = False
    for line in path.read_text().splitlines():
        item = json.loads(line)
        if not isinstance(item, dict) or finished:
            raise ValueError("Invalid Clippy JSON stream")
        if item.get("reason") == "build-finished":
            if item.get("success") is not True:
                raise ValueError("Clippy build did not succeed")
            finished = True
        elif item.get("reason") == "compiler-message":
            message = item.get("message")
            if not isinstance(message, dict) or message.get("level") in {"warning", "error", "failure-note"}:
                raise ValueError("Strict Clippy report contains a failed diagnostic")

            def spans(node: dict) -> None:
                if not isinstance(node.get("spans"), list) or not isinstance(node.get("children"), list):
                    raise ValueError("Invalid compiler diagnostic")
                for span in node["spans"]:
                    filename = span.get("file_name") if isinstance(span, dict) else None
                    if not isinstance(filename, str) or not filename or "\\" in filename:
                        raise ValueError("Invalid diagnostic filename")
                    candidate = Path(filename)
                    if not normalize and (candidate.is_absolute() or ".." in candidate.parts):
                        raise ValueError("Non-repository diagnostic filename")
                    if not candidate.is_absolute():
                        candidate = root / candidate
                        if normalize and not candidate.exists():
                            candidate = root / "rust" / filename
                    resolved = candidate.resolve()
                    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                        raise ValueError("Diagnostic span is outside the checkout")
                    if normalize:
                        span["file_name"] = resolved.relative_to(root.resolve()).as_posix()
                    expansion = span.get("expansion")
                    if expansion is not None:
                        if not isinstance(expansion, dict):
                            raise ValueError("Invalid diagnostic expansion")
                        for key in ("span", "def_site_span"):
                            nested = expansion.get(key)
                            if nested is not None:
                                spans({"spans": [nested], "children": []})
                for child in node["children"]:
                    if not isinstance(child, dict):
                        raise ValueError("Invalid diagnostic child")
                    spans(child)

            spans(message)
        elif item.get("reason") not in {"compiler-artifact", "build-script-executed"}:
            raise ValueError("Unknown Clippy JSON message")
        messages.append(item)
    if not finished:
        raise ValueError("Clippy report has no successful build-finished record")
    if normalize:
        path.write_text("".join(json.dumps(item) + "\n" for item in messages))


def bind(root: Path, directory: Path) -> None:
    validate_report(directory / REPORT, root, normalize=True)
    metadata = identity(root)
    metadata["report_hash"] = digest(directory / REPORT)
    (directory / "metadata.json").write_text(json.dumps(metadata) + "\n")


def verify(root: Path, directory: Path, expected: dict) -> None:
    if directory.is_symlink() or not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("Clippy artifact directory is outside the checkout")
    metadata_path = directory / "metadata.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError("Missing or linked Clippy metadata")
    metadata = json.loads(metadata_path.read_text())
    if metadata != {**expected, "report_hash": digest(directory / REPORT)}:
        raise ValueError("Clippy report provenance or digest mismatch")
    validate_report(directory / REPORT, root)


def select(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    fetch=barrier.github_json,
    clock=time.monotonic,
    sleep=time.sleep,
    timeout=960.0,
) -> dict:
    if barrier.REPOSITORY_PATTERN.fullmatch(repository) is None or any(p in {".", ".."} for p in repository.split("/")):
        raise ValueError("Invalid repository")
    if run_id <= 0 or attempt <= 0:
        raise ValueError("Invalid run identity")
    base = f"/repos/{repository}/actions/runs/{run_id}"
    deadline = clock() + timeout
    while clock() < deadline:
        run = fetch(base, 10.0)
        if (
            not isinstance(run, dict)
            or run.get("id") != run_id
            or run.get("run_attempt") != attempt
            or run.get("path") != ".github/workflows/ci.yml"
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != repository
        ):
            raise ValueError("Workflow run identity changed")
        jobs = [
            job
            for job in _pages(f"{base}/attempts/{attempt}/jobs", "jobs", fetch)
            if job.get("name") == "Rust workspace (clippy)"
        ]
        if len(jobs) > 1:
            raise ValueError("Ambiguous Clippy producer")
        if not jobs:
            if run.get("status") == "completed":
                raise ValueError("Current attempt has no Clippy producer")
            sleep(5.0)
            continue
        job = jobs[0]
        if (
            job.get("run_id") != run_id
            or job.get("run_attempt") != attempt
            or job.get("head_sha") != run.get("head_sha")
        ):
            raise ValueError("Clippy producer identity mismatch")
        if barrier._job_state(job, "Clippy producer") != "success":
            sleep(5.0)
            continue
        barrier._require_current_execution(job, "Clippy producer")
        name = f"clippy-report-{attempt}"
        artifacts = [item for item in _pages(f"{base}/artifacts", "artifacts", fetch) if item.get("name") == name]
        if not artifacts:
            sleep(5.0)
            continue
        if len(artifacts) != 1:
            raise ValueError("Ambiguous Clippy artifact")
        artifact = artifacts[0]
        source = artifact.get("workflow_run")
        if (
            not isinstance(source, dict)
            or source.get("id") != run_id
            or source.get("head_sha") != run.get("head_sha")
            or artifact.get("expired") is not False
            or not _time(job["started_at"]) <= _time(artifact.get("created_at")) <= _time(job["completed_at"])
        ):
            raise ValueError("Clippy artifact is not bound to the successful execution")
        return artifact
    raise ValueError("Timed out waiting for current-attempt Clippy report")


def print_diagnostics(directory: Path) -> None:
    report = directory / "clippy.jsonl"
    if directory.is_symlink() or report.is_symlink() or not report.is_file():
        raise ValueError("Clippy diagnostic report is not a regular file")
    with report.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid Clippy diagnostic JSON at line {number}", file=sys.stderr)
                continue
            if not isinstance(record, dict) or record.get("reason") != "compiler-message":
                continue
            message = record.get("message")
            rendered = message.get("rendered") if isinstance(message, dict) else None
            if isinstance(rendered, str):
                print(rendered, file=sys.stderr, end="" if rendered.endswith("\n") else "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["bind", "select", "verify", "diagnostics"])
    parser.add_argument("--directory", type=Path, default=Path("clippy-report"))
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if args.operation == "bind":
        bind(root, args.directory)
    elif args.operation == "verify":
        verify(root, args.directory, identity(root))
    elif args.operation == "diagnostics":
        print_diagnostics(args.directory)
    else:
        artifact = select(
            os.environ["GITHUB_REPOSITORY"],
            int(os.environ["GITHUB_RUN_ID"]),
            int(os.environ["GITHUB_RUN_ATTEMPT"]),
        )
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"artifact-id={artifact['id']}\n")


if __name__ == "__main__":
    main()
