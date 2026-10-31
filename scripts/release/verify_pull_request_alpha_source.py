#!/usr/bin/env python3
"""Bind a pull request alpha's tagged source to the main publish run that built it.

A pull request alpha publishes an admin-authorized pull request head, so its
source is not an ancestor of main and the release-branch ancestry proof used for
main alphas cannot apply. The proof here is the publication itself: the wheel's
provenance names the trusted publish workflow on main and the exact run that
built it, that run authorized a pull request alpha, and the native runtime
manifest the run sealed into the wheel names the tagged source commit.

The caller verifies the provenance signature with `gh attestation verify`
against the attested main commit; this script checks the statement's contents
and the run, then prints nothing on success.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

MANIFEST_PATH = "codex_plugin_scanner/_native/runtime-manifest.json"
MAX_MANIFEST_BYTES = 64 * 1024
AUTHORIZE_JOB = "Authorize pull request alpha"
_SHA40 = re.compile(r"[0-9a-f]{40}")
_ALPHA = re.compile(r"3\.(0|[1-9][0-9]*)\.0a[1-9][0-9]*")


class SourceBindingError(ValueError):
    pass


def attested_statement(bundle: Path, wheel: Path, repo: str, run_id: str, attested_commit: str) -> None:
    lines = bundle.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise SourceBindingError("ambiguous publication provenance")
    statement = json.loads(base64.b64decode(json.loads(lines[0])["dsseEnvelope"]["payload"]))
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if not any(subject.get("digest", {}).get("sha256") == digest for subject in statement["subject"]):
        raise SourceBindingError("publication provenance does not bind the native wheel")
    build = statement["predicate"]["buildDefinition"]
    workflow = build["externalParameters"]["workflow"]
    if workflow.get("path") != ".github/workflows/publish.yml" or workflow.get("ref") != "refs/heads/main":
        raise SourceBindingError("publication provenance is not the main publish workflow")
    if build["resolvedDependencies"][0]["digest"].get("gitCommit") != attested_commit:
        raise SourceBindingError("publication provenance does not name the attested main commit")
    invocation = statement["predicate"]["runDetails"]["metadata"]["invocationId"]
    expected = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/1"
    if invocation != expected:
        raise SourceBindingError("publication provenance does not come from the dispatched publication run")


def manifest_source(wheel: Path) -> tuple[str, str]:
    with zipfile.ZipFile(wheel) as archive:
        names = [entry.filename for entry in archive.infolist()]
        if names.count(MANIFEST_PATH) != 1:
            raise SourceBindingError("native wheel manifest is missing or duplicated")
        info = archive.getinfo(MANIFEST_PATH)
        if info.file_size > MAX_MANIFEST_BYTES:
            raise SourceBindingError("native wheel manifest is too large")
        manifest = json.loads(archive.read(info).decode("utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != "hol-guard-native-runtime.v1":
        raise SourceBindingError("native wheel manifest has an unexpected schema")
    return str(manifest.get("source_sha")), str(manifest.get("package_version"))


def authorized_run(repo: str, run_id: str, attested_commit: str) -> None:
    run = json.loads(
        subprocess.check_output(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"], text=True, timeout=20)
    )
    if (
        run["path"].split("@")[0] != ".github/workflows/publish.yml"
        or run["event"] != "workflow_dispatch"
        or run["head_branch"] != "main"
        or run["head_sha"] != attested_commit
    ):
        raise SourceBindingError("publication run is not a main dispatch of the publish workflow")
    conclusions = subprocess.check_output(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repo}/actions/runs/{run_id}/attempts/1/jobs?per_page=100",
            "--jq",
            f'.jobs[] | select(.name == "{AUTHORIZE_JOB}") | .conclusion',
        ],
        text=True,
        timeout=20,
    ).splitlines()
    if conclusions != ["success"]:
        raise SourceBindingError("publication run did not authorize a pull request alpha")


def verify(
    *, wheel: Path, bundle: Path, repo: str, run_id: str, source_sha: str, version: str, attested_commit: str
) -> None:
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise SourceBindingError("invalid publication run id")
    if not _SHA40.fullmatch(source_sha) or not _SHA40.fullmatch(attested_commit):
        raise SourceBindingError("source and attested commit must be full lowercase Git SHAs")
    if not _ALPHA.fullmatch(version):
        raise SourceBindingError("invalid alpha version")
    attested_statement(bundle, wheel, repo, run_id, attested_commit)
    manifest_sha, manifest_version = manifest_source(wheel)
    if manifest_sha != source_sha or manifest_version != version:
        raise SourceBindingError("native wheel was not built from the tagged pull request source")
    authorized_run(repo, run_id, attested_commit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--attested-commit", required=True)
    args = parser.parse_args(argv)
    try:
        verify(
            wheel=args.wheel,
            bundle=args.bundle,
            repo=args.repo,
            run_id=args.run_id,
            source_sha=args.source_sha,
            version=args.version,
            attested_commit=args.attested_commit,
        )
    except SourceBindingError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
