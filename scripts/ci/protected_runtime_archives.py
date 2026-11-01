"""Derive archive protection from trusted main sources, without compiling Rust."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

WORKFLOWS = ("ci.yml", "rust-test-cache-warm.yml")
ACTIVE_STATUSES = ("queued", "in_progress", "requested", "waiting", "pending")
PARTITIONS = ("core", "command", "runtime")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_RUNS = 1000
MAX_SOURCES = 16
SCHEMA = "hol-guard.protected-runtime-archives.v1"


class DiscoveryError(ValueError):
    """An incomplete snapshot must never authorize archive deletion."""


class GitHub:
    def __init__(self, repository: str, deadline: float):
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
            raise DiscoveryError("invalid_repository")
        self.repository = repository
        self.deadline = deadline

    def command(self, arguments: list[str], *, cwd: Path | None = None, output=None, limit=15):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise DiscoveryError("discovery_deadline")
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                stdout=output or subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=min(limit, remaining),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DiscoveryError("source_or_api_unavailable") from error
        if result.returncode:
            raise DiscoveryError("source_or_api_unavailable")
        return result.stdout

    def api(self, path: str):
        try:
            data = json.loads(self.command(["gh", "api", "--hostname", "github.com", path]))
            if not isinstance(data, dict):
                raise DiscoveryError("invalid_api_response")
            return data
        except (UnicodeError, json.JSONDecodeError) as error:
            raise DiscoveryError("invalid_api_response") from error

    def main_sha(self):
        data = self.api(f"repos/{self.repository}/git/ref/heads/main")
        obj = data.get("object", {})
        sha = obj.get("sha", "")
        if data.get("ref") != "refs/heads/main" or obj.get("type") != "commit" or not SHA.fullmatch(sha):
            raise DiscoveryError("invalid_main_ref")
        return sha

    def runs(self, status: str):
        result, seen, total = [], set(), None
        for page in range(1, MAX_RUNS // 100 + 1):
            query = urlencode(dict(branch="main", event="push", status=status, per_page=100, page=page))
            data = self.api(f"repos/{self.repository}/actions/runs?{query}")
            count, rows = data.get("total_count"), data.get("workflow_runs")
            if type(count) is not int or not 0 <= count < MAX_RUNS or not isinstance(rows, list):
                raise DiscoveryError("incomplete_run_inventory")
            if (total is not None and count != total) or len(rows) > 100:
                raise DiscoveryError("changing_run_inventory")
            total = count
            for row in rows:
                run_id = row.get("id") if isinstance(row, dict) else None
                if type(run_id) is not int or run_id <= 0 or run_id in seen:
                    raise DiscoveryError("invalid_run_inventory")
                seen.add(run_id)
                result.append(row)
            if len(result) == total:
                return result
            if len(result) > total or len(rows) != 100:
                raise DiscoveryError("incomplete_run_inventory")
        raise DiscoveryError("incomplete_run_inventory")


def trusted_sources(client):
    repository = client.api(f"repos/{client.repository}")
    repository_id = repository.get("id")
    if (
        type(repository_id) is not int
        or repository.get("full_name") != client.repository
        or repository.get("default_branch") != "main"
    ):
        raise DiscoveryError("invalid_repository_identity")
    main_sha = client.main_sha()
    sources = {main_sha}
    evidence = {}
    # Query repository runs, including historical workflows removed from main.
    # This fixed allowlist must not depend on files in the current checkout.
    paths = {f".github/workflows/{workflow}" for workflow in WORKFLOWS}
    for status in ACTIVE_STATUSES:
        for run in client.runs(status):
            # Never export or execute pull-request/fork sources, even if an
            # unexpected API response includes them in this filtered list.
            if run.get("event") != "push" or run.get("head_branch") != "main":
                continue
            if run.get("path") not in paths:
                continue
            if (
                run.get("repository", {}).get("id") != repository_id
                or run.get("head_repository", {}).get("id") != repository_id
            ):
                raise DiscoveryError("untrusted_run_repository")
            sha = run.get("head_sha", "")
            if type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0 or not SHA.fullmatch(sha):
                raise DiscoveryError("invalid_run_identity")
            if run.get("status") not in (*ACTIVE_STATUSES, "completed"):
                raise DiscoveryError("unknown_run_state")
            item = dict(id=run["id"], workflow=run["path"], workflow_id=run["workflow_id"], source_sha=sha)
            previous = evidence.get(run["id"])
            if previous is not None and previous != item:
                raise DiscoveryError("changing_run_identity")
            evidence[run["id"]] = item
            sources.add(sha)
    if len(sources) > MAX_SOURCES or main_sha != client.main_sha():
        raise DiscoveryError("changing_or_excessive_sources")
    return dict(main_sha=main_sha, sources=sorted(sources), runs=sorted(evidence.values(), key=lambda item: item["id"]))


def source_digests(client, sha):
    """Export one immutable trusted commit into a private, disposable directory."""
    if not SHA.fullmatch(sha):
        raise DiscoveryError("invalid_source_sha")
    with tempfile.TemporaryDirectory(prefix="guard-cache-source-") as temporary:
        root = Path(temporary)
        repository = root / "repository.git"
        client.command(["git", "init", "--bare", "--quiet", str(repository)])
        git = ["git", "--git-dir", str(repository)]
        client.command(
            [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                "credential.https://github.com.helper=!gh auth git-credential",
                "--git-dir",
                str(repository),
                "fetch",
                "--no-tags",
                "--depth=1",
                f"https://github.com/{client.repository}.git",
                sha,
            ],
            limit=60,
        )
        if client.command([*git, "rev-parse", "FETCH_HEAD"]).decode().strip() != sha:
            raise DiscoveryError("source_commit_mismatch")
        archive = root / "source.tar"
        with archive.open("wb") as output:
            client.command([*git, "archive", "--format=tar", sha], output=output, limit=30)
        source = root / "source"
        source.mkdir()
        with tarfile.open(archive) as contents:
            for member in contents:
                if time.monotonic() >= client.deadline:
                    raise DiscoveryError("discovery_deadline")
                parts = Path(member.name).parts
                if not parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise DiscoveryError("unsafe_source_archive")
                if ".." in parts or Path(member.name).is_absolute():
                    raise DiscoveryError("unsafe_source_archive")
                contents.extract(member, source, filter="data")
        client.command([sys.executable, "scripts/refresh_extension_artifacts.py", "--trust-only"], cwd=source, limit=30)
        digests = {}
        for partition in PARTITIONS:
            result = client.command(
                [sys.executable, "-m", "scripts.ci.rust_test_archive_inputs", "--partition", partition],
                cwd=source,
                limit=30,
            )
            value = result.decode().strip().removeprefix("digest=")
            if not DIGEST.fullmatch(value):
                raise DiscoveryError("invalid_source_digest")
            digests[partition] = value
        return dict(source_sha=sha, digests=digests)


def still_covered(saved, fresh):
    """Finished runs may shrink the live set without adding unprotected inputs."""
    try:
        known = {run["id"]: run for run in saved["runs"]}
        return (
            saved["main_sha"] == fresh["main_sha"]
            and set(fresh["sources"]) <= set(saved["sources"])
            and all(known.get(run["id"]) == run for run in fresh["runs"])
        )
    except (KeyError, TypeError):
        return False


def discover(client, derive=source_digests):
    report = dict(schema=SCHEMA, complete=False, sources=[], discovery={})
    try:
        before = trusted_sources(client)
        report["discovery"] = before
        report["sources"] = [derive(client, sha) for sha in before["sources"]]
        # A source change or rerun arriving while exports are hashed leaves the
        # snapshot incomplete. Other cleanup families can still be processed.
        if not still_covered(before, trusted_sources(client)):
            raise DiscoveryError("changing_protected_sources")
        report["complete"] = True
    except (DiscoveryError, OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        report["error"] = "archive_protection_incomplete"
    return report


def verify_plan(client, plan):
    """Filter archive deletions if the uploaded plan's source snapshot changed."""
    outcome, fresh = "source_discovery_incomplete", None
    saved = plan.get("protection") or {}
    if saved.get("complete") is True:
        try:
            fresh = trusted_sources(client)
            outcome = "verified" if still_covered(saved.get("discovery"), fresh) else "source_snapshot_changed"
        except (DiscoveryError, OSError, ValueError, KeyError, TypeError, AttributeError):
            outcome = "source_snapshot_unavailable"
    selected, skipped = [], []
    for entry in plan["selected"]:
        if outcome != "verified" and entry["key"].startswith("runtime-test-archive-"):
            skipped.append(dict(entry, reasons=[outcome]))
        else:
            selected.append(entry)
    return dict(
        schema="hol-guard.cache-prune-verification.v1",
        source_verification=outcome,
        discovery=fresh,
        # Apply archive deletions before potentially lengthy unrelated cleanup,
        # keeping the final source check close to its protected operation.
        selected=sorted(
            selected, key=lambda entry: (not entry["key"].startswith("runtime-test-archive-"), entry["id"])
        ),
        skipped_archives=skipped,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GH_REPO", ""))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-plan", type=Path)
    args = parser.parse_args(argv)
    if args.verify_plan:
        plan = json.loads(args.verify_plan.read_text())
        report = verify_plan(GitHub(args.repository, time.monotonic() + 45), plan)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return 0
    try:
        report = discover(GitHub(args.repository, time.monotonic() + 120))
    except DiscoveryError:
        report = dict(schema=SCHEMA, complete=False, sources=[], error="archive_protection_incomplete")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["complete"]:
        print("::warning::Archive source discovery incomplete; archive pruning is disabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
