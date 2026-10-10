"""Deliver missed introducing-contributor notices after verified snapshot publication."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import zipfile
from pathlib import Path

_helper_dir = str(Path(__file__).resolve().parent)
sys.path.insert(0, _helper_dir)
try:
    from extension_artifact_bundle import ARCHIVE, verify_bundle
    from notify_merged_extension_claimants import DEFAULT_STUDIO_URL, GitHubApi, process, trusted_notice_comment
finally:
    sys.path.remove(_helper_dir)

PLAN = "docs/guard/extensions/claim-invitations.v1.json"


def planned_pull_requests(directory: Path, source_sha: str) -> list[int]:
    """Accept only a hashed, source-bound plan consistent with its catalog."""
    verify_bundle(directory, source_sha)
    with zipfile.ZipFile(directory / ARCHIVE) as archive:
        plan = json.loads(archive.read(PLAN))
        catalog = json.loads(archive.read("docs/guard/extensions/catalog.v1.json"))
    if plan.get("schemaVersion") != "guard.extension-claim-invitations.v1" or plan.get("sourceSha") != source_sha:
        raise ValueError("Claim invitation plan identity differs")
    entries = plan.get("entries")
    if not isinstance(entries, list) or len(entries) > 512:
        raise ValueError("Claim invitation plan exceeds bounds")
    current = {entry["id"]: entry for entry in catalog["entries"]}
    seen: set[str] = set()
    pulls: set[int] = set()
    for row in entries:
        if not isinstance(row, dict) or set(row) != {"extensionId", "githubId", "pullRequest"}:
            raise ValueError("Claim invitation plan entry is invalid")
        extension_id, github_id, number = row["extensionId"], row["githubId"], row["pullRequest"]
        if not isinstance(extension_id, str) or extension_id in seen:
            raise ValueError("Claim invitation plan repeats an extension")
        entry = current.get(extension_id)
        if (
            entry is None or entry.get("claimPolicy") != "provenance" or entry.get("trustClass") != "external"
            or github_id not in entry["maintainerGithubIds"]
            or type(number) is not int or number <= 0
        ):
            raise ValueError("Claim invitation plan does not match catalog authority")
        seen.add(extension_id)
        pulls.add(number)
    return sorted(pulls)


def reconcile(client: GitHubApi, directory: Path, source_sha: str, *, dry_run: bool = False) -> int:
    failed = 0
    for number in planned_pull_requests(directory, source_sha):
        try:
            process(client, number, DEFAULT_STUDIO_URL, dry_run=dry_run, refresh_existing=True)
        except Exception as error:
            # Finish unrelated notices; a failed run remains visibly retryable.
            print(f"PR #{number}: claim invitation failed: {error}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


def pending_pull_requests(client: GitHubApi, directory: Path, source_sha: str) -> list[int]:
    numbers = planned_pull_requests(directory, source_sha)
    with zipfile.ZipFile(directory / ARCHIVE) as archive:
        entries = json.loads(archive.read(PLAN))["entries"]
    expected = {number: {row["extensionId"] for row in entries if row["pullRequest"] == number} for number in numbers}
    pending = []
    for number in numbers:
        notice = trusted_notice_comment(client.comments(number))
        covered: set[str] = set()
        if notice is not None:
            for url in re.findall(r"\]\((https://hol\.org/guard/extension-studio\?[^)\s]+)\)", notice.get("body", "")):
                covered.update(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("claim", []))
        if not expected[number].issubset(covered):
            pending.append(number)
    if len(pending) > 256:
        raise ValueError("Missing invitations exceed the GitHub Actions matrix limit")
    return pending


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--plan", action="store_true", help="Print only PRs missing a trusted claim notice.")
    args = parser.parse_args()
    client = GitHubApi(os.environ.get("GH_TOKEN", ""), "hashgraph-online/hol-guard")
    if args.plan:
        pending = pending_pull_requests(client, args.directory, args.source_sha)
        print(json.dumps(pending, separators=(",", ":")))
        return 0
    return reconcile(client, args.directory, args.source_sha, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
