"""Plan missed claim invitations without depending on artifact compilation."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

from extension_claim_github_comments import batched_pull_comments
from extension_claim_github_history import SnapshotClaimHistory
from extension_claim_provenance import ClaimProvenanceError, resolve_initial_contribution
from notify_merged_extension_claimants import (
    ClaimNoticeError,
    GitHubApi,
    GitHubApiError,
    accepted_github_ids,
    contribution_paths,
    trusted_notice_comment,
)
from reconcile_extension_claim_notices import pending_entries


def external_sources(root: Path) -> dict[str, list[str]]:
    result = {}
    for directory in ("command-sources", "extensions", "mcp-servers"):
        for path in sorted((root / "contributions" / directory).glob("*.json")):
            identity = path.stem
            runtime_id = f"command.mcp-{identity[4:]}" if identity.startswith("mcp.") else identity
            binding = root / "contracts/extensions/trust" / f"{runtime_id}.v1.json"
            if not binding.exists() or json.loads(binding.read_text()) != {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": runtime_id,
                "trustClass": "external",
            }:
                continue
            result[identity] = [name for name in contribution_paths(identity) if (root / name).is_file()]
    return result


def _invitation_entries(
    history,
    root: Path,
    sources: dict[str, list[str]],
    sha: str,
    *,
    revoked=None,
    owners=None,
) -> list[dict]:
    rows = []
    for identity, paths in sorted(sources.items()):
        listing_path = root / "contributions/extension-listings" / f"{identity}.json"
        listing = json.loads(listing_path.read_text()) if listing_path.exists() else None
        ids = accepted_github_ids(listing, identity) if listing is not None else ()
        try:
            owner = resolve_initial_contribution(history, paths, sha)
        except ClaimProvenanceError as error:
            print(f"{identity}: recovery needs provenance review: {error}", file=sys.stderr)
            continue
        if owners is not None:
            owners[identity] = owner.github_id
        if listing is not None and "maintainerGithubIds" in listing and owner.github_id not in ids:
            if revoked is not None:
                revoked.append(
                    {"extensionId": identity, "githubId": owner.github_id, "pullRequest": owner.pull_request}
                )
            continue
        if listing is not None and "maintainerGithubIds" in listing:
            initial = history.file_json(str(listing_path.relative_to(root)), owner.merge_sha, missing_ok=True)
            if initial is not None and "maintainerGithubIds" in initial:
                initial_ids = accepted_github_ids(initial, identity)
                if initial_ids and owner.github_id not in initial_ids:
                    # A later explicit ID addition belongs on its listing PR.
                    continue
        rows.append({"extensionId": identity, "githubId": owner.github_id, "pullRequest": owner.pull_request})
    return rows


def invitation_entries(history, root: Path, sources: dict[str, list[str]], sha: str, *, revoked=None, owners=None):
    rows = []
    for identity, paths in sorted(sources.items()):
        try:
            rows.extend(_invitation_entries(history, root, {identity: paths}, sha, revoked=revoked, owners=owners))
        except GitHubApiError:
            raise
        except (ClaimProvenanceError, ClaimNoticeError, ValueError, subprocess.CalledProcessError) as error:
            print(f"{identity}: invitation recovery needs review: {error}", file=sys.stderr)
    return rows


def _listing_transitions(root: Path, sources: dict[str, list[str]], sha: str) -> list[dict]:
    """Find explicit ID additions in local history; delivery still verifies the PR."""
    rows = []
    for identity in sorted(sources):
        path = f"contributions/extension-listings/{identity}.json"
        commits = subprocess.check_output(
            ["git", "-C", str(root), "log", "--format=%H", "-n", "101", sha, "--", path],
            text=True,
        ).splitlines()
        if len(commits) > 100:
            raise ClaimProvenanceError("Listing history exceeds the recovery bound")
        # Walk forward from absence. Deletions reset explicit authority; a
        # later re-addition is examined again by the notifier before writing.
        previous = set()
        implicit_before = True
        for commit in reversed(commits):
            blob = subprocess.run(
                ["git", "-C", str(root), "show", f"{commit}:{path}"],
                capture_output=True,
                text=True,
            )
            if blob.returncode:
                exists = subprocess.check_output(
                    ["git", "-C", str(root), "ls-tree", commit, "--", path],
                    text=True,
                )
                if exists:
                    raise ClaimProvenanceError("Listing history is unavailable")
                previous = set()
                implicit_before = True
                continue
            if len(blob.stdout.encode()) > 16_384:
                raise ClaimProvenanceError("Listing exceeds the recovery byte bound")
            listing = json.loads(blob.stdout)
            ids = set(accepted_github_ids(listing, identity))
            for account_id in sorted(ids - previous):
                rows.append(
                    {
                        "extensionId": identity,
                        "githubId": account_id,
                        "commit": commit,
                        "implicit_before": implicit_before,
                    }
                )
            previous = ids
            implicit_before = "maintainerGithubIds" not in listing
    return rows


def listing_transitions(root: Path, sources: dict[str, list[str]], sha: str) -> list[dict]:
    rows = []
    for identity, paths in sorted(sources.items()):
        try:
            rows.extend(_listing_transitions(root, {identity: paths}, sha))
        except GitHubApiError:
            raise
        except (ClaimProvenanceError, ClaimNoticeError, ValueError, subprocess.CalledProcessError) as error:
            print(f"{identity}: listing recovery needs review: {error}", file=sys.stderr)
    return rows


def transition_entries(history, root: Path, transitions: list[dict], *, owners=None) -> tuple[list[dict], list[dict]]:
    active, revoked = [], []
    for row in transitions:
        if row.get("implicit_before") and (owners or {}).get(row["extensionId"]) == row["githubId"]:
            continue
        path = root / "contributions/extension-listings" / f"{row['extensionId']}.json"
        listing = json.loads(path.read_text()) if path.exists() else None
        # An absent override returns authority to the original author, whose
        # invitation is planned separately from reviewed ID additions.
        ids = accepted_github_ids(listing, row["extensionId"]) if listing is not None else ()
        target = active if row["githubId"] in ids else revoked
        pulls = history._request(f"{history.base_url}/commits/{row['commit']}/pulls?per_page=100")
        for pull in pulls:
            number = pull.get("number")
            if type(number) is not int or number <= 0:
                raise ClaimProvenanceError("Listing PR identity is invalid")
            evidence = history.pull_request(number)
            if not evidence.get("merged") or evidence.get("base", {}).get("ref") != "main":
                continue
            merge = evidence.get("merge_commit_sha")
            if history.compare(row["commit"], merge).get("status") not in {"ahead", "identical"}:
                continue
            if history.compare(merge, "main").get("status") not in {"ahead", "identical"}:
                continue
            target.append({"extensionId": row["extensionId"], "githubId": row["githubId"], "pullRequest": number})
    return active, revoked


def pending_revocations(client, rows: list[dict]) -> list[int]:
    pending = set()
    batches = batched_pull_comments(client, sorted({row["pullRequest"] for row in rows}))
    logins = {}
    for row in rows:
        number = row["pullRequest"]
        comments = batches[number] if number in batches else client.comments(number)
        notice = trusted_notice_comment(comments)
        if notice is None:
            continue
        body = notice.get("body", "")
        query = urllib.parse.urlencode({"claim": row["extensionId"]})
        if f"?{query}&" not in body:
            continue
        account = row["githubId"]
        if account not in logins:
            logins[account] = client.user_login(account)
        login = logins[account]
        if login is None or re.search(rf"@{re.escape(login)}(?![A-Za-z0-9-])", body):
            pending.add(number)
    return sorted(pending)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-sha", help="Canonical revision matching the contribution files in the checkout.")
    args = parser.parse_args()
    root = args.source_root.resolve()
    shallow = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
        text=True,
    ).strip()
    if shallow != "false":
        raise ClaimProvenanceError("Claim recovery requires complete source history")
    sha = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", args.source_sha or "HEAD"],
        text=True,
    ).strip()
    subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", sha, "refs/remotes/origin/main"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "diff", "--exit-code", sha, "--", "contributions", "contracts/extensions/trust"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    client = GitHubApi(os.environ.get("GH_TOKEN", ""), "hashgraph-online/hol-guard", source_root=root)
    # Keep stdout a single matrix JSON value; provenance diagnostics go to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        sources = external_sources(root)
        transitions = listing_transitions(root, sources, sha)
        history = SnapshotClaimHistory(
            client,
            [path for paths in sources.values() for path in paths],
            sha,
            additional_commits=[row["commit"] for row in transitions],
        )
        revoked = []
        owners = {}
        rows = invitation_entries(history, root, sources, sha, revoked=revoked, owners=owners)
        listing_rows, listing_revoked = transition_entries(history, root, transitions, owners=owners)
        rows.extend(listing_rows)
        pending = sorted(
            set(pending_entries(client, rows, sorted({row["pullRequest"] for row in rows})))
            | set(pending_revocations(client, revoked + listing_revoked))
        )
        if len(pending) > 256:
            raise ClaimProvenanceError("Recovery exceeds the GitHub Actions matrix bound")
    print(json.dumps(pending))


if __name__ == "__main__":
    main()
