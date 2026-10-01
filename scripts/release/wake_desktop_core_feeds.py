"""Wake both stable feeds only after a completed Core publication."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import TypedDict

WORKFLOWS = ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml")
STABLE_VERSION_PATTERN = r"3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


class WorkflowRunPayload(TypedDict, total=False):
    conclusion: str
    event: str
    head_branch: str


class IssuePayload(TypedDict, total=False):
    author_association: str
    title: str


class EventPayload(TypedDict, total=False):
    workflow_run: WorkflowRunPayload
    issue: IssuePayload
    ref: str


class DispatchPayload(TypedDict, total=False):
    ref: str
    inputs: dict[str, str]


class ReleaseAssetPayload(TypedDict):
    name: str


class ReleasePayload(TypedDict):
    draft: bool
    prerelease: bool
    tag_name: str
    assets: list[ReleaseAssetPayload]


def dispatch_payload(
    event_name: str, event: EventPayload, publication_version: str | None = None
) -> DispatchPayload | None:
    if event_name == "workflow_run":
        run = event.get("workflow_run", {})
        if run.get("conclusion") != "success" or run.get("event") not in {"push", "workflow_dispatch"}:
            return None
        branch = run.get("head_branch", "")
        if branch == "main" and run.get("event") == "workflow_dispatch":
            if publication_version is None:
                return None
            return {"ref": "main", "inputs": {"core_version": publication_version}}
        if not isinstance(branch, str) or not re.fullmatch(rf"v{STABLE_VERSION_PATTERN}", branch):
            return None
        return {"ref": "main", "inputs": {"core_version": branch[1:]}}
    if event_name == "push" and event.get("ref") == "refs/heads/main":
        return {"ref": "main"}
    if event_name == "issues":
        issue = event.get("issue", {})
        if issue.get("author_association") in {"OWNER", "MEMBER", "COLLABORATOR"} and str(
            issue.get("title", "")
        ).startswith("[desktop-core-feed]"):
            return {"ref": "main"}
    return None


def read_publication_version(path: Path) -> str | None:
    versions = set()
    for line in path.read_text().splitlines():
        digest, separator, filename = line.partition(" ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("Publication checksum manifest is malformed")
        name = Path(filename.lstrip(" *")).name
        if not name.startswith("hol_guard-") or not name.endswith(".whl"):
            continue
        match = re.fullmatch(rf"hol_guard-({STABLE_VERSION_PATTERN}(?:(?:a|b|rc)[0-9]+)?)-.+\.whl", name)
        if match is None:
            raise RuntimeError("Publication wheel name does not match expected pattern")
        versions.add(match[1])
    if len(versions) != 1:
        raise RuntimeError("Publication checksum manifest has no unique version")
    version = versions.pop()
    return version if re.fullmatch(STABLE_VERSION_PATTERN, version) else None


def require_published_assets(release: ReleasePayload, version: str) -> None:
    if not (release.get("draft") is False and release.get("prerelease") is False):
        raise RuntimeError("Core release is not published stable")
    if release.get("tag_name") != f"v{version}":
        raise RuntimeError("Core release tag does not match completed publication")
    assets = {asset.get("name", "") for asset in release.get("assets", [])}
    if f"hol-guard-v{version}.intoto.jsonl" not in assets:
        raise RuntimeError("Core publication attestation is unavailable")
    prefix = f"hol_guard-{version}-"
    # These are the two platform wheel contracts consumed by the stable feeds.
    for target in ("manylinux_2_17_x86_64.whl", "macosx_11_0_arm64.whl"):
        if not any(name.startswith(prefix) and name.endswith(target) for name in assets):
            raise RuntimeError("Core publication native wheels are unavailable")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def main() -> None:
    try:
        event_name = os.environ["GITHUB_EVENT_NAME"]
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    except (KeyError, OSError, json.JSONDecodeError) as error:
        raise SystemExit("GitHub event payload is unavailable or invalid") from error
    publication_version = None
    if event_name == "workflow_run":
        publication_version = read_publication_version(Path(os.environ["PUBLICATION_CHECKSUMS"]))
    payload = dispatch_payload(event_name, event, publication_version)
    if payload is None:
        print("Event does not identify a completed stable Core publication")
        return
    repository = os.environ["REPOSITORY"]
    # Privileged dispatch is restricted to this release authority, including on forks.
    if repository != "hashgraph-online/hol-guard":
        raise RuntimeError("Unexpected feed repository")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hol-guard-desktop-core-feed-wake",
    }
    version = payload.get("inputs", {}).get("core_version")
    # A stable tag must not dispatch from a nonstable manifest (None).
    # Nonstable main publications already returned before this point.
    if event_name == "workflow_run" and version != publication_version:
        raise RuntimeError("Publication manifest does not match completed run tag")
    opener = urllib.request.build_opener(NoRedirect())
    if version:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/releases/tags/v{version}", headers=headers
        )
        with opener.open(request, timeout=20) as response:
            require_published_assets(json.load(response), version)
    for workflow in WORKFLOWS:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/dispatches",
            data=json.dumps(payload).encode(),
            method="POST",
            headers=headers,
        )
        with opener.open(request, timeout=20) as response:
            if response.status != 204:
                # Do not echo bodies from authenticated API requests.
                raise RuntimeError(f"Core feed dispatch returned HTTP {response.status}")
        print(f"Dispatched {workflow}")


if __name__ == "__main__":
    main()
