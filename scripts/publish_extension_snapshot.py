"""Publish verified extension snapshots once, without overwriting released assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from extension_artifact_bundle import ARCHIVE, MANIFEST, source_sha, verify_bundle

from codex_plugin_scanner.no_redirect import RejectRedirects

REPOSITORY = "hashgraph-online/hol-guard"
PROVENANCE = "extension-artifacts.intoto.jsonl"
WORKFLOW = REPOSITORY + "/.github/workflows/extension-artifact-regen.yml"


def github_id(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("GitHub resource identity is invalid")
    return value


def upload_asset(release_id: int, path: Path) -> dict:
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise RuntimeError("GH_TOKEN is required to upload snapshot assets")
    endpoint = (
        f"https://uploads.github.com/repos/{REPOSITORY}/releases/{github_id(release_id)}/assets"
        f"?name={urllib.parse.quote(path.name, safe='')}"
    )
    request = urllib.request.Request(
        endpoint,
        data=path.read_bytes(),
        method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream"},
    )
    # The destination is constructed locally. Never follow a response redirect
    # carrying the token, or accept a server-supplied upload URL.
    with urllib.request.build_opener(RejectRedirects()).open(request, timeout=120) as response:
        asset = json.load(response)
    github_id(asset.get("id"))
    if asset.get("name") != path.name:
        raise ValueError("uploaded snapshot asset identity differs")
    return asset


def download_asset(asset: dict, destination: Path) -> None:
    endpoint = f"repos/{REPOSITORY}/releases/assets/{github_id(asset.get('id'))}"
    with destination.open("xb") as stream:
        result = subprocess.run(
            ["gh", "api", endpoint, "--header", "Accept: application/octet-stream"],
            stdout=stream,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip() or "GitHub download failed")


def github(*arguments: str) -> str:
    result = subprocess.run(["gh", *arguments], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "GitHub request failed")
    return result.stdout


def find_release(tag: str) -> dict | None:
    endpoint = f"repos/{REPOSITORY}/releases/tags/{tag}"
    try:
        return json.loads(github("api", endpoint))
    except RuntimeError as error:
        if "HTTP 404" not in str(error):
            raise
    # The tag endpoint excludes drafts. Writers can retrieve them from the
    # paginated list, including a draft whose tag has not been created yet.
    pages = json.loads(github("api", f"repos/{REPOSITORY}/releases?per_page=100", "--paginate", "--slurp"))
    matches = [release for page in pages for release in page if release["tag_name"] == tag]
    if len(matches) > 1:
        raise ValueError("snapshot tag has duplicate releases")
    return matches[0] if matches else None


def verify_provenance(directory: Path, expected_sha: str) -> None:
    bundle = directory / PROVENANCE
    if not bundle.is_file() or bundle.stat().st_size > 1024 * 1024:
        raise ValueError("snapshot provenance is missing or exceeds byte limit")
    for name in (ARCHIVE, MANIFEST):
        github(
            "attestation", "verify", str(directory / name), "--bundle", str(bundle),
            "--repo", REPOSITORY, "--signer-workflow", WORKFLOW,
            "--source-ref", "refs/heads/main", "--source-digest", expected_sha,
        )


def publish(directory: Path, expected_sha: str) -> None:
    expected_sha = source_sha(expected_sha)
    verify_bundle(directory, expected_sha)
    verify_provenance(directory, expected_sha)
    tag = "extension-artifacts-" + expected_sha
    release = find_release(tag)
    if release is None:
        release = json.loads(
            github(
                "api", f"repos/{REPOSITORY}/releases", "--method", "POST",
                "-f", "tag_name=" + tag, "-f", "target_commitish=" + expected_sha,
                "-F", "draft=true", "-F", "prerelease=true", "-f", "make_latest=false",
                "-f", "name=Extension artifacts " + expected_sha[:12],
                "-f", "body=Verified extension directory and metadata for source commit " + expected_sha + ".",
            )
        )
        if release.get("draft") is not True:
            raise ValueError("created snapshot must remain a draft until verified")
    release_id = github_id(release.get("id"))
    if release.get("tag_name") != tag:
        raise ValueError("snapshot release tag differs")
    if release.get("target_commitish") != expected_sha or release.get("prerelease") is not True:
        raise ValueError("snapshot release does not match its source")
    try:
        # The ref endpoint reports an absent tag as 404; commit resolution uses
        # 422 for the same state, which is ambiguous with other invalid requests.
        github("api", f"repos/{REPOSITORY}/git/ref/tags/{tag}")
    except RuntimeError as error:
        # GitHub may defer creating a new tag until a draft is published.
        if not release["draft"] or "HTTP 404" not in str(error):
            raise
    else:
        commit = json.loads(github("api", f"repos/{REPOSITORY}/commits/{tag}"))
        if commit.get("sha") != expected_sha:
            raise ValueError("snapshot tag does not match its source")
    assets = {asset["name"]: asset for asset in release["assets"]}
    if len(assets) != len(release["assets"]):
        raise ValueError("snapshot release has duplicate assets")
    expected = {ARCHIVE, MANIFEST, PROVENANCE}
    if assets.keys() - expected:
        raise ValueError("snapshot release has unexpected assets")
    if not release["draft"] and assets.keys() != expected:
        raise ValueError("published snapshot release is incomplete")
    with tempfile.TemporaryDirectory(prefix="extension-snapshot-") as temp:
        downloaded = Path(temp)
        for name in sorted(assets):
            download_asset(assets[name], downloaded / name)
            if (
                name != PROVENANCE
                and hashlib.sha256((downloaded / name).read_bytes()).digest()
                != hashlib.sha256((directory / name).read_bytes()).digest()
            ):
                raise ValueError("existing snapshot asset differs; refusing to overwrite")
        for name in sorted(expected - assets.keys()):
            asset = upload_asset(release_id, directory / name)
            download_asset(asset, downloaded / name)
        for name in expected:
            # Attestations contain signing timestamps. A retry keeps the
            # existing bundle and verifies its subjects instead of replacing it.
            if name == PROVENANCE and name in assets:
                continue
            if (downloaded / name).read_bytes() != (directory / name).read_bytes():
                raise ValueError("uploaded snapshot differs from verified local assets")
        verify_bundle(downloaded, expected_sha)
        verify_provenance(downloaded, expected_sha)
    if release["draft"]:
        published = json.loads(github("api", f"repos/{REPOSITORY}/releases/{release_id}",
                                      "--method", "PATCH", "-F", "draft=false", "-f", "make_latest=false"))
        if published.get("draft") is not False or published.get("tag_name") != tag:
            raise ValueError("snapshot release publication was not confirmed")
        commit = json.loads(github("api", f"repos/{REPOSITORY}/commits/{tag}"))
        if commit.get("sha") != expected_sha:
            raise ValueError("published snapshot tag does not match its source")
    print(json.dumps({"ok": True, "source_sha": expected_sha, "tag": tag}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    publish(args.directory, args.source_sha)


if __name__ == "__main__":
    main()
