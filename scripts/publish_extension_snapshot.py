"""Publish verified extension snapshots once, without overwriting released assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from extension_artifact_bundle import ARCHIVE, MANIFEST, source_sha, verify_bundle

REPOSITORY = "hashgraph-online/hol-guard"


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


def publish(directory: Path, expected_sha: str) -> None:
    expected_sha = source_sha(expected_sha)
    verify_bundle(directory, expected_sha)
    tag = "extension-artifacts-" + expected_sha
    release = find_release(tag)
    if release is None:
        github(
            "release",
            "create",
            tag,
            "--repo",
            REPOSITORY,
            "--target",
            expected_sha,
            "--draft",
            "--prerelease",
            "--latest=false",
            "--title",
            "Extension artifacts " + expected_sha[:12],
            "--notes",
            "Verified extension directory and metadata for source commit " + expected_sha + ".",
        )
        release = find_release(tag)
        if release is None:
            raise ValueError("created snapshot draft could not be retrieved")
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
    assets = {asset["name"] for asset in release["assets"]}
    expected = {ARCHIVE, MANIFEST}
    if assets - expected:
        raise ValueError("snapshot release has unexpected assets")
    if not release["draft"] and assets != expected:
        raise ValueError("published snapshot release is incomplete")
    with tempfile.TemporaryDirectory(prefix="extension-snapshot-") as temp:
        downloaded = Path(temp)
        for name in sorted(assets):
            github("release", "download", tag, "--repo", REPOSITORY, "--pattern", name, "--dir", str(downloaded))
            if (
                hashlib.sha256((downloaded / name).read_bytes()).digest()
                != hashlib.sha256((directory / name).read_bytes()).digest()
            ):
                raise ValueError("existing snapshot asset differs; refusing to overwrite")
        for name in sorted(expected - assets):
            github("release", "upload", tag, str(directory / name), "--repo", REPOSITORY)
            github("release", "download", tag, "--repo", REPOSITORY, "--pattern", name, "--dir", str(downloaded))
        for name in expected:
            if (downloaded / name).read_bytes() != (directory / name).read_bytes():
                raise ValueError("uploaded snapshot differs from verified local assets")
        verify_bundle(downloaded, expected_sha)
    if release["draft"]:
        github("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")
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
