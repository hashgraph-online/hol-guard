"""Publish immutable attested package inputs before independent registry verification."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from packaging.version import Version

from scripts.verify_native_runtime_release import local_guard_hashes


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def validate_distributions(directory: Path, *, version: str, source: str) -> None:
    # Provenance and SBOM files accompany the release but are not distributions.
    with tempfile.TemporaryDirectory() as scratch:
        for path in directory.iterdir():
            if path.name.endswith((".whl", ".tar.gz")):
                if path.is_symlink() or not path.is_file():
                    raise ValueError("release distribution must be a regular file")
                shutil.copyfile(path, Path(scratch) / path.name)
        local_guard_hashes(Path(scratch), version=version, source_sha=source)


def publish(directory: Path) -> None:
    version = os.environ["VERSION"]
    source = os.environ["SOURCE_SHA"]
    repo = os.environ["GITHUB_REPOSITORY"]
    channel = os.environ.get("CHANNEL", "stable")
    parsed = Version(version)
    if channel not in {"stable", "alpha", "canary"} or (
        (channel == "stable" and parsed.is_prerelease)
        or (channel == "alpha" and (parsed.pre is None or parsed.pre[0] != "a"))
        or (channel == "canary" and not parsed.is_devrelease)
    ):
        raise ValueError("release channel does not match the package version")
    validate_distributions(directory, version=version, source=source)
    tag = f"v{version}" if channel == "stable" else f"{channel}/v{version}"
    if channel == "canary" and not run("git", "ls-remote", "origin", f"refs/tags/{tag}").strip():
        # Canary versions are source-specific and have no separate reservation job.
        run(
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{repo}/git/refs",
            "-f",
            f"ref=refs/tags/{tag}",
            "-f",
            f"sha={source}",
        )
    run("git", "fetch", "--no-tags", "origin", f"refs/tags/{tag}:refs/tags/{tag}")
    if run("git", "rev-parse", f"{tag}^{{commit}}").strip() != source:
        raise ValueError("release tag does not match the verified build")
    files = sorted(path for path in directory.iterdir() if path.is_file())
    if not files:
        raise ValueError("no verified release inputs")
    # The release CLI resolves drafts too; the published-release REST tag lookup
    # cannot be used to resume an asset upload that stopped while still a draft.
    view = ["gh", "release", "view", tag, "--repo", repo, "--json", "isDraft,isPrerelease,assets"]
    lookup = subprocess.run(view, capture_output=True, text=True)
    if lookup.returncode:
        if "404" not in lookup.stderr and "release not found" not in lookup.stderr.lower():
            raise RuntimeError(lookup.stderr)
        command = [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repo,
            "--verify-tag",
            "--draft",
            "--title",
            f"Guard {version}",
            "--notes",
            "Verified package assets; registry publication is pending.",
        ]
        if channel != "stable":
            command.append("--prerelease")
        run(*command)
        releases = json.loads(run(*view))
    else:
        releases = json.loads(lookup.stdout)
    if releases["isPrerelease"] != (channel != "stable"):
        raise ValueError("release channel identity differs")
    names = {asset["name"] for asset in releases["assets"]}
    with tempfile.TemporaryDirectory() as scratch:
        for path in files:
            if path.name in names:
                run("gh", "release", "download", tag, "--repo", repo, "--pattern", path.name, "--dir", scratch)
                remote = Path(scratch) / path.name
                if not path.name.endswith(".intoto.jsonl") and path.read_bytes() != remote.read_bytes():
                    raise ValueError(f"immutable release asset differs: {path.name}")
            else:
                run("gh", "release", "upload", tag, str(path), "--repo", repo)
                run("gh", "release", "download", tag, "--repo", repo, "--pattern", path.name, "--dir", scratch)
                if path.read_bytes() != (Path(scratch) / path.name).read_bytes():
                    raise ValueError(f"uploaded release asset differs: {path.name}")
        bundle = f"hol-guard-v{version}.intoto.jsonl"
        if not (Path(scratch) / bundle).exists():
            run("gh", "release", "download", tag, "--repo", repo, "--pattern", bundle, "--dir", scratch)
        for path in files:
            if path.name.startswith("hol_guard-"):
                command = [
                    "gh",
                    "attestation",
                    "verify",
                    str(Path(scratch) / path.name),
                    "--repo",
                    repo,
                    "--bundle",
                    str(Path(scratch) / bundle),
                    "--signer-workflow",
                    f"{repo}/.github/workflows/publish.yml",
                    "--deny-self-hosted-runners",
                    "--source-digest",
                ]
                try:
                    run(*command, source)
                except subprocess.CalledProcessError:
                    run(*command, os.environ["GITHUB_SHA"])
        # Revalidate the downloaded complete platform set and its embedded source identities.
        validate_distributions(Path(scratch), version=version, source=source)
    if releases["isDraft"]:
        run("gh", "release", "edit", tag, "--repo", repo, "--draft=false", "--latest=false")
    published = json.loads(run(*view))
    if published["isDraft"] or published["isPrerelease"] != (channel != "stable"):
        raise ValueError("release publication was not confirmed")
    run("git", "fetch", "--no-tags", "origin", f"refs/tags/{tag}:refs/tags/{tag}")
    if run("git", "rev-parse", f"{tag}^{{commit}}").strip() != source:
        raise ValueError("published release tag does not match the verified build")
    print("Verified package assets are ready; registry verification and Desktop signing continue independently.")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("core_ready=true\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    publish(parser.parse_args().directory)
