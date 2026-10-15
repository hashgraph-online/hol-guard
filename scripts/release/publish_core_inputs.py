"""Publish immutable attested package inputs before independent registry verification."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def publish(directory: Path) -> None:
    version = os.environ["VERSION"]
    source = os.environ["SOURCE_SHA"]
    repo = os.environ["GITHUB_REPOSITORY"]
    tag = f"v{version}"
    run("git", "fetch", "--no-tags", "origin", f"refs/tags/{tag}:refs/tags/{tag}")
    if run("git", "rev-parse", f"{tag}^{{commit}}").strip() != source:
        raise ValueError("release tag does not match the verified build")
    files = sorted(path for path in directory.iterdir() if path.is_file())
    if not files:
        raise ValueError("no verified release inputs")
    lookup = subprocess.run(["gh", "api", f"repos/{repo}/releases/tags/{tag}"], capture_output=True, text=True)
    if lookup.returncode:
        if "404" not in lookup.stderr:
            raise RuntimeError(lookup.stderr)
        # Manual publication creates its release only after registry success.
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write("core_ready=false\n")
        return
    else:
        releases = json.loads(lookup.stdout)
    if releases["draft"] or releases["prerelease"]:
        raise ValueError("Core inputs require a published stable release")
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
        bundle = f"hol-guard-v{version}.intoto.jsonl"
        if not (Path(scratch) / bundle).exists():
            run("gh", "release", "download", tag, "--repo", repo, "--pattern", bundle, "--dir", scratch)
        for path in files:
            if path.name.startswith("hol_guard-"):
                command = [
                    "gh",
                    "attestation",
                    "verify",
                    str(path),
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
    print("Verified package assets are ready; registry verification and Desktop signing continue independently.")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("core_ready=true\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    publish(parser.parse_args().directory)
