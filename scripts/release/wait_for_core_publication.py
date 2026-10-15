"""Let signing run early while withholding updater assets until publication succeeds."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def attested_publication_identity(
    wheel: Path, bundle: Path, repo: str, *, version: str | None = None
) -> tuple[str, str]:
    # Verify the single signed statement before trusting its invocation identity.
    subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            str(wheel),
            "--repo",
            repo,
            "--bundle",
            str(bundle),
            "--signer-workflow",
            f"{repo}/.github/workflows/publish.yml",
            "--deny-self-hosted-runners",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=20,
    )
    lines = bundle.read_text().splitlines()
    if len(lines) != 1:
        raise ValueError("ambiguous publication provenance")
    statement = json.loads(base64.b64decode(json.loads(lines[0])["dsseEnvelope"]["payload"]))
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if not any(subject.get("digest", {}).get("sha256") == digest for subject in statement["subject"]):
        raise ValueError("publication provenance does not bind the attested wheel")
    invocation = statement["predicate"]["runDetails"]["metadata"]["invocationId"]
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repo)}/actions/runs/([1-9][0-9]*)/attempts/[1-9][0-9]*", invocation
    )
    if not match:
        raise ValueError("publication provenance has an invalid invocation")
    run_id = match[1]
    if version is not None:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("invalid stable version")
        source = statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"]
        if not re.fullmatch(r"[0-9a-f]{40}", source):
            raise ValueError("invalid attested source")
        completed = subprocess.check_output(
            [
                "gh",
                "api",
                "--paginate",
                f"repos/{repo}/commits/{source}/statuses?per_page=100",
                "--jq",
                f'.[] | select(.context == "hol-guard / published {version}" and .state == "success") | .target_url',
            ],
            text=True,
            timeout=20,
        ).splitlines()
        if completed:
            repaired = re.fullmatch(rf"https://github\.com/{re.escape(repo)}/actions/runs/([1-9][0-9]*)", completed[0])
            if not repaired:
                raise ValueError("invalid completed publication identity")
            run_id = repaired[1]
    run = json.loads(
        subprocess.check_output(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"], text=True, timeout=20)
    )
    return run_id, run["head_sha"]


_VERSION_PATTERNS = {
    "stable": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+"),
    "alpha": re.compile(r"3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)a[1-9][0-9]*"),
}
_PUBLICATION_JOBS = {"stable": "Publish main release to PyPI", "alpha": "Publish alpha to PyPI"}


def _alpha_source_is_in_run(repo: str, source_sha: str, head_sha: str) -> bool:
    """An alpha run dispatches from main, which may have moved past the alpha source commit."""
    if head_sha == source_sha:
        return True
    comparison = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{repo}/compare/{source_sha}...{head_sha}?per_page=1"], text=True, timeout=20
        )
    )
    return (
        comparison["status"] in {"ahead", "identical"}
        and comparison["base_commit"]["sha"] == source_sha
        and comparison["merge_base_commit"]["sha"] == source_sha
    )


def publication_ready(repo: str, run_id: str, source_sha: str, channel: str = "stable") -> bool:
    if channel not in _PUBLICATION_JOBS:
        raise ValueError("invalid release channel")
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid publication run identity")
    result = json.loads(
        subprocess.check_output(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"], text=True, timeout=20)
    )
    if result["path"].split("@")[0] != ".github/workflows/publish.yml" or result["event"] != "workflow_dispatch":
        raise ValueError("publication run is not the authorized release dispatch")
    if channel == "stable":
        if result["head_sha"] != source_sha:
            raise ValueError("publication run is not the authorized release dispatch")
    elif result["head_branch"] != "main" or not _alpha_source_is_in_run(repo, source_sha, result["head_sha"]):
        raise ValueError("alpha publication run is not an authorized main dispatch of the alpha source")
    conclusions = subprocess.check_output(
        [
            "gh",
            "api",
            "--paginate",
            # Publish jobs run only on attempt 1; a later rerun of an unrelated
            # failed job reports them as skipped in the latest attempt.
            f"repos/{repo}/actions/runs/{run_id}/attempts/1/jobs?per_page=100",
            "--jq",
            f'.jobs[] | select(.name == "{_PUBLICATION_JOBS[channel]}") | .conclusion',
        ],
        text=True,
        timeout=20,
    ).splitlines()
    if conclusions == ["success"]:
        return True
    if channel == "stable" and not conclusions and result["conclusion"] == "success":
        # Older publish workflows used different job names; require the entire run.
        return True
    if any(value not in {"null", ""} for value in conclusions) or result["conclusion"] in {"failure", "cancelled"}:
        raise ValueError(f"{channel} registry publication failed; withholding updater assets")
    return False


def _alpha_release_digests(repo: str, version: str) -> dict[str, str | None]:
    """Map each uploaded asset of the live alpha prerelease to its sha256 (None when GitHub reports none)."""
    tag = f"alpha/v{version}"
    release = json.loads(
        subprocess.check_output(["gh", "api", f"repos/{repo}/releases/tags/{tag}"], text=True, timeout=20)
    )
    if release.get("tag_name") != tag or release.get("draft") is not False or release.get("prerelease") is not True:
        raise ValueError("alpha prerelease is not published; withholding updater assets")
    digests: dict[str, str | None] = {}
    for asset in release["assets"]:
        if asset.get("state") == "uploaded":
            match = re.fullmatch(r"sha256:([0-9a-f]{64})", asset.get("digest") or "")
            digests[asset["name"]] = match[1] if match else None
    return digests


def _alpha_registry_ready(version: str, wheel: Path, filename: str | None, repo: str) -> bool:
    """Alpha PyPI carries only the pure wheel; platform wheels exist solely on the GitHub prerelease.

    The native wheel was verified against the release provenance bundle when it was downloaded
    (authorize_macos_core_source.sh). Here it must still match the live prerelease asset, and PyPI
    must expose the same pure wheel the prerelease carries.
    """
    digests = _alpha_release_digests(repo, version)
    name = filename or wheel.name
    if name not in digests:
        return False
    if digests[name] != hashlib.sha256(wheel.read_bytes()).hexdigest():
        raise ValueError(
            "alpha prerelease asset digest mismatch; withholding updater assets "
            "(the live prerelease no longer carries the wheel the Core build was authorized from)"
        )
    pure = f"hol_guard-{version}-py3-none-any.whl"
    if pure not in digests:
        return False
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/hol-guard/{version}/json", timeout=20) as response:
            metadata = json.loads(response.read(2_000_000))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise
    if metadata["info"]["version"] != version:
        raise ValueError("PyPI version mismatch; withholding updater assets")
    matches = [item for item in metadata["urls"] if item["filename"] == pure]
    if not matches:
        return False
    if len(matches) != 1 or digests[pure] is None or matches[0]["digests"]["sha256"] != digests[pure]:
        raise ValueError("PyPI pure wheel does not match the alpha prerelease; withholding updater assets")
    return True


def registry_ready(
    version: str,
    wheel: Path,
    filename: str | None = None,
    channel: str = "stable",
    *,
    repo: str | None = None,
) -> bool:
    if channel not in _VERSION_PATTERNS or not _VERSION_PATTERNS[channel].fullmatch(version):
        raise ValueError(f"invalid {channel} version")
    if channel == "alpha":
        if repo is None:
            raise ValueError("alpha readiness requires the release repository")
        return _alpha_registry_ready(version, wheel, filename, repo)
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/hol-guard/{version}/json", timeout=20) as response:
            metadata = json.loads(response.read(2_000_000))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if metadata["info"]["version"] != version:
        raise ValueError("PyPI version mismatch; withholding updater assets")
    matches = [item for item in metadata["urls"] if item["filename"] == (filename or wheel.name)]
    if not matches:
        # Uploads are sequential: another platform can arrive before this wheel.
        return False
    if len(matches) != 1 or matches[0]["digests"]["sha256"] != digest:
        raise ValueError(
            "PyPI wheel digest mismatch; withholding updater assets "
            "(PyPI already holds a different build of this file than the GitHub release asset; "
            "PyPI files cannot be replaced, so ship the fix in a new patch release)"
        )
    return True


def _registry_ready(version: str, wheel: Path, filename: str | None, channel: str) -> bool:
    if channel == "alpha":
        return registry_ready(version, wheel, filename, channel, repo=os.environ["GITHUB_REPOSITORY"])
    return registry_ready(version, wheel, filename, channel)


def wait(
    version: str, wheel: Path, timeout: float = 600, *, filename: str | None = None, channel: str = "stable"
) -> None:
    run_id = os.environ.get("PUBLICATION_RUN_ID", "")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if run_id:
                ready = publication_ready(
                    os.environ["GITHUB_REPOSITORY"], run_id, os.environ["PUBLICATION_SOURCE_SHA"], channel
                )
            elif channel == "alpha":
                raise ValueError("alpha publication requires the publishing run identity")
            else:
                ready = True
            if ready and _registry_ready(version, wheel, filename, channel):
                print("Registry publication verified; signed updater assets may be published.")
                return
        except urllib.error.HTTPError as error:
            if error.code != 429 and error.code < 500:
                raise
            print(f"Transient registry HTTP error {error.code}; retrying publication check.")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, urllib.error.URLError):
            print("Transient publication API error; retrying verification before the deadline.")
        time.sleep(min(15, max(0, deadline - time.monotonic())))
    raise TimeoutError("registry publication was not verified before the updater deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--filename", help="Original distribution filename before copying the attested wheel")
    parser.add_argument("--bundle", type=Path, help="Verified package provenance for scheduled publication checks")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--channel", choices=tuple(_PUBLICATION_JOBS), default="stable")
    args = parser.parse_args()
    if not os.environ.get("PUBLICATION_RUN_ID"):
        if args.channel == "alpha":
            raise ValueError("alpha publication requires the publishing run identity")
        if args.bundle is None:
            raise ValueError("a publishing run or package provenance is required")
        run_id, source_sha = attested_publication_identity(
            args.wheel, args.bundle, os.environ["GITHUB_REPOSITORY"], version=args.version
        )
        os.environ["PUBLICATION_RUN_ID"] = run_id
        os.environ["PUBLICATION_SOURCE_SHA"] = source_sha
    if args.check_only:
        print("publication_run_id=" + os.environ["PUBLICATION_RUN_ID"])
        print("publication_source_sha=" + os.environ["PUBLICATION_SOURCE_SHA"])
        ready = publication_ready(
            os.environ["GITHUB_REPOSITORY"],
            os.environ["PUBLICATION_RUN_ID"],
            os.environ["PUBLICATION_SOURCE_SHA"],
            args.channel,
        )
        ready = ready and _registry_ready(args.version, args.wheel, args.filename, args.channel)
        print("registry_ready=" + str(ready).lower())
    else:
        wait(args.version, args.wheel, filename=args.filename, channel=args.channel)
