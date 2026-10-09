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


def publication_ready(repo: str, run_id: str, source_sha: str) -> bool:
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid publication run identity")
    result = json.loads(
        subprocess.check_output(["gh", "api", f"repos/{repo}/actions/runs/{run_id}"], text=True, timeout=20)
    )
    if (
        result["path"].split("@")[0] != ".github/workflows/publish.yml"
        or result["event"] != "workflow_dispatch"
        or result["head_sha"] != source_sha
    ):
        raise ValueError("publication run is not the authorized release dispatch")
    conclusions = subprocess.check_output(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100",
            "--jq",
            '.jobs[] | select(.name == "Publish main release to PyPI") | .conclusion',
        ],
        text=True,
        timeout=20,
    ).splitlines()
    if conclusions == ["success"]:
        return True
    if not conclusions and result["conclusion"] == "success":
        # Older publish workflows used different job names; require the entire run.
        return True
    if any(value not in {"null", ""} for value in conclusions) or result["conclusion"] in {"failure", "cancelled"}:
        raise ValueError("stable registry publication failed; withholding updater assets")
    return False


def registry_ready(version: str, wheel: Path, filename: str | None = None) -> bool:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid stable version")
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
        raise ValueError("PyPI wheel digest mismatch; withholding updater assets")
    return True


def wait(version: str, wheel: Path, timeout: float = 600, *, filename: str | None = None) -> None:
    run_id = os.environ.get("PUBLICATION_RUN_ID", "")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if run_id:
                ready = publication_ready(os.environ["GITHUB_REPOSITORY"], run_id, os.environ["PUBLICATION_SOURCE_SHA"])
            else:
                ready = True
            if ready and registry_ready(version, wheel, filename):
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
    args = parser.parse_args()
    if not os.environ.get("PUBLICATION_RUN_ID"):
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
            os.environ["GITHUB_REPOSITORY"], os.environ["PUBLICATION_RUN_ID"], os.environ["PUBLICATION_SOURCE_SHA"]
        )
        print("registry_ready=" + str(ready and registry_ready(args.version, args.wheel, args.filename)).lower())
    else:
        wait(args.version, args.wheel, filename=args.filename)
