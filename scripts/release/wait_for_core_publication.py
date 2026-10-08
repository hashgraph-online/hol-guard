"""Let signing run early while withholding updater assets until publication succeeds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


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
        if run_id:
            ready = publication_ready(os.environ["GITHUB_REPOSITORY"], run_id, os.environ["PUBLICATION_SOURCE_SHA"])
        else:
            ready = True
        if ready and registry_ready(version, wheel, filename):
            print("Registry publication verified; signed updater assets may be published.")
            return
        time.sleep(min(15, max(0, deadline - time.monotonic())))
    raise TimeoutError("registry publication was not verified before the updater deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--filename", help="Original distribution filename before copying the attested wheel")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if args.check_only:
        print("registry_ready=" + str(registry_ready(args.version, args.wheel, args.filename)).lower())
    else:
        wait(args.version, args.wheel, filename=args.filename)
