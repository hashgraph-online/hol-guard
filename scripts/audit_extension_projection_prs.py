"""Audit open PRs before retiring legacy extension projection paths."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

REPOSITORY = "hashgraph-online/hol-guard"
LEGACY_PREFIXES = (
    "contributions/extensions/",
    "docs/guard/extensions/catalog.",
    "docs/guard/extensions/README.md",
    "contracts/extensions/trust-class-map.v1.json",
)


def github(*arguments: str):
    completed = subprocess.run(["gh", *arguments], capture_output=True, text=True, timeout=120, check=True)
    return json.loads(completed.stdout)


def audit() -> dict:
    prs = github(
        "pr",
        "list",
        "--repo",
        REPOSITORY,
        "--state",
        "open",
        "--limit",
        "1000",
        "--json",
        "number,headRefOid,changedFiles,files",
    )
    if len(prs) >= 1000:
        raise ValueError("open PR audit may be truncated")
    affected = []
    for pr in prs:
        # The PR-list connection omits rename origins. Always use the complete
        # files API so a move out of a legacy path cannot escape this audit.
        pages = github("api", f"repos/{REPOSITORY}/pulls/{pr['number']}/files?per_page=100", "--paginate", "--slurp")
        files = [item for page in pages for item in page]
        paths = [item["filename"] for item in files]
        if len(paths) != pr["changedFiles"] or len(paths) != len(set(paths)):
            raise ValueError("PR file audit is incomplete")
        current = github("api", f"repos/{REPOSITORY}/pulls/{pr['number']}")
        if (
            current["state"] != "open"
            or current["head"]["sha"] != pr["headRefOid"]
            or current["changed_files"] != len(paths)
        ):
            raise ValueError("PR changed during its file audit; retry the audit")
        origins = [item["previous_filename"] for item in files if "previous_filename" in item]
        legacy = sorted({path for path in paths + origins if path.startswith(LEGACY_PREFIXES)})
        if legacy:
            affected.append({"number": pr["number"], "head_sha": pr["headRefOid"], "paths": sorted(legacy)})
    return {"repository": REPOSITORY, "complete": True, "open_prs": len(prs), "affected_prs": affected}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"complete": True, "open_prs": result["open_prs"], "affected_prs": len(result["affected_prs"])}))


if __name__ == "__main__":
    main()
