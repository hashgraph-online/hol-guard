"""Require source-bound live evidence inside the existing Python CI aggregate."""

from __future__ import annotations

import re
from typing import Any

from .github_ci import CONTEXT, PASS_DESCRIPTION_PREFIX, GitHubAPI, changed_paths, requires_gauntlet
from .trust import validate_producer_revision

EVIDENCE_WORKFLOW = ".github/workflows/guard-gauntlet-evidence.yml"


def require_evidence(api: GitHubAPI, event: dict[str, Any]) -> None:
    """A status alone is insufficient: require its successful trusted producer and artifact."""
    number = event["pull_request"]["number"]
    candidate = event["pull_request"]["head"]["sha"]
    pull = api.pull(number, candidate)
    if not requires_gauntlet(changed_paths(api, number, pull)):
        print("Guard Gauntlet: no enforcement or acceptance-system changes in this PR")
        return
    run_id = qualified_run(api, number, candidate, pull)
    print(f"Guard Gauntlet: verified exact-head live evidence from trusted workflow run {run_id}")


def qualified_run(api: GitHubAPI, number: int, candidate: str, pull: dict[str, Any]) -> str:
    """Validate existing evidence without overwriting an unchanged success."""
    latest = None
    for page in range(1, 21):
        rows = api.request(f"/commits/{candidate}/statuses?per_page=100&page={page}")
        latest = next((row for row in rows if row.get("context") == CONTEXT), None)
        if latest is not None or len(rows) < 100:
            break
    instruction = (
        "Guard Gauntlet requires fresh real-agent evidence for this exact PR head. "
        "Run the live suite, pack the verified public evidence, dispatch Guard Gauntlet evidence, "
        "wait for its successful validation, then rerun failed CI jobs. See ci/gauntlet/README.md."
    )
    if latest is None or latest.get("state") != "success":
        raise RuntimeError(instruction)
    match = re.fullmatch(
        r"https://github\.com/" + re.escape(api.repo) + r"/actions/runs/([0-9]+)", latest.get("target_url", "")
    )
    if match is None:
        raise RuntimeError("Gauntlet status has no repository-owned producer run")
    run_id = match.group(1)
    run = api.request(f"/actions/runs/{run_id}")
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or run.get("path", "").split("@", 1)[0] != EVIDENCE_WORKFLOW
        or run.get("head_repository", {}).get("full_name") != api.repo
    ):
        raise RuntimeError("Gauntlet evidence producer is incomplete, failed or untrusted. " + instruction)
    validate_producer_revision(api, number, pull, run)
    artifacts = api.request(f"/actions/runs/{run_id}/artifacts?per_page=100")
    names = [
        artifact
        for artifact in artifacts.get("artifacts", [])
        if artifact.get("name") == "guard-gauntlet-" + candidate and artifact.get("expired") is False
    ]
    if len(names) != 1:
        raise RuntimeError("Gauntlet producer has no unique unexpired evidence artifact for this head")
    # A once-green test merge must not qualify a different integration after
    # main advances. Resolve the published source against the current PR base.
    source_match = re.fullmatch(
        re.escape(PASS_DESCRIPTION_PREFIX) + r"([0-9a-f]{40})", latest.get("description", "") or ""
    )
    if source_match is None:
        raise RuntimeError("Gauntlet status is missing its verified source binding")
    api.prove_source(source_match.group(1), candidate, pull["gauntlet_base_sha"])
    return run_id
