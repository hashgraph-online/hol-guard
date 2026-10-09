"""Bind each CI scan to main or one API-proven pull request, never a default branch."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from scripts.ci.wait_for_pytest_shards import github_json

REPOSITORY = "hashgraph-online/hol-guard"
CONTEXT_PATH = Path("sonar-scan-context.json")
SETTINGS_PATH = Path("sonar-scan.properties")
TASK_PATH = Path(".scannerwork/report-task.txt")
MAX_CONTEXT_BYTES = 16 * 1024


def source_identity(environment: Mapping[str, str], checkout_sha: str) -> dict:
    """Require the selected branch and checkout from this exact workflow execution."""
    revision = environment.get("GITHUB_SHA", "")
    branch = environment.get("GITHUB_REF_NAME", "")
    event = environment.get("GITHUB_EVENT_NAME", "")
    if (
        environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or event not in {"push", "schedule", "workflow_dispatch"}
        or not branch
        or any(ord(character) < 32 or ord(character) == 127 for character in branch)
        or environment.get("GITHUB_REF") != f"refs/heads/{branch}"
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
        or revision == "0" * 40
        or checkout_sha != revision
    ):
        raise ValueError("Sonar source does not match the selected repository, branch and checkout")
    execution = {}
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environment.get(key, "")
        if re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
            raise ValueError("Sonar source is missing its workflow execution identity")
        execution[key] = value
    return {"repository": REPOSITORY, "revision": revision, "branch": branch, "event": event, **execution}


def select_context(
    environment: Mapping[str, str], checkout_sha: str, fetch_json: Callable[[str, float], object]
) -> dict:
    """A non-main dispatch must identify exactly one open, same-repository PR into main."""
    context = source_identity(environment, checkout_sha)
    if context["branch"] == "main":
        return {**context, "kind": "branch"}
    if context["event"] != "workflow_dispatch":
        raise ValueError("Non-main Sonar scans require a dispatch with a verified pull request")
    opened = []
    seen = set()
    deadline = time.monotonic() + 30
    for page in range(1, 11):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Sonar pull-request provenance lookup exceeded its deadline")
        pulls = fetch_json(f"/repos/{REPOSITORY}/commits/{checkout_sha}/pulls?per_page=100&page={page}", remaining)
        if not isinstance(pulls, list) or len(pulls) > 100:
            raise ValueError("Malformed commit-associated pull-request page")
        for pull in pulls:
            if not isinstance(pull, dict) or type(pull.get("id")) is not int or pull["id"] <= 0:
                raise ValueError("Malformed commit-associated pull request")
            if pull["id"] in seen:
                raise ValueError("Ambiguous commit-associated pull-request pagination")
            seen.add(pull["id"])
            if pull.get("state") == "open":
                opened.append(pull)
            elif pull.get("state") != "closed":
                raise ValueError("Commit-associated pull request has an invalid state")
        if len(pulls) < 100:
            break
    else:
        raise ValueError("Commit-associated pull requests exceed the pagination limit")
    if len(opened) != 1:
        raise ValueError("Non-main scan requires exactly one open commit-associated pull request")
    pull = opened[0]
    head, base = pull.get("head"), pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise ValueError("Pull-request source or target is missing")
    if (
        type(pull.get("number")) is not int
        or pull["number"] <= 0
        or head.get("sha") != checkout_sha
        or head.get("ref") != context["branch"]
        or not isinstance(head.get("repo"), dict)
        or head["repo"].get("full_name") != REPOSITORY
        or not isinstance(base.get("repo"), dict)
        or base["repo"].get("full_name") != REPOSITORY
        or base.get("ref") != "main"
    ):
        raise ValueError("Associated pull request does not match the exact source and main target")
    return {**context, "kind": "pull_request", "pull_request": str(pull["number"]), "base": "main"}


def checkout_revision() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=15).strip()


def read_context(environment: Mapping[str, str], checkout_sha: str) -> dict:
    """Reject context from another branch, checkout, workflow run or rerun attempt."""
    if CONTEXT_PATH.is_symlink():
        raise ValueError("Linked Sonar scan context is not accepted")
    with CONTEXT_PATH.open("rb") as stream:
        raw = stream.read(MAX_CONTEXT_BYTES + 1)
    if len(raw) > MAX_CONTEXT_BYTES:
        raise ValueError("Sonar scan context exceeds its size limit")
    context = json.loads(raw)
    expected = source_identity(environment, checkout_sha)
    if not isinstance(context, dict) or any(context.get(key) != value for key, value in expected.items()):
        raise ValueError("Sonar scan context belongs to another source or workflow execution")
    if expected["branch"] == "main":
        if context.get("kind") != "branch" or "pull_request" in context:
            raise ValueError("Main scan context cannot identify a pull request")
    elif (
        expected["event"] != "workflow_dispatch"
        or context.get("kind") != "pull_request"
        or not isinstance(context.get("pull_request"), str)
        or re.fullmatch(r"[1-9][0-9]*", context["pull_request"]) is None
        or context.get("base") != "main"
    ):
        raise ValueError("Non-main scan context is not a verified pull request into main")
    return context


def prepare(environment: Mapping[str, str]) -> None:
    context = select_context(environment, checkout_revision(), github_json)
    context["prepared_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    properties = {"sonar.scm.revision": context["revision"]}
    if context["kind"] == "branch":
        properties["sonar.branch.name"] = context["branch"]
    else:
        properties.update(
            {
                "sonar.pullrequest.key": context["pull_request"],
                "sonar.pullrequest.branch": context["branch"],
                "sonar.pullrequest.base": context["base"],
            }
        )
    # Java property values carry branch names as data, including quotes and Unicode.
    # Keep every source, report and gate setting from the repository configuration.
    settings = Path("sonar-project.properties").read_text(encoding="utf-8")
    settings += (
        "\n"
        + "\n".join(f"{key}={json.dumps(value, ensure_ascii=True)[1:-1]}" for key, value in properties.items())
        + "\n"
    )
    SETTINGS_PATH.write_text(settings, encoding="utf-8")
    CONTEXT_PATH.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
    TASK_PATH.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Verify the completed scan and its standard quality gate")
    arguments = parser.parse_args()
    report = {"decision": "blocked"}
    try:
        if not arguments.verify:
            prepare(os.environ)
            return 0
        from scripts.ci.sonar_quality_client import SonarClient, metadata_task

        context = read_context(os.environ, checkout_revision())
        task_id = metadata_task(TASK_PATH)
        client = SonarClient(os.environ.get("SONAR_TOKEN", ""))
        analysis_id = client.analysis(task_id, context)
        gate = client.gate(analysis_id)
        report.update(context=context, task_id=task_id, analysis_id=analysis_id, gate=gate)
        if gate.get("status") != "OK":
            raise ValueError("The analysis-specific standard Sonar quality gate did not pass")
        report["decision"] = "standard-gate-verified"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
        print("::error::Sonar scan identity or standard quality gate could not be verified")
    output = Path("sonar-quality-evidence")
    output.mkdir(exist_ok=True)
    (output / "identity.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["decision"] == "standard-gate-verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
