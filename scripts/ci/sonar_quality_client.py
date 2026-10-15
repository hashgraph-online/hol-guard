"""Read bounded analysis-specific Sonar evidence from a fixed, no-redirect origin."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROJECT = "hashgraph-online_hol-guard"
ORIGIN = "https://sonarcloud.io"
MAX_BYTES = 4 * 1024 * 1024
ENDPOINTS = {
    "/api/ce/task",
    "/api/qualitygates/project_status",
    "/api/project_analyses/search",
    "/api/project_pull_requests/list",
}


class NoRedirect(HTTPRedirectHandler):
    """Never forward a scanner credential to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def identifier(value: object) -> str:
    """Task and analysis IDs are opaque bounded tokens, never URLs."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is None:
        raise ValueError("Invalid Sonar analysis identifier")
    return value


def timestamp(value: object) -> datetime:
    """Compare scanner and server timestamps without accepting a missing timezone."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Missing or invalid Sonar analysis timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid Sonar analysis timestamp") from error
    if result.tzinfo is None:
        raise ValueError("Sonar analysis timestamp has no timezone")
    return result


def metadata_task(path: Path) -> str:
    """Use only this scan's task ID, rejecting foreign or ambiguous metadata."""
    if path.is_symlink():
        raise ValueError("Symlinked scan metadata is not accepted")
    with path.open("rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("Scan metadata exceeds the byte limit")
    values = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError("Malformed or duplicate scan metadata")
        values[key] = value
    if values.get("projectKey") != PROJECT or values.get("serverUrl", "").rstrip("/") != ORIGIN:
        raise ValueError("Scan metadata does not identify the configured Sonar project")
    return identifier(values.get("ceTaskId"))


class SonarClient:
    """A single bounded budget covers task polling and all gate/baseline reads."""

    def __init__(self, token: str, *, timeout: float = 280) -> None:
        if not token or "\n" in token or "\r" in token:
            raise ValueError("SONAR_TOKEN is missing or invalid")
        self.token = token
        self.deadline = time.monotonic() + timeout
        self.opener = build_opener(NoRedirect())

    def read(self, endpoint: str, **parameters: object) -> dict:
        if endpoint not in ENDPOINTS:
            raise ValueError("Unsupported Sonar endpoint")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Sonar evidence polling timed out")
        request = Request(
            ORIGIN + endpoint + "?" + urlencode(parameters),
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        with self.opener.open(request, timeout=min(20, remaining)) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Sonar response exceeds the byte limit")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Sonar response is not an object")
        return payload

    def analysis(self, task_id: str, context: dict) -> str:
        identifier(task_id)
        while True:
            task = self.read("/api/ce/task", id=task_id).get("task")
            if not isinstance(task, dict) or task.get("id") != task_id or task.get("componentKey") != PROJECT:
                raise ValueError("Sonar task does not match this scan")
            if task.get("status") == "SUCCESS":
                analysis_id = identifier(task.get("analysisId"))
                self.verify_source(task, analysis_id, context)
                return analysis_id
            if task.get("status") not in {"PENDING", "IN_PROGRESS"}:
                raise ValueError("Sonar analysis failed or was cancelled")
            time.sleep(min(3, max(0, self.deadline - time.monotonic())))

    def verify_source(self, task: dict, analysis_id: str, context: dict) -> None:
        """Reject stale tasks and a server analysis of another revision or context."""
        prepared = timestamp(context.get("prepared_at"))
        if timestamp(task.get("submittedAt")) < prepared:
            raise ValueError("Sonar task predates this workflow scan")
        if context.get("kind") == "branch":
            if task.get("branch") != context["branch"] or task.get("pullRequest") is not None:
                raise ValueError("Sonar task belongs to another branch or pull request")
            analyses = self.read("/api/project_analyses/search", project=PROJECT, branch=context["branch"], ps=1).get(
                "analyses"
            )
            if (
                not isinstance(analyses, list)
                or len(analyses) != 1
                or not isinstance(analyses[0], dict)
                or analyses[0].get("key") != analysis_id
                or analyses[0].get("revision") != context["revision"]
                or timestamp(analyses[0].get("date")) < prepared
            ):
                raise ValueError("Sonar branch analysis is stale or belongs to another revision")
        elif context.get("kind") == "pull_request":
            if (
                task.get("pullRequest") != context["pull_request"]
                or task.get("branch", context["branch"]) != context["branch"]
            ):
                raise ValueError("Sonar task belongs to another pull request or source branch")
            pulls = self.read("/api/project_pull_requests/list", project=PROJECT).get("pullRequests")
            if not isinstance(pulls, list) or any(not isinstance(pull, dict) for pull in pulls):
                raise ValueError("Sonar pull-request analysis inventory is malformed")
            matches = [pull for pull in pulls if pull.get("key") == context["pull_request"]]
            if len(matches) != 1:
                raise ValueError("Sonar pull-request analysis is missing or ambiguous")
            pull = matches[0]
            if (
                pull.get("branch") != context["branch"]
                or pull.get("base") != context["base"]
                or not isinstance(pull.get("commit"), dict)
                or pull["commit"].get("sha") != context["revision"]
                or timestamp(pull.get("analysisDate")) < prepared
            ):
                raise ValueError("Sonar pull-request analysis is stale or belongs to another source")
        else:
            raise ValueError("Unsupported Sonar scan context")

    def gate(self, analysis_id: str) -> dict:
        gate = self.read("/api/qualitygates/project_status", analysisId=identifier(analysis_id)).get("projectStatus")
        if not isinstance(gate, dict):
            raise ValueError("Analysis-specific gate is missing")
        return gate
