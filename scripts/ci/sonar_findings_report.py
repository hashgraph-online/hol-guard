"""Export read-only Sonar findings, coverage gaps, and their analyzed revisions."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PROJECT = "hashgraph-online_hol-guard"
REPOSITORY = "hashgraph-online/hol-guard"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
METRICS = (
    "new_coverage,new_lines_to_cover,new_uncovered_lines,"
    "new_conditions_to_cover,new_uncovered_conditions"
)


def read_json(service: str, path: str, **parameters: object) -> object:
    """Only contact the two fixed report origins; never send credentials to Sonar."""
    if service == "github":
        origin = "https://api.github.com"
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif service == "sonar":
        origin = "https://sonarcloud.io"
        headers = {"Accept": "application/json"}
    else:
        raise ValueError("unsupported report service")
    query = urlencode(parameters)
    request = Request(origin + path + ("?" + query if query else ""), headers=headers)
    with urlopen(request, timeout=30) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError("report response exceeded the byte limit")
    return json.loads(data)


def sonar_pages(path: str, field: str, **parameters: object) -> dict:
    items = []
    for page in range(1, 21):
        payload = read_json("sonar", path, p=page, ps=100, **parameters)
        items.extend(payload.get(field, []))
        total = payload.get("total", payload.get("paging", {}).get("total", len(items)))
        if len(items) >= total:
            return {field: items, "total": total}
    raise ValueError("report exceeds the pagination limit")


def sonar_snapshot(pull_request: int | None) -> dict:
    scope = {} if pull_request is None else {"pullRequest": pull_request}
    issues = sonar_pages(
        "/api/issues/search", "issues", componentKeys=PROJECT, resolved="false", **scope
    )
    measures = sonar_pages(
        "/api/measures/component_tree", "components", component=PROJECT,
        metricKeys=METRICS, qualifiers="FIL", **scope,
    )
    snapshot = {
        "issues": issues,
        "coverage": measures,
        "gate": read_json("sonar", "/api/qualitygates/project_status", projectKey=PROJECT, **scope),
    }
    if pull_request is not None:
        sources = {}
        for component in measures["components"]:
            has_gaps = any(
                metric["metric"].startswith("new_uncovered")
                and float(metric.get("period", {}).get("value", metric.get("value", "0"))) > 0
                for metric in component.get("measures", [])
            )
            if has_gaps:
                sources[component["key"]] = read_json(
                    "sonar", "/api/sources/lines", key=component["key"],
                    **{"from": 1, "to": 1000}, **scope,
                )
        snapshot["sources"] = sources
    return snapshot


def github_pages(path: str, field: str | None = None) -> list:
    """Fetch the full bounded result or report explicit truncation."""
    items = []
    for page in range(1, 21):
        parameters = {"per_page": 100, "page": page}
        parameters.update({"state": "open"} if field is None else {"filter": "latest"})
        payload = read_json("github", path, **parameters)
        batch = payload if field is None else payload[field]
        if not isinstance(batch, list):
            raise ValueError("invalid paginated response")
        items.extend(batch)
        if field is None:
            if len(batch) < 100:
                return items
        elif len(items) >= payload["total_count"]:
            return items
        elif not batch:
            raise ValueError("incomplete paginated response")
    raise ValueError("GitHub report exceeds the pagination limit; results are incomplete")


def _record_error(report: dict, scope: str, error: Exception) -> None:
    report["errors"].append({"scope": scope, "error": str(error)})
    print(scope, "report error", type(error).__name__, str(error))


def _collect_report(output: Path, report: dict) -> None:
    errors = (OSError, ValueError, KeyError, TypeError)
    for name, path in (("branches", "/api/project_branches/list"), ("analyses", "/api/project_pull_requests/list")):
        try:
            report[name] = read_json("sonar", path, project=PROJECT)
        except errors as error:
            _record_error(report, name, error)
    try:
        pulls = github_pages(f"/repos/{REPOSITORY}/pulls")
    except errors as error:
        _record_error(report, "pull-request-discovery", error)
        pulls = []
    current = os.environ.get("PULL_REQUEST_NUMBER", "")
    if current:
        try:
            if not current.isascii() or not current.isdecimal() or int(current) <= 0:
                raise ValueError("invalid triggering pull request number")
            current = str(int(current))
            trigger = read_json("github", f"/repos/{REPOSITORY}/pulls/{current}")
            pulls = [pull for pull in pulls if pull["number"] != trigger["number"]]
            pulls.append(trigger)
        except errors as error:
            _record_error(report, "triggering-pull-request", error)
    scopes = [None]
    for pull in pulls:
        name = "pull-request-checks"
        try:
            if "sonar" not in pull["head"]["ref"] and str(pull["number"]) != current:
                continue
            number = pull["number"]
            name = f"pr-{number}-checks"
            scopes.append(number)
            head = pull["head"]["sha"]
            report["pull_requests"][str(number)] = {"head": head, "checks": [], "checks_complete": False}
            checks = github_pages(f"/repos/{REPOSITORY}/commits/{head}/check-runs", "check_runs")
            checks = [{key: item.get(key) for key in ("id", "name", "status", "conclusion", "output")}
                      for item in checks]
            report["pull_requests"][str(number)].update(checks=checks, checks_complete=True)
            print("PR", number, "head", head, "nonpassing checks",
                  [(c["id"], c["name"], c["status"], c["conclusion"]) for c in checks
                   if c["conclusion"] not in {"success", "skipped", "neutral"}])
        except errors as error:
            _record_error(report, name, error)
    for number in scopes:
        name = "main" if number is None else f"pr-{number}"
        try:
            snapshot = sonar_snapshot(number)
            (output / f"{name}.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            print(name, "open issues", snapshot["issues"]["total"], "gate", snapshot["gate"])
        except errors as error:
            _record_error(report, name, error)


def main() -> None:
    output = Path("sonar-findings-report")
    output.mkdir(exist_ok=True)
    report = {"retrieved_at": datetime.now(timezone.utc).isoformat(), "errors": [], "pull_requests": {}}
    try:
        _collect_report(output, report)
    except (OSError, ValueError, KeyError, TypeError) as error:
        _record_error(report, "report", error)
    finally:
        (output / "metadata.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
