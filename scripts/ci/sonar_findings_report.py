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


def main() -> None:
    output = Path("sonar-findings-report")
    output.mkdir(exist_ok=True)
    report = {"retrieved_at": datetime.now(timezone.utc).isoformat(), "errors": [], "pull_requests": {}}
    report["branches"] = read_json("sonar", "/api/project_branches/list", project=PROJECT)
    report["analyses"] = read_json("sonar", "/api/project_pull_requests/list", project=PROJECT)
    pulls = read_json("github", f"/repos/{REPOSITORY}/pulls", state="open", per_page=100)
    current = os.environ.get("PULL_REQUEST_NUMBER", "")
    scopes = [None]
    for pull in pulls:
        if "sonar" not in pull["head"]["ref"] and str(pull["number"]) != current:
            continue
        scopes.append(pull["number"])
        checks = []
        for page in range(1, 6):
            payload = read_json(
                "github", f"/repos/{REPOSITORY}/commits/{pull['head']['sha']}/check-runs",
                filter="latest", per_page=100, page=page,
            )
            checks.extend({key: item.get(key) for key in ("id", "name", "status", "conclusion", "output")}
                          for item in payload.get("check_runs", []))
            if len(checks) >= payload["total_count"]:
                break
        report["pull_requests"][str(pull["number"])] = {"head": pull["head"]["sha"], "checks": checks}
        print("PR", pull["number"], "head", pull["head"]["sha"], "nonpassing checks",
              [(c["id"], c["name"], c["status"], c["conclusion"]) for c in checks
               if c["conclusion"] not in {"success", "skipped", "neutral"}])
    for number in scopes:
        name = "main" if number is None else f"pr-{number}"
        try:
            snapshot = sonar_snapshot(number)
            (output / f"{name}.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            print(name, "open issues", snapshot["issues"]["total"], "gate", snapshot["gate"])
        except (OSError, ValueError, KeyError, TypeError) as error:
            report["errors"].append({"scope": name, "error": str(error)})
            print(name, "report error", type(error).__name__, str(error))
    (output / "metadata.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
