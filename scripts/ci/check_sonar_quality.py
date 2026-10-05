"""Keep main security gates blocking and report migration-wide coverage debt explicitly."""

from __future__ import annotations

import json
import os
import re
import subprocess
from decimal import Decimal
from html import escape
from pathlib import Path

from scripts.ci.sonar_quality_client import SonarClient, metadata_task
from scripts.ci.sonar_quality_policy import conditions, number

REPOSITORY = "hashgraph-online/hol-guard"
ANCHOR_COVERAGE = Decimal("61.7")


def verify_main_push(environment: dict[str, str], event: dict) -> None:
    """The coverage-only reporting policy is never available to contributor PRs."""
    if not isinstance(event, dict) or not isinstance(event.get("repository"), dict):
        raise ValueError("Push provenance is not an object")
    if (
        environment.get("GITHUB_EVENT_NAME") != "push"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or event.get("ref") != "refs/heads/main"
        or event["repository"].get("full_name") != REPOSITORY
        or event.get("forced") is not False
        or event.get("deleted") is not False
    ):
        raise ValueError("Coverage reporting policy is available only to normal main pushes")
    after = environment.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", after) is None or after == "0" * 40 or event.get("after") != after:
        raise ValueError("Push commit provenance is invalid")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=15).strip()
    if actual != after:
        raise ValueError("Checkout does not match the main push")


def evaluate(client: SonarClient, analysis_id: str, environment: dict[str, str], report: dict) -> bool:
    gate = client.gate(analysis_id)
    report.update(
        analysis_id=analysis_id, sonar_status=gate.get("status"), gate=gate, coverage_floor=str(ANCHOR_COVERAGE)
    )
    checked = conditions(gate)
    if gate.get("ignoredConditions") is not False or "new_coverage" not in checked:
        raise ValueError("Main analysis omitted coverage evidence or ignored gate conditions")
    if gate["status"] == "OK":
        report["decision"] = "full-quality-gate-passed"
        return True
    failures = {key for key, value in checked.items() if value["status"] == "ERROR"}
    if failures != {"new_coverage"}:
        return False
    if number(checked["new_coverage"]["actualValue"]) < ANCHOR_COVERAGE:
        return False
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    with event_path.open("rb") as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Push event exceeds its byte limit")
    verify_main_push(environment, json.loads(raw))
    report["decision"] = "main-coverage-debt-reported"
    return True


def evidence(report: dict, environment: dict[str, str]) -> None:
    output = Path("sonar-quality-evidence")
    output.mkdir(exist_ok=True)
    (output / "quality.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "## Sonar quality decision",
        "",
        f"CI policy: **{escape(report['decision'])}**.",
        f"Raw Sonar gate: **{escape(str(report.get('sonar_status', 'unavailable')))}**.",
        "",
        "| Condition | Actual | Required | Status |",
        "| --- | --- | --- | --- |",
    ]
    items = report.get("gate", {}).get("conditions", [])
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            values = [item.get(key, "missing") for key in ("metricKey", "actualValue", "errorThreshold", "status")]
            lines.append("| " + " | ".join(escape(str(value)).replace("|", "&#124;") for value in values) + " |")
    if report["decision"] == "main-coverage-debt-reported":
        lines += [
            "",
            "Migration-wide main coverage above the reviewed 61.7% bootstrap anchor is advisory, "
            "not a fixed target. The unchanged PR coverage gate and every current non-coverage "
            "condition remain enforced. This is not a historical coverage ratchet, an 80% result, "
            "or a green raw Sonar gate.",
        ]
    if "error" in report:
        lines += ["", "Evidence error: " + escape(report["error"])]
    markdown = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(markdown, encoding="utf-8")
    if environment.get("GITHUB_STEP_SUMMARY"):
        with Path(environment["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(markdown)


def main() -> int:
    report = {"decision": "blocked", "policy_version": 2, "revision": os.environ.get("GITHUB_SHA")}
    passed = False
    try:
        client = SonarClient(os.environ.get("SONAR_TOKEN", ""))
        analysis_id = client.analysis(metadata_task(Path(".scannerwork/report-task.txt")))
        passed = evaluate(client, analysis_id, dict(os.environ), report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    evidence(report, dict(os.environ))
    if not passed:
        print("::error::Sonar quality policy failed. See the job summary and sonar-quality-evidence artifact.")
    elif report["decision"] == "main-coverage-debt-reported":
        print("::warning::Main coverage remains below its threshold. See the measured conditions in the summary.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
