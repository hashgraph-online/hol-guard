"""Human-readable Gauntlet summary rendering."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

USAGE_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens", "reasoning_tokens")


def inference_usage(case_dir: Path, case_ids: Iterable[str]) -> dict[str, int]:
    """Sum the informational token counters the relay stored on each completed case."""
    totals = {key: 0 for key in USAGE_KEYS}
    rounds = 0
    rounds_with_usage = 0
    for case_id in case_ids:
        data = json.loads((case_dir / f"{case_id}.json").read_text(encoding="utf-8"))
        inference = data.get("inference")
        if not isinstance(inference, dict):
            continue
        for row in inference.get("live_rounds", []):
            rounds += 1
            usage = row.get("usage")
            if not isinstance(usage, dict):
                continue
            rounds_with_usage += 1
            for key in USAGE_KEYS:
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    totals[key] += value
    return {**totals, "rounds": rounds, "rounds_with_usage": rounds_with_usage}


def render_summary_markdown(report: dict[str, Any], binding: dict[str, Any], build_sha: str, version: str) -> str:
    """Render the public summary; it depends only on report contents, never completion order."""
    usage = report.get("inference_usage")
    lines = [
        "# Guard Gauntlet",
        "",
        f"Candidate: `{binding['candidate_sha']}`",
        f"Installed build: `{build_sha}`",
        f"Host: `{version}` / `{report['platform']}`",
        f"Full profile: {report['full_profile']}",
        f"Merge-qualified: {report['merge_qualified']}",
        *(
            [
                f"Inference tokens: input {usage['prompt_tokens']} (cached {usage['cached_tokens']}), "
                f"output {usage['completion_tokens']} over {usage['rounds']} rounds"
            ]
            if usage
            else []
        ),
        "",
        "Hook HTTP round-trip latency (nearest-rank; milliseconds):",
        f"Samples: {report['hook_latency']['samples']}; missing: {report['hook_latency']['missing_samples']}; "
        f"failed attempts: {report['hook_latency']['failed_attempts']}",
        "",
        "| p50 | p90 | p95 | p99 | mean | max |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        "| "
        + " | ".join(
            json.dumps(report["hook_latency"][key])
            for key in ("p50_ms", "p90_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms")
        )
        + " |",
        "",
        "| Event | Samples | p50 | p90 | p95 | p99 | mean | max |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        *[
            "| "
            + event
            + " | "
            + " | ".join(
                json.dumps(values[key])
                for key in ("samples", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms")
            )
            + " |"
            for event, values in report["hook_latency"]["by_event"].items()
        ],
        "",
        "| Scenario | Outcome | Actual tools |",
        "| --- | --- | ---: |",
    ]
    lines.extend(f"| {c['id']} | {c['outcome']} | {c['tool_calls']} |" for c in report["cases"])
    return "\n".join(lines) + "\n"
