"""Human-readable Gauntlet summary rendering."""

from __future__ import annotations

import json
from typing import Any


def render_summary_markdown(report: dict[str, Any], binding: dict[str, Any], build_sha: str, version: str) -> str:
    """Render the public summary; it depends only on report contents, never completion order."""
    lines = [
        "# Guard Gauntlet",
        "",
        f"Candidate: `{binding['candidate_sha']}`",
        f"Installed build: `{build_sha}`",
        f"Host: `{version}` / `{report['platform']}`",
        f"Full profile: {report['full_profile']}",
        f"Merge-qualified: {report['merge_qualified']}",
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
