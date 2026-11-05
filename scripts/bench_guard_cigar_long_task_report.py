"""Summary table for the long-task token benchmark (see bench_guard_cigar_long_task.py)."""

from __future__ import annotations

import collections
import statistics

FIXTURE_SHA = "934813e4d421071a1b3db3973c02fe2721359a6e"
MODEL = "gpt-6-luna"
EFFORT = "medium"


def summarize(rows: list[dict]) -> dict:
    # A rep whose codex exec crashed or timed out holds partial (or zero) tokens: count it, keep it out of
    # the statistics. Once a clean rerun of the same rep is recorded, the errored row no longer counts.
    clean = {row["rep"] for row in rows if not row.get("error")}
    failed = [row for row in rows if row.get("error") and row["rep"] not in clean]
    rows = [row for row in rows if not row.get("error")]
    inputs = [row["tokens"]["input_tokens"] for row in rows]
    return {
        "n": len(rows),
        "errored": len(failed),
        "passed": sum(1 for row in rows if row["passed"]),
        "mean_input": round(statistics.fmean(inputs)) if inputs else 0,
        "median_input": round(statistics.median(inputs)) if inputs else 0,
        "min_input": min(inputs) if inputs else 0,
        "max_input": max(inputs) if inputs else 0,
        "mean_uncached": round(statistics.fmean(row["tokens"]["uncached_input_tokens"] for row in rows)) if rows else 0,
        "mean_requests": round(statistics.fmean(row["tokens"]["requests"] for row in rows), 1) if rows else 0,
        "mean_compactions": round(statistics.fmean(row["tokens"]["compactions"] for row in rows), 1) if rows else 0,
        "mean_read_chars": round(statistics.fmean(row["tool_output"]["chars"].get("read", 0) for row in rows))
        if rows
        else 0,
        "mean_secs": round(statistics.fmean(row["secs"] for row in rows)) if rows else 0,
    }


def report(rows: list[dict], base: str, arms: list[str]) -> dict:
    """Per-arm summary and the change against the base arm's mean."""
    by_arm = collections.defaultdict(list)
    for row in rows:
        by_arm[row["arm"]].append(row)
    missing = [arm for arm in [base, *arms] if arm not in by_arm]
    if missing:
        raise ValueError(f"no recorded runs for arm(s) {', '.join(missing)}; recorded: {', '.join(sorted(by_arm))}")
    summary = {arm: summarize(by_arm[arm]) for arm in dict.fromkeys([base, *arms])}
    base_mean = summary[base]["mean_input"]
    for stats in summary.values():
        stats["change_vs_base"] = round((stats["mean_input"] - base_mean) / base_mean, 3) if base_mean else 0.0
        stats["all_passed"] = stats["n"] > 0 and stats["passed"] == stats["n"] and not stats["errored"]
    return {"base": base, "fixture": FIXTURE_SHA, "model": MODEL, "effort": EFFORT, "arms": summary}


def markdown(summary: dict) -> str:
    head = (
        f"Fixture pallets/click `{summary['fixture'][:10]}`, Codex `{summary['model']}` {summary['effort']}, "
        "six resumed prompts, rollout `token_usage_record` sums."
    )
    lines = [
        head,
        "",
        "| Arm | n | errored | all pass | mean input | median | min-max | vs base "
        "| uncached | requests | compactions | read chars |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for arm, stats in summary["arms"].items():
        cells = [
            arm,
            str(stats["n"]),
            str(stats["errored"]),
            "yes" if stats["all_passed"] else "NO",
            f"{stats['mean_input']:,}",
            f"{stats['median_input']:,}",
            f"{stats['min_input']:,}-{stats['max_input']:,}",
            f"{stats['change_vs_base']:+.1%}",
            f"{stats['mean_uncached']:,}",
            str(stats["mean_requests"]),
            str(stats["mean_compactions"]),
            f"{stats['mean_read_chars']:,}",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
