"""Summary table for the long-task token benchmark (see bench_guard_cigar_long_task.py)."""

from __future__ import annotations

import collections
import statistics

import bench_guard_cigar_usage as usage

FIXTURE_SHA = "934813e4d421071a1b3db3973c02fe2721359a6e"
MODEL = "gpt-6-luna"
EFFORT = "medium"


def tokens_of(row: dict) -> dict:
    """The row's usage in the current shape; rows recorded before cache writes were tracked have none."""
    return {**usage.empty(), **row["tokens"]}


def cost_of(row: dict) -> dict:
    return row.get("cost") or usage.cost(tokens_of(row), row.get("model") or MODEL)


def summarize(rows: list[dict]) -> dict:
    # A rep whose codex exec crashed or timed out holds partial (or zero) tokens: count it, keep it out of
    # the statistics. Once a clean rerun of the same rep is recorded, the errored row no longer counts.
    clean = {row["rep"] for row in rows if not row.get("error")}
    failed = [row for row in rows if row.get("error") and row["rep"] not in clean]
    rows = [row for row in rows if not row.get("error")]
    inputs = [row["tokens"]["input_tokens"] for row in rows]

    def mean(values, digits: int = 0):
        values = list(values)
        return round(statistics.fmean(values), digits or None) if values else 0

    return {
        "n": len(rows),
        "errored": len(failed),
        "passed": sum(1 for row in rows if row["passed"]),
        "mean_input": round(statistics.fmean(inputs)) if inputs else 0,
        "median_input": round(statistics.median(inputs)) if inputs else 0,
        "min_input": min(inputs) if inputs else 0,
        "max_input": max(inputs) if inputs else 0,
        "mean_usd": mean((cost_of(row)["usd"] for row in rows), 4),
        "mean_input_usd": mean((cost_of(row)["input_usd"] for row in rows), 4),
        "mean_paid_tokens": mean(cost_of(row)["paid_tokens"] for row in rows),
        "mean_cached": mean(tokens_of(row)["cached_input_tokens"] for row in rows),
        "mean_cache_write": mean(tokens_of(row)["cache_write_tokens"] for row in rows),
        "mean_output": mean(tokens_of(row)["output_tokens"] for row in rows),
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
    base_usd = summary[base]["mean_usd"]
    for stats in summary.values():
        stats["change_vs_base"] = round((stats["mean_input"] - base_mean) / base_mean, 3) if base_mean else 0.0
        stats["paid_change_vs_base"] = round((stats["mean_usd"] - base_usd) / base_usd, 3) if base_usd else 0.0
        stats["all_passed"] = stats["n"] > 0 and stats["passed"] == stats["n"] and not stats["errored"]
    models = sorted({row.get("model") or MODEL for row in rows if row["arm"] in summary})
    return {
        "base": base,
        "fixture": FIXTURE_SHA,
        "models": models,
        "effort": EFFORT,
        "prices_read": usage.PRICES_READ,
        "arms": summary,
    }


def markdown(summary: dict) -> str:
    head = (
        f"Fixture pallets/click `{summary['fixture'][:10]}`, models {', '.join(summary['models'])}, "
        "six resumed prompts, usage from each harness's own ledger. Paid is the list-price cost "
        f"(prices read {summary['prices_read']}): full-price input, cache reads, cache writes and output. "
        "Raw input counts every input token, cached or not, and is shown for reference only."
    )
    lines = [
        head,
        "",
        "| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base "
        "| full-price in | cache read | cache write | output | requests | compactions | read chars |",
        "|" + "---|" * 16,
    ]
    for arm, stats in summary["arms"].items():
        cells = [
            arm,
            str(stats["n"]),
            str(stats["errored"]),
            "yes" if stats["all_passed"] else "NO",
            f"{stats['mean_usd']:.4f}",
            f"{stats['paid_change_vs_base']:+.1%}",
            f"{stats['mean_input_usd']:.4f}",
            f"{stats['mean_input']:,}",
            f"{stats['change_vs_base']:+.1%}",
            f"{stats['mean_uncached']:,}",
            f"{stats['mean_cached']:,}",
            f"{stats['mean_cache_write']:,}",
            f"{stats['mean_output']:,}",
            str(stats["mean_requests"]),
            str(stats["mean_compactions"]),
            f"{stats['mean_read_chars']:,}",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
