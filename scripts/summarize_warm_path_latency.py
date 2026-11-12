#!/usr/bin/env python3
"""Summarize a warm-path latency run as markdown and JSON (reporting only, no gates)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from warm_path_stats import median, percentile, spread_ratio

_PATH_TITLES = {"hook": "Warm benign PreToolUse hook (process spawn to exit)", "mcp": "Warm non-package MCP tools/call"}
# A run set is reported as noisy when per-round p95 values span more than this share of their median.
NOISE_SPREAD = 0.15
# Distinct refusal reasons carried into the summary for one target.
REASON_LIMIT = 6
# Characters that would otherwise let refusal text open a code span, a link, a
# table cell or emphasis in the published report.
_MARKDOWN_ESCAPES = str.maketrans({c: "\\" + c for c in "\\`*_[]|<>#"})
# A decision class is a short token in a code span; anything longer or stranger
# than that came from a hook's own answer and is cut down to fit.
_CLASS_TOKEN_CHARS = 40


def _by_round(item: tuple[str, object]) -> tuple[int, str]:
    """Order round keys by their number, so round 10 follows round 9."""

    key = item[0]
    return (int(key), key) if key.lstrip("-").isdigit() else (sys.maxsize, key)


def _inline(text: str) -> str:
    """Refusal text as one escaped markdown fragment.

    A hook's stderr is arbitrary: a traceback, a wrapped message, a line that
    starts with a pipe or a hash. Collapsing it to one line and escaping the
    characters markdown reads keeps a refusal a readable sentence instead of a
    new heading, table or link in the job summary.
    """

    return " ".join(text.split()).translate(_MARKDOWN_ESCAPES)


def _class(name: str) -> str:
    """A decision class as a code span that cannot carry markdown.

    A class is built from the decision a hook answered with, so a backtick or a
    newline in that answer reaches the report. A code span cannot be escaped
    from the inside, so the name is reduced to the characters a class is made
    of and bounded before it is wrapped.
    """

    token = re.sub(r"[^0-9A-Za-z_-]+", "_", name).strip("_")[:_CLASS_TOKEN_CHARS]
    return f"`{token or 'unnamed'}`"


def _classes(counts: dict[str, int]) -> str:
    """Decision classes as `name x count` pairs."""

    return ", ".join(f"{_class(name)} x{count}" for name, count in sorted(counts.items())) or "none"


def _rows(document: dict[str, object], path: str, label: str) -> list[dict[str, object]]:
    rows = []
    for entry in document["rounds"]:  # type: ignore[union-attr]
        phase = entry["results"].get(label, {}).get(path)
        if isinstance(phase, dict) and "samples_ms" in phase:
            rows.append(
                {
                    "round": entry["round"],
                    "phase": phase,
                    "calibration": entry["results"][label]["calibration_spawn_ms"],
                }
            )
    return rows


def _optional_median(values: list[object]) -> float | None:
    """Median of the values that were actually measured; None when the metric was not collected."""

    present = [float(value) for value in values if value is not None]  # type: ignore[arg-type]
    return median(present) if present else None


def _role_medians(rows: list[dict[str, object]]) -> dict[str, dict[str, float]]:
    """Median process count and RSS, anonymous RSS and PSS MB per role over the rounds that recorded
    roles (absent role or metric = 0)."""

    recorded = [r["phase"]["service"]["roles"] for r in rows if "roles" in r["phase"]["service"]]  # type: ignore[index,operator]
    names = sorted({role for roles in recorded for role in roles})
    return {
        role: {
            metric: median([float(roles.get(role, {}).get(metric, 0)) for roles in recorded])
            for metric in ("processes", "rss_mb", "anon_mb", "pss_mb")
        }
        for role in names
    }


def _role_cpu_medians(rows: list[dict[str, object]]) -> dict[str, float]:
    """Median CPU ms per call per role over the rounds that recorded it (absent role = 0)."""

    recorded = [
        r["phase"]["service_cpu_ms_per_call_by_role"]  # type: ignore[index]
        for r in rows
        if "service_cpu_ms_per_call_by_role" in r["phase"]  # type: ignore[operator]
    ]
    names = sorted({role for roles in recorded for role in roles})
    return {role: median([float(roles.get(role, 0.0)) for roles in recorded]) for role in names}


def _setup_statuses(rows: list[dict[str, object]]) -> dict[str, int]:
    """How each round's pre-timing setup went (MCP only), e.g. ``daemon_ensure=ok``."""

    statuses: dict[str, int] = {}
    for r in rows:
        setup = r["phase"].get("setup") or {}  # type: ignore[union-attr]
        labels = [f"daemon_ensure={setup['daemon_ensure']['status']}"] if "daemon_ensure" in setup else []
        if "warmup_session" in setup:
            labels.append(f"warmup_call={setup['warmup_session']['call_class']}")
        for label in labels:
            statuses[label] = statuses.get(label, 0) + 1
    return statuses


def _non_allow_detail(rows: list[dict[str, object]]) -> dict[str, object]:
    """Where the refused samples landed and why, over the rounds that recorded it.

    A pooled count cannot tell a warm-up window apart from a steady refusal, and
    one class can cover several reasons, so the per-round counts, the sample runs
    and the first distinct reasons are carried through to the summary. A round
    whose runs the probe itself cut short is named, so a report that shows only
    the early positions says so rather than reading as the whole picture.
    """

    per_round: dict[str, int] = {}
    runs: dict[str, list[list[int]]] = {}
    truncated: list[str] = []
    reasons: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for r in rows:
        detail = r["phase"].get("non_ok")  # type: ignore[union-attr]
        if not isinstance(detail, dict):
            continue
        label = str(r["round"])
        per_round[label] = int(detail["count"])
        if detail["runs"]:
            runs[label] = detail["runs"]  # type: ignore[assignment]
        if detail.get("runs_truncated"):
            truncated.append(label)
        for reason in detail["reasons"]:  # type: ignore[union-attr]
            key = (str(reason["class"]), str(reason["detail"]))
            if key in seen:
                continue
            seen.add(key)
            reasons.append({"round": r["round"], **reason})
    return {
        "per_round": per_round,
        "runs": runs,
        "runs_truncated": truncated,
        "reasons": reasons[:REASON_LIMIT],
    }


def summarize_label(rows: list[dict[str, object]]) -> dict[str, object]:
    per_round = {q: [float(r["phase"]["stats_ms"][q]) for r in rows] for q in ("p50", "p95", "p99")}  # type: ignore[index]
    pooled = [value for r in rows for value in r["phase"]["samples_ms"]]  # type: ignore[index]
    classes: dict[str, int] = {}
    for r in rows:
        for key, count in r["phase"]["classes"].items():  # type: ignore[index]
            classes[key] = classes.get(key, 0) + int(count)
    return {
        "rounds": len(rows),
        "samples": len(pooled),
        "median_of_round_p50_ms": median(per_round["p50"]),
        "median_of_round_p95_ms": median(per_round["p95"]),
        "median_of_round_p99_ms": median(per_round["p99"]),
        "round_p95_ms": per_round["p95"],
        "round_p95_spread": spread_ratio(per_round["p95"]),
        "pooled_p50_ms": percentile(pooled, 50),
        "pooled_p95_ms": percentile(pooled, 95),
        "pooled_p99_ms": percentile(pooled, 99),
        "classes": classes,
        "non_allow": sum(int(r["phase"]["non_allow"]) for r in rows),  # type: ignore[index]
        "non_allow_detail": _non_allow_detail(rows),
        "client_cpu_ms_per_call": _optional_median([r["phase"].get("client_cpu_ms_per_call") for r in rows]),  # type: ignore[union-attr]
        "service_cpu_ms_per_call": median([float(r["phase"]["service_cpu_ms_per_call"]) for r in rows]),  # type: ignore[index]
        "service_rss_mb": median([float(r["phase"]["service"]["rss_mb"]) for r in rows]),  # type: ignore[index]
        "service_pss_mb": _optional_median([r["phase"]["service"].get("pss_mb") for r in rows]),  # type: ignore[union-attr]
        "service_processes": median([float(r["phase"]["service"]["processes"]) for r in rows]),  # type: ignore[index]
        "service_fds": median([float(r["phase"]["service"]["fds"]) for r in rows]),  # type: ignore[index]
        "service_roles": _role_medians(rows),
        "service_role_cpu_ms_per_call": _role_cpu_medians(rows),
        "setup": _setup_statuses(rows),
        "calibration_spawn_p50_ms": median([float(r["calibration"]["p50"]) for r in rows]),  # type: ignore[index]
    }


def build_summary(document: dict[str, object], baseline: str, candidate: str) -> dict[str, object]:
    summary: dict[str, object] = {"baseline": baseline, "candidate": candidate, "paths": {}}
    for path in document["config"]["paths"]:  # type: ignore[index]
        base_rows, cand_rows = _rows(document, path, baseline), _rows(document, path, candidate)
        entry: dict[str, object] = {"title": _PATH_TITLES[path]}
        shared = sorted({int(r["round"]) for r in base_rows} & {int(r["round"]) for r in cand_rows})  # type: ignore[call-overload]
        if shared:
            # Only rounds in which both targets produced a result enter the comparison.
            base_rows = [r for r in base_rows if r["round"] in shared]
            cand_rows = [r for r in cand_rows if r["round"] in shared]
            base, cand = summarize_label(base_rows), summarize_label(cand_rows)
            paired = [
                100.0 * (float(c["phase"]["stats_ms"]["p95"]) / float(b["phase"]["stats_ms"]["p95"]) - 1.0)  # type: ignore[index]
                for b, c in zip(base_rows, cand_rows, strict=True)
            ]
            delta = 100.0 * (float(cand["median_of_round_p95_ms"]) / float(base["median_of_round_p95_ms"]) - 1.0)
            noisy = max(float(base["round_p95_spread"]), float(cand["round_p95_spread"])) > NOISE_SPREAD
            entry.update(
                {
                    "baseline": base,
                    "candidate": cand,
                    "matched_rounds": shared,
                    "p95_delta_pct": delta,
                    "paired_round_p95_delta_pct": paired,
                    "noisy": noisy,
                    "decision_parity": set(base["classes"]) == set(cand["classes"]),  # type: ignore[call-overload]
                }
            )
        else:
            entry["error"] = "no round has a result from both targets for this path"
        summary["paths"][path] = entry  # type: ignore[index]
    return summary


def _format_optional(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.1f}"  # type: ignore[arg-type]


def _format_roles(roles: dict[str, dict[str, float]], cpu_ms_per_call: dict[str, float] | None = None) -> str:
    parts = []
    for role, values in roles.items():
        part = f"{role} {values['processes']:g}x {values['rss_mb']:.1f} MB"
        if values.get("pss_mb"):
            part += f" (anon {values['anon_mb']:.1f}, PSS {values['pss_mb']:.1f})"
        if cpu_ms_per_call and role in cpu_ms_per_call:
            part += f" {cpu_ms_per_call[role]:.2f} CPU ms/call"
        parts.append(part)
    return ", ".join(parts) or "none recorded"


def render_markdown(document: dict[str, object], summary: dict[str, object]) -> str:
    runner = document["runner"]
    config = document["config"]
    lines = [
        "## Matched warm-path latency",
        "",
        f"Runner: {runner['platform']}; {runner['cpu_model']}; {runner['logical_cpus']} logical CPUs; "  # type: ignore[index]
        f"image {runner['image_os']} {runner['image_version']}.",  # type: ignore[index]
        f"Rounds: {config['rounds']} per target, alternating order, one runner, fresh home and daemon per round.",  # type: ignore[index]
        "Targets: "
        + "; ".join(f"`{t['label']}` = `{t['sha']}` (hol-guard {t['wheel_version']})" for t in document["targets"]),  # type: ignore[union-attr]
        "",
    ]
    for entry in summary["paths"].values():  # type: ignore[union-attr]
        lines += [f"### {entry['title']}", ""]
        if "error" in entry:
            lines += [f"No result: {entry['error']}", ""]
            continue
        lines += [
            "| target | rounds | samples | p50 ms | p95 ms | p99 ms | pooled p95 ms | round-p95 spread | "
            "client CPU ms/call | service CPU ms/call | service RSS MB | service procs | non-allow |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for role in ("baseline", "candidate"):
            s = entry[role]
            lines.append(
                f"| {summary[role]} | {s['rounds']} | {s['samples']} | {s['median_of_round_p50_ms']:.2f} | "
                f"{s['median_of_round_p95_ms']:.2f} | {s['median_of_round_p99_ms']:.2f} | {s['pooled_p95_ms']:.2f} | "
                f"{100 * s['round_p95_spread']:.1f}% | {_format_optional(s['client_cpu_ms_per_call'])} | "
                f"{s['service_cpu_ms_per_call']:.2f} | {s['service_rss_mb']:.1f} | "
                f"{s['service_processes']:.0f} | {s['non_allow']} |"
            )
        lines.append("")
        for role in ("baseline", "candidate"):
            s = entry[role]
            setup = ", ".join(f"{key} x{count}" for key, count in sorted(s["setup"].items()))
            roles = _format_roles(s["service_roles"], s.get("service_role_cpu_ms_per_call"))
            lines.append(
                f"Service by role (median), `{summary[role]}`: {roles}." + (f" Setup: {setup}." if setup else "")
            )
        for role in ("baseline", "candidate"):
            s = entry[role]
            if not s["non_allow"]:
                continue
            detail = s["non_allow_detail"]
            per_round = ", ".join(
                f"round {key} x{count}" for key, count in sorted(detail["per_round"].items(), key=_by_round)
            )
            reasons = "; ".join(
                f"{_class(str(reason['class']))} at round {reason['round']} sample {reason['index']}"
                + (f": {_inline(str(reason['detail']))}" if reason["detail"] else "")
                for reason in detail["reasons"]
            )
            cut = set(detail["runs_truncated"])
            runs = ", ".join(
                "round {key} {spans}{more}".format(
                    key=key,
                    spans=",".join(f"{first}-{last}" for first, last in value),
                    more=" and later positions not recorded" if key in cut else "",
                )
                for key, value in sorted(detail["runs"].items(), key=_by_round)
            )
            lines.append(
                f"Non-allow samples, `{summary[role]}`: {s['non_allow']}"
                + (f" ({per_round})" if per_round else "")
                + "."
                + (f" Sample runs: {runs}." if runs else "")
                + (f" Reasons: {reasons}." if reasons else "")
            )
        flags = []
        if entry["noisy"]:
            flags.append(f"round p95 spread above {int(NOISE_SPREAD * 100)}%: treat the delta as inconclusive")
        if len(entry["matched_rounds"]) < int(config["rounds"]):  # type: ignore[arg-type]
            flags.append(
                f"only {len(entry['matched_rounds'])} of {config['rounds']} rounds have a result from both targets"
            )
        if not entry["decision_parity"]:
            flags.append("decision classes differ between targets: timed cohorts are not comparable")
        paired = ", ".join(f"{value:+.1f}%" for value in entry["paired_round_p95_delta_pct"])
        lines += [
            "",
            f"p95 delta (median of per-round p95, candidate vs baseline): **{entry['p95_delta_pct']:+.1f}%**. "
            f"Per-round paired deltas: {paired}.",
            f"Decision classes baseline {_classes(entry['baseline']['classes'])}, "  # type: ignore[arg-type]
            f"candidate {_classes(entry['candidate']['classes'])}.",  # type: ignore[arg-type]
        ]
        lines += [f"Flag: {flag}." for flag in flags] or ["No noise or parity flags."]
        lines.append("")
    lines.append(
        "Method: p50/p95/p99 use linear interpolation per round; headline values are the median across rounds. "
        "Whole-process spawn latency is measured for hooks; an open proxy session is measured for tools/call, "
        "after the daemon is ensured and one untimed warm-up session has run for every target."
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--baseline", required=True, help="baseline target label")
    parser.add_argument("--candidate", required=True, help="candidate target label")
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    document = json.loads(args.input.read_text(encoding="utf-8"))
    summary = build_summary(document, args.baseline, args.candidate)
    markdown = render_markdown(document, summary)
    if args.markdown:
        args.markdown.write_text(markdown, encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    sys.stdout.write(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
