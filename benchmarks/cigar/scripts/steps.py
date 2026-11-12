"""Per-step cost and request counts of a Codex session row, for the by-kind table."""

import json
from pathlib import Path

U, C, O = 0.10, 0.01, 0.50


def _cumulative(path):
    total = 0.0
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "turn.completed":
            u = e["usage"]
            cached = u.get("cached_input_tokens", 0)
            total += (u.get("input_tokens", 0) - cached) * U + cached * C + u.get("output_tokens", 0) * O
    return total or None


def _requests(rollout, n):
    counts, step = [0] * n, -1
    for line in Path(rollout).read_text().splitlines():
        e = json.loads(line)
        p = e.get("payload") or {}
        if e.get("type") == "response_item" and p.get("type") == "message" and p.get("role") == "user":
            text = ((p.get("content") or [{}])[0].get("text") or "").lstrip()
            if not text.startswith(("<", "#")):
                step += 1
        if e.get("type") == "event_msg" and p.get("type") == "token_count" and p.get("info") and 0 <= step < n:
            counts[step] += 1
    return counts


def codex_steps(row, runs_dir):
    """[{kind, usd, requests}] per step; usd splits the row's total by each step's share of turn usage."""
    kinds = row["kinds"]
    cums, prev = [], 0.0
    for n in range(1, len(kinds) + 1):
        c = _cumulative(Path(runs_dir) / f"{row['arm']}-s{row['seed']}-{n}.jsonl")
        cums.append(max((c or prev) - prev, 0.0))
        prev = c or prev
    whole = sum(cums) or 1.0
    try:
        requests = _requests(row["ledger"][0], len(kinds)) if row.get("ledger") else [None] * len(kinds)
    except OSError:
        requests = [None] * len(kinds)
    usd = row["cost"]["usd"]
    return [{"kind": k, "usd": round(usd * c / whole, 6), "requests": r} for k, c, r in zip(kinds, cums, requests)]


def claude_steps(row, runs_dir):
    """[{kind, usd, requests}] per step of a Claude Code row: each step's result line holds its own usage."""
    kinds, shares, requests = row["kinds"], [], []
    for n in range(1, len(kinds) + 1):
        path = Path(runs_dir) / f"{row['arm']}-s{row['seed']}-{n}.jsonl"
        u, turns = {}, None
        if path.exists():
            for line in path.read_text().splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("type") == "result":
                    u, turns = e.get("usage") or {}, e.get("num_turns")
        shares.append(
            u.get("input_tokens", 0)
            + 2 * u.get("cache_creation_input_tokens", 0)
            + 0.1 * u.get("cache_read_input_tokens", 0)
            + 5 * u.get("output_tokens", 0)
        )
        requests.append(turns)
    whole = sum(shares) or 1.0
    usd = row["cost"]["usd"]
    return [{"kind": k, "usd": round(usd * s / whole, 6), "requests": r} for k, s, r in zip(kinds, shares, requests)]


def row_steps(row, runs_dir):
    return (claude_steps if row.get("harness") == "claude-code" else codex_steps)(row, runs_dir)
