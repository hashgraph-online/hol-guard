"""Usage ledgers and list prices for the long-task token benchmark.

Every harness keeps its own record of what each model request cost. The
benchmark reads that record, never an estimate, and normalizes it to one row
shape so arms on different harnesses land in the same table:

    input_tokens          every input token sent, cached or not
    cached_input_tokens   input served from the provider's prompt cache
    cache_write_tokens    input written to the cache (billed above list on Anthropic)
    uncached_input_tokens input billed at the full input price
    output_tokens         generated tokens, reasoning included
    requests              model requests in the session
    compactions           times the harness summarized the chat

The raw input total mostly counts the same chat prefix re-read from cache on
every turn, which bills at a tenth of the input price. The number a user
pays for is `cost_usd`, the list-price sum of the five token kinds.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

# USD per million tokens, read from each provider's public price page on PRICES_READ.
# cache_write applies to Anthropic only: Claude Code writes the 1-hour cache (2x input);
# the 5-minute cache bills at 1.25x input.
PRICES_READ = "2026-11-05"
PRICES = {
    "gpt-6-luna": {"input": 0.10, "cached": 0.01, "cache_write": 0.10, "output": 0.50},
    "claude-haiku-4-5": {"input": 1.00, "cached": 0.10, "cache_write": 2.00, "cache_write_5m": 1.25, "output": 5.00},
}
FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "uncached_input_tokens",
    "output_tokens",
    "requests",
    "compactions",
)


class NoUsageLedgerError(RuntimeError):
    """The harness keeps no local record of model usage; the report says so instead of guessing."""


def empty() -> dict:
    return dict.fromkeys(FIELDS, 0)


def price_of(model: str) -> dict:
    for name, price in PRICES.items():
        if model == name or model.startswith(name + "-"):
            return price
    raise KeyError(f"no list price recorded for model {model!r}; add it to PRICES with the date read")


def cost(tokens: dict, model: str) -> dict:
    """List-price cost of one session, split into input and output, in USD."""
    price = price_of(model)
    write_5m = tokens.get("cache_write_5m_tokens", 0)
    write_1h = tokens["cache_write_tokens"] - write_5m
    input_cost = (
        tokens["uncached_input_tokens"] * price["input"]
        + tokens["cached_input_tokens"] * price["cached"]
        + write_1h * price["cache_write"]
        + write_5m * price.get("cache_write_5m", price["cache_write"])
    ) / 1e6
    output_cost = tokens["output_tokens"] * price["output"] / 1e6
    return {
        "input_usd": round(input_cost, 6),
        "output_usd": round(output_cost, 6),
        "usd": round(input_cost + output_cost, 6),
        # The bill expressed in full-price input tokens: comparable across arms of one model.
        "paid_tokens": round((input_cost + output_cost) * 1e6 / price["input"]),
    }


def codex_rollout(path: Path) -> dict:
    """Codex: every `token_usage_record` in the thread's rollout, compaction calls included.

    `turn.completed` usage and per-step session rows are cumulative and must not be summed.
    OpenAI reports cached input inside `input_tokens` and has no separate cache-write charge.
    """
    totals = collections.Counter()
    requests = compactions = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("type") == "compacted":
            compactions += 1
            continue
        if record.get("type") != "token_usage_record":
            continue
        usage = record.get("payload", {}).get("usage", {})
        requests += 1
        for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
            totals[key] += int(usage.get(key) or 0)
    return {
        "input_tokens": totals["input_tokens"],
        "cached_input_tokens": totals["cached_input_tokens"],
        "cache_write_tokens": 0,
        "uncached_input_tokens": totals["input_tokens"] - totals["cached_input_tokens"],
        "output_tokens": totals["output_tokens"],
        "requests": requests,
        "compactions": compactions,
    }


def claude_transcripts(projects: Path, session_id: str) -> list[Path]:
    """The session's transcript plus any subagent transcripts Claude Code wrote beside it."""
    main = sorted(projects.glob(f"*/{session_id}.jsonl"))
    if not main:
        return []
    return [main[-1], *sorted((main[-1].parent / session_id).rglob("*.jsonl"))]


def claude_transcript(paths: list[Path]) -> dict:
    """Claude Code: `message.usage` of each assistant message in the session transcripts.

    One API response is written as several lines (one per content block) that repeat the
    same usage, so each message id counts once. Anthropic reports `input_tokens` without
    the cached part; cache reads and writes are separate counts.
    """
    if not paths:
        raise NoUsageLedgerError("no Claude Code transcript for this session")
    seen: set[str] = set()
    totals = collections.Counter()
    compactions = 0
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("{"):
                continue
            record = json.loads(line)
            if record.get("type") == "system" and record.get("subtype") == "compact_boundary":
                compactions += 1
                continue
            message = record.get("message") or {}
            usage = message.get("usage")
            if record.get("type") != "assistant" or not usage or message.get("id") in seen:
                continue
            seen.add(message.get("id"))
            totals["uncached"] += int(usage.get("input_tokens") or 0)
            totals["read"] += int(usage.get("cache_read_input_tokens") or 0)
            totals["write"] += int(usage.get("cache_creation_input_tokens") or 0)
            totals["write_5m"] += int((usage.get("cache_creation") or {}).get("ephemeral_5m_input_tokens") or 0)
            totals["output"] += int(usage.get("output_tokens") or 0)
    return {
        "input_tokens": totals["uncached"] + totals["read"] + totals["write"],
        "cached_input_tokens": totals["read"],
        "cache_write_tokens": totals["write"],
        "cache_write_5m_tokens": totals["write_5m"],
        "uncached_input_tokens": totals["uncached"],
        "output_tokens": totals["output"],
        "requests": len(seen),
        "compactions": compactions,
    }
