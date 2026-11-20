#!/usr/bin/env python3
"""Generate the published harness claims from the harness protection contract.

``docs/guard/generated/harness-claims.v1.json`` and ``docs/guard/harness-claims.md`` are rendered
from ``src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json``. The hosted
coverage and non-coverage pages consume the JSON file, so every published copy of a claim comes from
the one contract. The native runtime validates the contract and returns the same claim rows from its
``harness_protection_contract`` operation; a Rust test pins the JSON file to those rows.

Edit the contract, then run:

    python scripts/generate_harness_claims.py          # rewrite both files
    python scripts/generate_harness_claims.py --check  # fail when a file is out of date
    python scripts/generate_harness_claims.py --check --as-of 2026-11-14T00:00:00Z
                                                       # also fail when evidence has expired
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json"
JSON_OUTPUT = ROOT / "docs/guard/generated/harness-claims.v1.json"
MARKDOWN_OUTPUT = ROOT / "docs/guard/harness-claims.md"
SCHEMA = "hol-guard.harness-claims.v1"
EVIDENCE_STATES = frozenset({"transport_ready", "live_block_proven", "live_allow_proven", "partial", "stale"})
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def valid_timestamp(value: object) -> bool:
    """A real UTC instant in the fixed ``YYYY-MM-DDTHH:MM:SSZ`` form.

    The pattern alone accepts impossible dates such as ``2026-11-31``, which
    would then compare as a future expiry.
    """
    if not isinstance(value, str) or not TIMESTAMP.match(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


FAILURE_TEXT = {
    "fail_closed": "Stops the action",
    "fail_open": "Lets the action continue",
    "observe_only": "Records only",
    "unsupported": "No enforcement",
}


def claim_rows(contract: dict[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for entry in contract["contracts"]:  # type: ignore[union-attr]
        for event in entry["capability_events"]:
            claim = event["claim"]
            rows.append(
                {
                    "harness": entry["harness"],
                    "event": event["event"],
                    "tools": list(event.get("tools", [])),
                    "transport": event["transport"],
                    "mode": event["mode"],
                    "surface": event["surface"],
                    "failure_behavior": event["failure_behavior"],
                    "state": claim["state"],
                    "expires_at": claim.get("expires_at"),
                    "limitations": list(claim.get("limitations", [])),
                    "known_blind_spots": list(event.get("known_blind_spots", [])),
                    "evidence": {
                        key: claim[key]
                        for key in (
                            "guard_version",
                            "harness_version",
                            "platform",
                            "evidence_reference",
                            "observed_at",
                        )
                        if key in claim
                    },
                }
            )
    return rows


def non_coverage(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Rows that do not stop an action when Guard fails, or that name a blind spot."""
    return [
        {
            "harness": row["harness"],
            "event": row["event"],
            "tools": row["tools"],
            "surface": row["surface"],
            "failure_behavior": row["failure_behavior"],
            "state": row["state"],
            "known_blind_spots": row["known_blind_spots"],
            "limitations": row["limitations"],
        }
        for row in rows
        if row["failure_behavior"] != "fail_closed" or row["known_blind_spots"] or row["limitations"]
    ]


def render_json(contract: dict[str, object]) -> str:
    rows = claim_rows(contract)
    document = {
        "schema": SCHEMA,
        "source": CONTRACT.relative_to(ROOT).as_posix(),
        "contract_schema": contract["schema"],
        "claims": rows,
        "non_coverage": non_coverage(rows),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def row_label(row: dict[str, object]) -> str:
    """``harness event [tools] (transport)``, naming tools only when the row splits its event by tool."""
    tools = ", ".join(row["tools"])  # type: ignore[arg-type]
    return f"{row['harness']} {row['event']}{f' [{tools}]' if tools else ''} ({row['transport']})"


def _event_cell(row: dict[str, object]) -> str:
    tools = ", ".join(f"`{tool}`" for tool in row["tools"])  # type: ignore[union-attr]
    return f"`{row['event']}`" + (f": {tools}" if tools else "")


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(contract: dict[str, object]) -> str:
    rows = claim_rows(contract)
    lines = [
        "<!-- Generated by scripts/generate_harness_claims.py from the harness protection contract. "
        "Edit the contract, not this file. -->",
        "",
        "# Harness protection claims",
        "",
        "Each row is one hook event or extension surface Guard connects to. **If Guard fails** says what "
        "happens to a state-changing action when the Guard runtime cannot answer; actions that continue "
        "anyway are named under **Not covered**. **Claim** is what the project states about the row:",
        "",
        "- `configured`: Guard installs and answers this event. No live run on an exact harness version is on record.",
        "- `transport_ready`, `live_block_proven`, `live_allow_proven`: proven on the Guard build, harness "
        "version and platform named in the row, until its expiry time.",
        "- `partial`: proven with the stated limitations.",
        "- `observe_only`: Guard records the event and cannot stop it.",
        "- `unsupported`: the harness exposes no boundary Guard can enforce.",
        "- `stale`: the evidence has expired. Treat the row as `configured`.",
        "",
        "The machine-readable copy is [`generated/harness-claims.v1.json`](generated/harness-claims.v1.json).",
    ]
    harnesses: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        harnesses.setdefault(str(row["harness"]), []).append(row)
    for harness, harness_rows in harnesses.items():
        lines += [
            "",
            f"## {harness}",
            "",
            "| Event | Surface | Transport | Mode | If Guard fails | Claim | Expires |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for row in harness_rows:
            lines.append(
                "| "
                + " | ".join(
                    _cell(str(value))
                    for value in (
                        _event_cell(row),
                        row["surface"],
                        f"`{row['transport']}`",
                        f"`{row['mode']}`",
                        FAILURE_TEXT[str(row["failure_behavior"])],
                        f"`{row['state']}`",
                        row["expires_at"] or "n/a",
                    )
                )
                + " |"
            )
    lines += [
        "",
        "## Not covered",
        "",
        "Rows that do not stop the action when Guard fails, and the blind spots each row names.",
        "",
        "| Harness | Event | Surface | If Guard fails | Blind spots and limitations |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in non_coverage(rows):
        notes = [*row["known_blind_spots"], *row["limitations"]]  # type: ignore[misc]
        lines.append(
            "| "
            + " | ".join(
                _cell(str(value))
                for value in (
                    row["harness"],
                    _event_cell(row),
                    row["surface"],
                    FAILURE_TEXT[str(row["failure_behavior"])],
                    " ".join(notes) or "None named.",
                )
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def expired(contract: dict[str, object], as_of: str) -> list[str]:
    """Evidence claims that cannot be published at ``as_of``.

    A claim backed by evidence fails when it carries no well-formed expiry or
    when its expiry is not after ``as_of``. The fixed timestamp form orders as
    text, so a missing or malformed expiry never reads as current.
    """
    failures: list[str] = []
    for row in claim_rows(contract):
        if row["state"] not in EVIDENCE_STATES:
            continue
        label = row_label(row)
        expires_at = row["expires_at"]
        if not valid_timestamp(expires_at):
            failures.append(f"{label} claims {row['state']} without a valid expires_at")
        elif expires_at <= as_of:
            failures.append(f"{label} expired {expires_at}")
    return failures


def outputs(contract: dict[str, object]) -> dict[Path, str]:
    return {JSON_OUTPUT: render_json(contract), MARKDOWN_OUTPUT: render_markdown(contract)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Fail when a generated file is out of date")
    parser.add_argument("--as-of", help="Also fail when evidence has expired at this UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    args = parser.parse_args(argv)
    if args.as_of is not None and not valid_timestamp(args.as_of):
        print("--as-of must be YYYY-MM-DDTHH:MM:SSZ", file=sys.stderr)
        return 2
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    stale = []
    for path, content in outputs(contract).items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(path.relative_to(ROOT).as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    if stale:
        print("Out of date: " + ", ".join(stale), file=sys.stderr)
        print("Run python scripts/generate_harness_claims.py", file=sys.stderr)
        return 1
    lapsed = expired(contract, args.as_of) if args.as_of else []
    if lapsed:
        print("Expired harness claims; renew the evidence or lower the claim:", file=sys.stderr)
        for line in lapsed:
            print(f"  {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
