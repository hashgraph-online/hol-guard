#!/usr/bin/env python3
"""Promote one harness protection claim from a live evidence receipt.

A receipt (schema ``hol-guard.harness-claim-evidence.v1``) records a run against a real harness:
which capability row it exercised, the exact Guard build, harness version and platform, and the
native decisions Guard returned. The native runtime's ``harness_claim_promotion`` operation decides
whether the receipt may raise the row's claim. Receipts that report a unit test, fixture, replay or
probe are always refused, and a live block claim needs a native deny before the action ran plus a
benign allow on the same event. This script only carries the receipt to the runtime, writes the claim
the runtime returns into the contract, and regenerates the published claims.

The receipt is not authenticated: its source, inference, verifier and witness fields are
self-reported. A promoted claim is a proposed contract change, and the reviewer of that change must
confirm the run named by ``evidence_reference`` before merging it.

    python scripts/promote_harness_claim.py receipt.json            # show the decision
    python scripts/promote_harness_claim.py receipt.json --write    # write the promoted claim

Receipts must use synthetic or redacted values only: no local paths, prompts, file contents or
command arguments. The runtime refuses a receipt with any field it does not know.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json"

Decide = Callable[[str, dict[str, Any]], Any]


def _native_decide(operation: str, params: dict[str, Any]) -> Any:
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard.native_cli_runtime_support import cli_runtime_support

    return cli_runtime_support(operation, params)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_claim(contract: dict[str, Any], receipt: dict[str, Any], claim: dict[str, Any]) -> None:
    """Replace the claim on the one row the receipt names."""
    for entry in contract["contracts"]:
        if entry["harness"] != receipt["harness"]:
            continue
        for event in entry["capability_events"]:
            if (event["event"], event["transport"], event.get("surface")) == (
                receipt["event"],
                receipt["transport"],
                receipt["surface"],
            ):
                event["claim"] = claim
                return
    raise ValueError("the contract declares no row for this receipt")


def main(argv: list[str] | None = None, decide: Decide = _native_decide) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt", type=Path, help="Evidence receipt JSON")
    parser.add_argument("--write", action="store_true", help="Write the promoted claim and regenerate")
    parser.add_argument("--now", default=None, help="Decision time, YYYY-MM-DDTHH:MM:SSZ (default: now)")
    args = parser.parse_args(argv)
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    text = CONTRACT.read_text(encoding="utf-8")
    decision = decide("harness_claim_promotion", {"receipt": receipt, "contract": text, "now": args.now or _now()})
    if not isinstance(decision, dict) or not isinstance(decision.get("promotable"), bool):
        print("The native runtime returned no promotion decision.", file=sys.stderr)
        return 2
    if not decision["promotable"]:
        print("Not promoted:", file=sys.stderr)
        for refusal in decision.get("refusals", []):
            print(f"  {refusal}", file=sys.stderr)
        return 1
    claim = decision["claim"]
    print(json.dumps(claim, indent=2))
    if decision.get("provenance") == "self_reported":
        print(
            "The receipt is self-reported. Confirm the run named by evidence_reference"
            " when reviewing this contract change.",
            file=sys.stderr,
        )
    if not args.write:
        return 0
    contract = json.loads(text)
    apply_claim(contract, receipt, claim)
    CONTRACT.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sys.path.insert(0, str(ROOT / "scripts"))
    import generate_harness_claims

    return generate_harness_claims.main([])


if __name__ == "__main__":
    raise SystemExit(main())
