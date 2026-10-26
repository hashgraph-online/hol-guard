#!/usr/bin/env python3
"""Record or verify the policy decision parity fixtures.

``spec/guard-policy/v1alpha1/fixtures/parity/cases.json`` lists events and the policy documents they are
decided against. ``decisions.json`` holds the Decision each one produced. The Policy Studio Explain
engine must reproduce the same file, so a change to either engine shows up as a diff here.

    python scripts/record_policy_parity.py          # rewrite decisions.json
    python scripts/record_policy_parity.py --check  # fail when decisions.json is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.business_policy_document_import import compile_document_for_import
from codex_plugin_scanner.guard.policy_decision_engine import decide_command, decide_rows, parse_event
from codex_plugin_scanner.guard.policy_document import policy_document_digest
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

PARITY_DIRECTORY = Path(__file__).resolve().parents[1] / "spec" / "guard-policy" / "v1alpha1" / "fixtures" / "parity"


def record_decisions(directory: Path = PARITY_DIRECTORY) -> dict[str, object]:
    cases = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    now = str(cases["now"])
    documents = {
        name: parse_policy_document_yaml((directory / relative).read_text(encoding="utf-8"))
        for name, relative in cases["documents"].items()
    }
    decisions: dict[str, object] = {}
    for case in cases["cases"]:
        document = documents[case["document"]]
        if "command" in case:
            decision = decide_command(document, case["command"], now=now)
        else:
            rows = tuple(compile_document_for_import(document))
            decision = decide_rows(rows, parse_event(case["event"]), now=now)
        decision["document"] = {"id": document.metadata.id, "digest": policy_document_digest(document)}
        decisions[case["id"]] = decision
    return {"version": cases["version"], "now": now, "decisions": decisions}


def render(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail when decisions.json is out of date")
    args = parser.parse_args(argv)
    target = PARITY_DIRECTORY / "decisions.json"
    rendered = render(record_decisions())
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != rendered:
            print("decisions.json is out of date; run python scripts/record_policy_parity.py", file=sys.stderr)
            return 1
        return 0
    target.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
