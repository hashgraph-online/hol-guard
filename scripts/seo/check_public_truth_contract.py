#!/usr/bin/env python3
"""Fail CI when HOL Guard's public support contract is unsafe or stale."""
from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/guard/public-support-manifest.v1.json"
CONTRACTS = ROOT / "src/codex_plugin_scanner/guard/adapters/contracts.py"


def _harness_ids_from_contracts() -> set[str]:
    text = CONTRACTS.read_text(encoding="utf-8")
    return set(re.findall(r'harness="([a-z0-9-]+)"', text))


def validate(strict_expiry: bool = True) -> list[str]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors: list[str] = []
    if data.get("schemaVersion") != "1.0.0":
        errors.append("unsupported schemaVersion")
    channels = {item["id"]: item for item in data.get("channels", [])}
    if "stable" not in channels or "alpha" not in channels:
        errors.append("stable and alpha channels are required")
    alpha = channels.get("alpha", {})
    alpha_ids = {item["id"] for item in alpha.get("harnesses", []) if item.get("support") in {"supported", "partial"}}
    contract_ids = _harness_ids_from_contracts()
    if alpha_ids != contract_ids:
        errors.append(f"alpha harness manifest drift: manifest={sorted(alpha_ids)} contracts={sorted(contract_ids)}")
    for channel in channels.values():
        if strict_expiry and channel.get("status") == "active" and date.fromisoformat(channel["expiresAt"]) < date.today():
            errors.append(f"expired active channel: {channel['id']}")
        ids = [item["id"] for item in channel.get("harnesses", [])]
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate harness in {channel['id']}")
    all_active = {item["id"] for c in channels.values() if c.get("status") == "active" for item in c.get("harnesses", []) if item.get("support") != "retracted"}
    if "windsurf" in all_active:
        errors.append("Windsurf must not be published as a current harness")
    if "devin" in all_active:
        errors.append("Devin must not be published until a source contract exists")
    migrations = data.get("migrations", [])
    if not any(m.get("from") == "Windsurf" and m.get("to") == "Devin" and m.get("guardSupport") in {"unverified", "unsupported"} for m in migrations):
        errors.append("Windsurf -> Devin migration must be recorded without inventing support")
    semantics = {item["id"] for item in data.get("decisionSemantics", [])}
    for required in {"allow", "observe", "ask", "block", "unsupported"}:
        if required not in semantics:
            errors.append(f"missing decision semantic: {required}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-expiry", action="store_true")
    args = parser.parse_args()
    errors = validate(strict_expiry=not args.no_expiry)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    print("HOL Guard public truth contract: OK")


if __name__ == "__main__":
    main()
