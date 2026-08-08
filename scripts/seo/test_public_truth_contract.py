#!/usr/bin/env python3
"""Lightweight truth-contract assertions without importing the Guard runtime."""
from __future__ import annotations

import json
from pathlib import Path

from check_public_truth_contract import validate

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/guard/public-support-manifest.v1.json"

data = json.loads(MANIFEST.read_text(encoding="utf-8"))
assert validate(strict_expiry=False) == []
active = {
    harness["id"]
    for channel in data["channels"]
    if channel["status"] == "active"
    for harness in channel["harnesses"]
}
assert "windsurf" not in active
assert "devin" not in active
migration = next(item for item in data["migrations"] if item["from"] == "Windsurf")
assert migration["to"] == "Devin"
assert migration["guardSupport"] == "unverified"
stable = next(item for item in data["channels"] if item["id"] == "stable")
alpha = next(item for item in data["channels"] if item["id"] == "alpha")
assert "cline" not in {item["id"] for item in stable["harnesses"]}
assert "cline" in {item["id"] for item in alpha["harnesses"]}
semantics = {item["id"] for item in data["decisionSemantics"]}
assert {"allow", "observe", "ask", "block", "unsupported"} <= semantics
print("HOL Guard public truth contract assertions: OK")
