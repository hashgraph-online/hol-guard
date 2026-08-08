from __future__ import annotations

import json
from pathlib import Path

from scripts.seo.check_public_truth_contract import validate

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/guard/public-support-manifest.v1.json"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_public_truth_contract_matches_alpha_source_contracts() -> None:
    assert validate(strict_expiry=False) == []


def test_windsurf_migration_does_not_invent_devin_support() -> None:
    data = _manifest()
    active = {h["id"] for c in data["channels"] if c["status"] == "active" for h in c["harnesses"]}
    assert "windsurf" not in active
    assert "devin" not in active
    migration = next(m for m in data["migrations"] if m["from"] == "Windsurf")
    assert migration["to"] == "Devin"
    assert migration["guardSupport"] == "unverified"


def test_stable_does_not_consume_alpha_only_cline_fact() -> None:
    data = _manifest()
    stable = next(c for c in data["channels"] if c["id"] == "stable")
    alpha = next(c for c in data["channels"] if c["id"] == "alpha")
    assert "cline" not in {h["id"] for h in stable["harnesses"]}
    assert "cline" in {h["id"] for h in alpha["harnesses"]}


def test_decision_semantics_are_not_universal_approval() -> None:
    data = _manifest()
    ids = {entry["id"] for entry in data["decisionSemantics"]}
    assert {"allow", "observe", "ask", "block", "unsupported"} <= ids
