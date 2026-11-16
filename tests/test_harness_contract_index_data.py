"""The native edge's harness contract index matches the Python registry."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.protection_capabilities import capability_for

INDEX = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/data/harness_contract_index.v1.json"


def test_the_native_contract_index_matches_the_registry() -> None:
    expected = []
    for contract in HARNESS_CONTRACTS:
        payload: dict[str, object] = {
            "install_aliases": list(contract.install_aliases),
            "event_surfaces": list(contract.event_surfaces),
            "native_approval": contract.native_approval,
            "browser_fallback": contract.browser_fallback,
            "resume_support": contract.resume_support,
            "known_blind_spots": contract.known_blind_spots,
        }
        capability = capability_for(contract.harness)
        if capability is not None:
            payload.update(capability.to_dict())
        expected.append({"harness": contract.harness, "contract": payload})
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    assert index == {"schema": "guard-harness-contract-index.v1", "contracts": expected}
