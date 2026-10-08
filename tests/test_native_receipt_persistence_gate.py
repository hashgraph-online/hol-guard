from __future__ import annotations

import json
from pathlib import Path

from scripts.ci.native_receipt_persistence_gate import run

ROOT = Path(__file__).resolve().parents[1]


def test_native_receipt_persistence_gate_emits_exact_head_evidence(tmp_path: Path) -> None:
    output = tmp_path / "receipt-gate.json"
    assert run(ROOT, json_path=output) == 0
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["schema"] == "hol-guard.native-hook-receipt-persistence-gate.v1"
    assert evidence["status"] == "passed"
    assert evidence["scope"] == "NHD-079-NHD-085-reconstructed"
    assert evidence["windows_ci_cd"] == "excluded_by_request"
