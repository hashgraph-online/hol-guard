from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.native_receipt_persistence_gate import _validate_hook_routes, run

ROOT = Path(__file__).resolve().parents[1]


def test_native_receipt_persistence_gate_emits_exact_head_evidence(tmp_path: Path) -> None:
    output = tmp_path / "receipt-gate.json"
    assert run(ROOT, json_path=output) == 0
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["schema"] == "hol-guard.native-hook-receipt-persistence-gate.v1"
    assert evidence["status"] == "passed"
    assert evidence["scope"] == "NHD-079-NHD-085-reconstructed"
    assert evidence["windows_ci_cd"] == "excluded_by_request"


@pytest.mark.parametrize(
    "removed",
    ["helper", "import", "call", "shadow", "call_nested", "call_unreachable", "loop_nested", "loop_unreachable"],
)
def test_receipt_gate_rejects_disconnected_or_incomplete_mode_proof(tmp_path: Path, removed: str) -> None:
    paths = (
        "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py",
        "ci/native_runtime/probe_native_default_auto.py",
        "ci/native_runtime/default_auto_routes.py",
    )
    for relative in paths:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    probe_path = tmp_path / paths[2]
    helper_path = tmp_path / paths[3]
    if removed == "helper":
        helper_path.unlink()
    elif removed == "import":
        source = probe_path.read_text(encoding="utf-8")
        marker = "    _exercise_mode_invariants,"
        assert marker in source
        probe_path.write_text(source.replace(marker, "    # _exercise_mode_invariants,", 1), encoding="utf-8")
    elif removed.startswith("call"):
        source = probe_path.read_text(encoding="utf-8")
        marker = "mode_invariants = _exercise_mode_invariants(daemon, guard_home, workspace)"
        assert marker in source
        replacement = {
            "call": "# " + marker,
            "call_nested": "def unused_mode_proof():\n            " + marker,
            "call_unreachable": "if False:\n            " + marker,
        }[removed]
        probe_path.write_text(source.replace(marker, replacement, 1), encoding="utf-8")
    elif removed == "shadow":
        source = helper_path.read_text(encoding="utf-8")
        marker = 'for mode in ("off", "shadow"):'
        assert marker in source
        helper_path.write_text(
            source.replace(marker, "# " + marker + '\n        for mode in ("off",):', 1), encoding="utf-8"
        )
    else:
        source = helper_path.read_text(encoding="utf-8")
        start = source.index('        for mode in ("off", "shadow"):')
        end = source.index("    finally:", start)
        wrapper = "def unused_mode_proof():" if removed == "loop_nested" else "if False:"
        wrapped = "        " + wrapper + "\n" + "".join("    " + line for line in source[start:end].splitlines(True))
        helper_path.write_text(source[:start] + wrapped + source[end:], encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"mode|default_auto_routes"):
        _validate_hook_routes(tmp_path)
