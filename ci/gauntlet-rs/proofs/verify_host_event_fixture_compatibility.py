"""Replay frozen host-event vectors against reviewed, unchanged Python reducers.

Main at 76efccff changed other parts of evidence.py. The historical vectors
and generators remain immutable. This proof accepts only that exact reviewed
source pair, checks normalized function ASTs against 7eba6064, and executes
only the generators' isolated stdlib-only functions, never controller imports.
"""

from __future__ import annotations

import ast
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
PROOFS = ROOT / "ci/gauntlet-rs/proofs"
FIXTURES = ROOT / "ci/gauntlet-rs/crates/gauntlet-evidence/tests"
HISTORICAL = "b76344cf9700c73abebd5d65a81d34aa28c960b591fc2bc485423afa038efe2f"
CURRENT = "720bf562b809033f3c46f0e37966d1f6fe123283290a26c3dd5955664d19524d"
FUNCTIONS = {
    "reconcile": "a70ae54c39ced369635adfab98f73cf8f719b359bdee92704fdf6459db584605",
    "read_events": "408a5d0412c2b2e91031b017e84bbbcb377495226bdeffe04757cec950e62c40",
}
GENERATORS = {
    "host-calls": (
        "freeze_host_calls_v1.py",
        "3969076a9926c8b5dd849ec190b4da205c9fb2f27cbb4c57c3a3218abb21ed16",
        "python_host_calls_v1.json",
        31,
    ),
    "omp-transcript": (
        "freeze_omp_transcript_v1.py",
        "8a9f211795f2f18f4f5db2f5df73a7edcaf972189d52f997ac97d9f6125c2913",
        "python_omp_transcript_v1.json",
        15,
    ),
}


def normalized(node):
    if isinstance(node, ast.AST):
        fields = {}
        for name, value in ast.iter_fields(node):
            # Python 3.12 adds this empty field to ordinary functions. Reject
            # generics, while comparing the same AST on Python 3.9 and 3.12+.
            if name == "type_params":
                if value:
                    raise ValueError("unexpected generic reducer")
                continue
            fields[name] = normalized(value)
        return [type(node).__name__, fields]
    if isinstance(node, list):
        return [normalized(value) for value in node]
    return node


def verify(kind: str) -> dict:
    source = ROOT / "ci/gauntlet/evidence.py"
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CURRENT:
        raise ValueError("current evidence source is outside the reviewed compatibility pair")
    tree = ast.parse(raw)
    for name, expected in FUNCTIONS.items():
        found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(found) != 1:
            raise ValueError("reducer is absent or ambiguous")
        canonical = json.dumps(normalized(found[0]), sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()
        if hashlib.sha256(canonical).hexdigest() != expected:
            raise ValueError("reviewed reducer AST changed")
    generator, digest, fixture_name, count = GENERATORS[kind]
    path = PROOFS / generator
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("historical fixture generator changed")
    spec = importlib.util.spec_from_file_location("frozen_host_event_proof", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = json.loads((FIXTURES / fixture_name).read_bytes())
    if kind == "host-calls":
        original, function = module.SOURCES["ci/gauntlet/evidence.py"]
        module.SOURCES = {**module.SOURCES, "ci/gauntlet/evidence.py": (CURRENT, function)}
        frozen = next(row["sha256"] for row in fixture["sources"]
                      if row["path"] == "ci/gauntlet/evidence.py")
    else:
        original = module.SOURCE_SHA256
        module.SOURCE_SHA256 = CURRENT
        frozen = fixture["source_sha256"]
    if original != HISTORICAL or frozen != HISTORICAL:
        raise ValueError("historical fixture source binding changed")
    captured = io.StringIO()
    with redirect_stdout(captured):
        module.main()
    replayed = json.loads(captured.getvalue())
    if (replayed["schema"] != fixture["schema"] or len(replayed["cases"]) != count
            or replayed["cases"] != fixture["cases"]):
        raise ValueError("current Python reducer differs from the immutable frozen cases")
    return {"schema": "gauntlet-host-event-source-compatibility.v1", "kind": kind,
            "historical_source_sha256": HISTORICAL, "current_source_sha256": CURRENT,
            "replayed_cases": count, "unchanged_function_asts": len(FUNCTIONS)}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in GENERATORS:
        raise SystemExit("usage: verify_host_event_fixture_compatibility.py host-calls|omp-transcript")
    print(json.dumps(verify(sys.argv[1]), sort_keys=True))
