"""Compare source-only Rust fixtures with the actual Python policy producers.

The generators run inside the explicit test oracle context. The context is
restored before Cargo runs; native results never supply their own expectations.
Full native composition is covered by the restored Rust test modules.
"""

from __future__ import annotations

import json
import os
import subprocess
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_mode import python_oracle_surface_enabled
from tests import native_generic_policy_vectors as generic
from tests import native_sensitive_read_mixed_origin_vectors as mixed
from tests import native_sensitive_read_policy_vectors as ordinary

ROOT = Path(__file__).resolve().parents[1]
RUST_TEST = (
    "policy_scoped_enforcement::policy_vector_commitment_tests::source_defined_policy_vectors_match_declared_case_sets"
)
COMMON = ("name", "harness", "source", "payload", "artifactId", "mode")
FIELDS = {
    "ordinary": (*COMMON, "effectivePolicy", "expected"),
    # The native mixed-origin test overwrites the flattened effectivePolicy
    # with localEffectivePolicy before evaluation. Only the latter is consumed.
    "mixed": (*COMMON, "localEffectivePolicy", "managedConfiguration", "expected"),
    "generic": (
        "name",
        "harness",
        "mode",
        "payload",
        "artifactId",
        "localEffectivePolicy",
        "managedConfiguration",
        "expected",
    ),
}
COUNTS = {"ordinary": 133, "mixed": 188, "generic": 260}


def _commitment(fixture: dict[str, object], name: str) -> dict[str, object]:
    cases = fixture["cases"]
    assert isinstance(cases, list)
    assert len(cases) == COUNTS[name]
    assert all(isinstance(case, dict) for case in cases)
    rows = cast(list[dict[str, object]], cases)
    assert len({case["name"] for case in rows}) == COUNTS[name]
    projected = [{key: case[key] for key in FIELDS[name]} for case in rows]
    encoded = json.dumps(projected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "count": len(rows),
        "fields": list(FIELDS[name]),
        "sha256": sha256(encoded).hexdigest(),
    }


@pytest.mark.slow
def test_source_defined_native_policy_vectors_match_actual_python(tmp_path: Path) -> None:
    before = dict(os.environ)
    with pytest.MonkeyPatch.context() as oracle:
        oracle.setenv("HOL_GUARD_NATIVE", "off")
        oracle.setenv("HOL_GUARD_TEST_MODE", "1")
        oracle.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
        oracle.setenv("HOL_GUARD_NATIVE_DIAGNOSTIC", "1")
        assert python_oracle_surface_enabled()
        expected = {
            "schema": "native-policy-vector-commitments.v1",
            "ordinary": _commitment(ordinary.generate_vectors(tmp_path / "ordinary"), "ordinary"),
            "mixed": _commitment(mixed.generate_vectors(tmp_path / "mixed"), "mixed"),
            "generic": _commitment(generic.generate_vectors(tmp_path / "generic"), "generic"),
        }
    assert dict(os.environ) == before
    native_environment = dict(os.environ)
    for key in (
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "PYTEST_CURRENT_TEST",
    ):
        native_environment.pop(key, None)
    native_environment["HOL_GUARD_NATIVE"] = "auto"
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "rust/Cargo.toml",
            "-p",
            "hol-guard-runtime",
            "--bin",
            "hol-guard-runtime",
            RUST_TEST,
            "--",
            "--exact",
            "--nocapture",
        ],
        cwd=ROOT,
        env=native_environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"Rust vector commitment test failed with status {completed.returncode}")
    marker = "POLICY_VECTOR_COMMITMENT="
    lines = [line.split(marker, 1)[1] for line in completed.stdout.splitlines() if marker in line]
    assert len(lines) == 1
    assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in completed.stdout
    actual = json.loads(lines[0])
    assert actual == expected
