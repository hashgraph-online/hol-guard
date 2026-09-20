"""A failed pilot cell must retain completed results and attempted counts."""

from __future__ import annotations

import importlib
import json
from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path

import pytest


@pytest.mark.parametrize("failure", ["during_case", "post_case_validation"])
def test_failed_native_comparison_preserves_the_failed_cell(tmp_path, monkeypatch, failure):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    comparison = importlib.import_module("compare_guard_mcp_native_text")
    identity = {"mcp_tool_calls.py": "risk", "proxy/runtime_mcp.py": "runtime"}
    monkeypatch.setattr(comparison, "source_identity", lambda _root: identity)
    monkeypatch.setattr(comparison, "harness_identity", lambda: {"harness": "frozen"})
    monkeypatch.setattr(comparison, "executable_identity", lambda _path: {"sha256": "native"})
    monkeypatch.setattr(comparison, "performance_lock", lambda _path: nullcontext())

    class Oracle:
        returncode = 0

        def __init__(self, *_args, **_kwargs):
            pass

        def communicate(self, **_kwargs):
            return json.dumps({"native_text_pilot": {}, "loaded_risk_sha256": "risk"}), None

    monkeypatch.setattr(comparison.subprocess, "Popen", Oracle)

    def run_case(**_options):
        if failure == "during_case":
            raise comparison.BenchmarkCaseError(
                {"attempted_tool_requests": 3, "observed_tool_responses": 2, "observed_child_forwarded_count": 2}
            )
        return {
            "loaded_runtime_sha256": {"mcp_tool_calls.py": "wrong"},
            "correctness": {"accepted": 4, "errors": 0},
        }

    monkeypatch.setattr(comparison, "run_case", run_case)
    output = tmp_path / "attempts.json"
    arguments = Namespace(
        ordinary_src=tmp_path / "B",
        text_src=tmp_path / "D",
        native_text_helper=tmp_path / "native",
        lock_file=tmp_path / "lock",
        json=output,
        samples=3,
    )
    with pytest.raises((comparison.BenchmarkCaseError, RuntimeError)):
        comparison.run_comparison(arguments)
    report = json.loads(output.read_text())
    assert report["cases"] == []
    failed = report["failed_case"]
    if failure == "during_case":
        assert failed["attempted_tool_requests"] == 3
        assert failed["observed_tool_responses"] == 2
        assert failed["observed_child_forwarded_count"] == 2
    else:
        assert failed["completed_case_result"]["correctness"]["accepted"] == 4
        assert failed["measurement_valid"] is False
        assert failed["failure_code"] == "native_mcp_comparison_wrong_runtime_loaded"
    with pytest.raises(ValueError, match="refuses_to_overwrite"):
        comparison.run_comparison(arguments)


@pytest.mark.parametrize(
    "helper_name",
    [
        "profile_guard_mcp_case.py",
        "profile_guard_mcp_fixture.py",
        "profile_guard_mcp_worker.py",
        "profile_guard_mcp_matrix.py",
    ],
)
def test_native_comparisons_bind_each_extracted_helper(monkeypatch, helper_name):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    comparison = importlib.import_module("compare_guard_mcp_native_text")
    markers = importlib.import_module("compare_guard_mcp_native_markers")
    original = comparison.harness_identity()
    assert markers.harness_identity is comparison.harness_identity
    read_bytes = Path.read_bytes

    def changed(path):
        content = read_bytes(path)
        return content + b"\n# synthetic changed helper\n" if path.name == helper_name else content

    monkeypatch.setattr(Path, "read_bytes", changed)
    observed = markers.harness_identity()

    assert set(observed) == set(original)
    assert observed[helper_name] != original[helper_name]
    assert all(observed[name] == digest for name, digest in original.items() if name != helper_name)
