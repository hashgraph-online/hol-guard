"""Source and accounting gates for F's fixed plan; no benchmark execution."""

from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
import json
import sys
from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path

import pytest


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("compare_guard_mcp_streaming_preparation")


def test_plan_is_the_entire_prior_e_schedule_with_only_the_arm_replaced(collector):
    previous = importlib.import_module("compare_guard_mcp_owned_preparation")
    expected = [{**cell, "arm": "F" if cell["arm"] == "E" else cell["arm"]} for cell in previous.schedule(30)]
    fixed = collector.plan_identity()
    assert collector.schedule(30) == fixed["plan"]["cells"] == expected
    assert len(expected) == 64
    assert sum(bool(cell.get("profile")) for cell in expected) == 14
    assert all(sum(cell["samples"] + 1 for cell in expected if cell["arm"] == arm) == 554 for arm in ("B", "F"))
    assert fixed["plan"]["harness_sources_sha256"] == collector.harness_identity()
    assert fixed["plan"]["prior_e_comparison_sha256"]
    assert fixed["plan"]["public_oracle_reference_sources_sha256"]


class _NormalizeWorker(ast.NodeTransformer):
    """Remove only the declared F import/flag, metadata and phase additions."""

    def visit_Expr(self, node):
        call = node.value
        if isinstance(call, ast.Call):
            values = [arg.value for arg in call.args if isinstance(arg, ast.Constant)]
            if "--streaming-preparation-pilot" in values or "_binding_matches" in values:
                return None
        return self.generic_visit(node)

    def visit_Assign(self, node):
        if any(isinstance(target, ast.Name) and target.id == "loaded_adapter_sha256" for target in node.targets):
            return None
        return self.generic_visit(node)

    def visit_If(self, node):
        if isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.And):
            attributes = [value.attr for value in node.test.values if isinstance(value, ast.Attribute)]
            if attributes == ["matrix", "streaming_preparation_pilot"]:
                return None
        return self.generic_visit(node)

    def visit_Dict(self, node):
        pairs = [
            (key, value)
            for key, value in zip(node.keys, node.values, strict=True)
            if not isinstance(key, ast.Constant) or key.value != "loaded_adapter_sha256"
        ]
        node.keys = [key for key, _value in pairs]
        node.values = [value for _key, value in pairs]
        return self.generic_visit(node)

    def generic_visit(self, node):
        node = super().generic_visit(node)
        replacements = (
            ("guard_mcp_streaming_preparation_pilot", "guard_mcp_owned_preparation_pilot"),
            ("streaming_preparation_pilot", "owned_preparation_pilot"),
            ("streaming_adapter", "owned_adapter"),
            ("streaming_pilot", "owned_pilot"),
            ("hol-guard-mcp-streaming-stdio", "hol-guard-mcp-stdio"),
        )
        for name, value in ast.iter_fields(node):
            if isinstance(value, str):
                for new, old in replacements:
                    value = value.replace(new, old)
                setattr(node, name, value)
        return node


def test_worker_preserves_all_prior_workload_deadline_quantile_and_resource_code(collector):
    root = Path(collector.__file__).parent
    previous_bytes = (root / "profile_guard_mcp_session.py").read_bytes()
    assert (
        hashlib.sha256(previous_bytes).hexdigest() == "6223e0c599e91ef0ac76d2dc510010dab7bf7c22a868e7034055233518808932"
    )
    previous = ast.parse(previous_bytes)
    current = ast.parse((root / "profile_guard_mcp_streaming_session.py").read_bytes())
    previous.body = previous.body[1:]  # Different module documentation only.
    current.body = current.body[1:]
    current = _NormalizeWorker().visit(current)
    assert ast.dump(current) == ast.dump(previous)
    worker = importlib.import_module("profile_guard_mcp_streaming_session")
    prior_worker = importlib.import_module("profile_guard_mcp_session")
    old_defaults = {
        name: parameter.default for name, parameter in inspect.signature(prior_worker.run_case).parameters.items()
    }
    new_defaults = {
        name: parameter.default for name, parameter in inspect.signature(worker.run_case).parameters.items()
    }
    new_defaults["owned_preparation_pilot"] = new_defaults.pop("streaming_preparation_pilot")
    assert new_defaults == old_defaults
    assert collector.run_case is worker.run_case


def test_worker_rejects_matrix_flag_that_cannot_select_f(collector, monkeypatch, tmp_path, capsys):
    worker = importlib.import_module("profile_guard_mcp_streaming_session")
    monkeypatch.setattr(
        sys,
        "argv",
        [str(worker.__file__), "--matrix", "--streaming-preparation-pilot", "--json", str(tmp_path / "unused.json")],
    )
    monkeypatch.setattr(worker, "run_matrix", lambda **_kwargs: pytest.fail("unsupported F flag must not run B matrix"))
    with pytest.raises(SystemExit) as error:
        worker.main()
    assert error.value.code == 2
    assert "explicit F matrix requires" in capsys.readouterr().err


@pytest.fixture
def accounting(tmp_path, monkeypatch, collector):
    runtime = {"runtime": "same-runtime"}
    reference = {"runtime": "frozen-old-public-oracle"}
    harness = {"guard_mcp_streaming_preparation_pilot.py": "exact-f-adapter"}
    args = Namespace(
        json=tmp_path / "attempt.json",
        runtime_src=tmp_path / "runtime",
        oracle_src=tmp_path / "oracle",
        lock_file=tmp_path / "lock",
        samples=30,
    )
    monkeypatch.setattr(collector, "source_identity", lambda path: reference if path.name == "oracle" else runtime)
    monkeypatch.setattr(collector, "harness_identity", lambda: harness)
    monkeypatch.setattr(
        collector,
        "plan_identity",
        lambda: {
            "sha256": "fixed-plan",
            "plan": {"harness_sources_sha256": harness, "public_oracle_reference_sources_sha256": reference},
        },
    )
    monkeypatch.setattr(collector, "oracle_identity", lambda: runtime)
    monkeypatch.setattr(collector, "performance_lock", lambda _path: nullcontext())
    monkeypatch.setattr(collector.time, "sleep", lambda _seconds: None)
    oracle_roots = []

    def oracle(path):
        oracle_roots.append(path)
        return {"cases": 3008}

    monkeypatch.setattr(collector, "verify_facts", oracle)
    calls = []

    def fake_case(**options):
        calls.append(options)
        selected = options["streaming_preparation_pilot"]
        return {
            "fixture": {"profile": False, **options},
            "loaded_runtime_sha256": runtime,
            "loaded_adapter_sha256": "exact-f-adapter" if selected else None,
            "streaming_preparation_pilot": {
                "candidate": "F",
                "comparison": "sequential_exact_bytes_without_accumulation",
                "counters": {
                    name: options["samples"] + 1
                    for name in (
                        "requests_admitted",
                        "category_derivations",
                        "preparations_completed",
                        "bound_forwards",
                    )
                },
            }
            if selected
            else None,
            "correctness": {"complete_synthetic_accounting_trace": True},
            "client_roundtrip_ms": {"p95": 1},
            "tree_cpu_ms_per_call": 1,
        }

    monkeypatch.setattr(collector, "run_case", fake_case)
    return args, calls, oracle_roots, fake_case


def test_stubbed_collector_accounts_for_all_cells_and_uses_separate_public_oracle(collector, accounting):
    args, calls, oracle_roots, _case = accounting
    result = collector.run_comparison(args)
    assert len(calls) == result["completed_cases"] == 64
    assert len(result["comparisons"]) == 32
    assert all(row["exact_correctness_parity"] for row in result["comparisons"])
    assert result["runtime_sources_sha256"]["B"] == result["runtime_sources_sha256"]["F"]
    assert oracle_roots == [args.oracle_src.resolve()]
    assert result["production_activation"] is False
    with pytest.raises(ValueError, match="refuses_to_overwrite"):
        collector.run_comparison(args)


@pytest.mark.parametrize(
    "failure", ["wrong_adapter", "baseline_adapter", "missing_counter", "fallback", "wrong_runtime"]
)
def test_wrong_or_incomplete_completed_cells_are_retained_without_credit(collector, accounting, monkeypatch, failure):
    args, calls, _oracle_roots, original = accounting

    def case(**options):
        result = original(**options)
        selected = options["streaming_preparation_pilot"]
        if failure == "baseline_adapter" and not selected:
            result["loaded_adapter_sha256"] = "unexpected"
        elif selected:
            if failure == "wrong_adapter":
                result["streaming_preparation_pilot"]["candidate"] = "E"
            elif failure == "missing_counter":
                result["streaming_preparation_pilot"]["counters"]["bound_forwards"] -= 1
            elif failure == "fallback":
                result["streaming_preparation_pilot"]["counters"]["busy_fallback"] = 1
            elif failure == "wrong_runtime":
                result["loaded_runtime_sha256"] = {"runtime": "wrong"}
        return result

    monkeypatch.setattr(collector, "run_case", case)
    with pytest.raises(RuntimeError):
        collector.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert len(calls) == (1 if failure == "baseline_adapter" else 2)
    assert len(report["cases"]) == len(calls) - 1
    assert report["failed_case"]["measurement_valid"] is False
    assert "completed_case_result" in report["failed_case"]


def test_partial_worker_failure_retains_real_counters_without_synthesizing_success(collector, accounting, monkeypatch):
    args, _calls, _oracle_roots, _original = accounting

    def case(**_options):
        raise collector.BenchmarkCaseError(
            {
                "attempted_tool_requests": 4,
                "observed_tool_responses": 2,
                "observed_child_forwarded_count": 3,
                "streaming_preparation_pilot": {"candidate": "F", "counters": {"bound_forwards": 3}},
            }
        )

    monkeypatch.setattr(collector, "run_case", case)
    with pytest.raises(collector.BenchmarkCaseError):
        collector.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    assert report["failed_case"]["attempted_tool_requests"] == 4
    assert report["failed_case"]["observed_tool_responses"] == 2
    assert report["failed_case"]["observed_child_forwarded_count"] == 3
    assert report["failed_case"]["streaming_preparation_pilot"]["counters"]["bound_forwards"] == 3


@pytest.mark.parametrize(
    "failure", ["wrong_oracle", "wrong_harness", "missing_source", "same_reference", "wrong_reference"]
)
def test_preflight_failure_is_retained_before_any_oracle_credit_or_cell(collector, accounting, monkeypatch, failure):
    args, calls, oracle_roots, _case = accounting
    if failure == "wrong_oracle":
        monkeypatch.setattr(collector, "oracle_identity", lambda: {"runtime": "wrong"})
    elif failure == "wrong_harness":
        monkeypatch.setattr(
            collector, "plan_identity", lambda: {"sha256": "plan", "plan": {"harness_sources_sha256": {}}}
        )
    elif failure == "missing_source":
        monkeypatch.setattr(collector, "source_identity", lambda _path: (_ for _ in ()).throw(FileNotFoundError()))
    elif failure == "same_reference":
        monkeypatch.setattr(collector, "source_identity", lambda _path: {"runtime": "same-runtime"})
    else:
        monkeypatch.setattr(
            collector,
            "source_identity",
            lambda path: {"runtime": "unrelated-reference" if path.name == "oracle" else "same-runtime"},
        )
    with pytest.raises((RuntimeError, ValueError, FileNotFoundError)):
        collector.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    assert calls == oracle_roots == []
    assert "public_api_facts_parity" not in report
    assert "failed_parity_gate" in report


def test_sample_count_cannot_silently_change_the_fixed_plan(collector, accounting):
    args, calls, _oracle_roots, _case = accounting
    args.samples = 3
    with pytest.raises(ValueError, match="requires_30_samples"):
        collector.run_comparison(args)
    assert calls == []
