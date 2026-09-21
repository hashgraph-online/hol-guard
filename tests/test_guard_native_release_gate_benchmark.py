from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_benchmark_oracle import BenchmarkPythonOracle, validate_semantic_response

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench_guard_native_release_gate.py"
SPEC = importlib.util.spec_from_file_location("bench_guard_native_release_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_shared_semantic_policy_is_explicit_and_ack_must_match(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    default = effective_native_policy_v3(load_guard_config(guard_home, workspace=tmp_path))
    assert default["default_action"] == "warn"
    with pytest.raises(RuntimeError, match="does not match"):
        benchmark._require_benchmark_policy({"mode": "enforce", "effective_policy": default})
    benchmark._prepare_benchmark_policy(guard_home)
    effective = effective_native_policy_v3(load_guard_config(guard_home, workspace=tmp_path))
    snapshot = {"mode": "enforce", "effective_policy": effective}
    benchmark._require_benchmark_policy(snapshot)
    for name in ("default_action", "subprocess_action", "unknown_publisher_action"):
        changed = copy.deepcopy(effective)
        changed[name] = "warn"
        with pytest.raises(RuntimeError, match="does not match"):
            benchmark._require_benchmark_policy({"mode": "enforce", "effective_policy": changed})
    with pytest.raises(RuntimeError, match="does not match"):
        benchmark._require_benchmark_policy({**snapshot, "mode": "observe"})


def test_native_policy_warning_is_named_but_never_accepted_as_content_scan() -> None:
    response = {"decision": "allow", "model_output_action": "allow_original", "reason_code": "native_policy_warning"}
    with pytest.raises(RuntimeError, match="reason=native_policy_warning"):
        validate_semantic_response(response, route="native_resident", expected_route="native_resident", case="benign")


def test_isolated_python_oracle_performs_semantic_work_without_production_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    for key in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(HookWorker, "_test_python_oracle_factory", None)
    (tmp_path / "guard-home").mkdir()
    benchmark._prepare_benchmark_policy(tmp_path / "guard-home")
    runner = BenchmarkPythonOracle(workspace=tmp_path, guard_home=tmp_path / "guard-home")
    try:
        runner.start()
        for case in ("benign", "secret"):
            benchmark._python_review(runner, case=case)
        assert runner.process.pid != os.getpid()
    finally:
        runner.close()
        runner.close()  # Cleanup remains safe after a failed/closed reader.
    assert os.environ["HOL_GUARD_NATIVE"] == "force"
    assert HookWorker._test_python_oracle_factory is None


@pytest.mark.parametrize(
    ("response", "route", "case"),
    [
        ({"decision": "allow", "reason_code": "native_hook_disabled"}, "python_semantic", "benign"),
        (
            {"decision": "allow", "model_output_action": "allow_original", "reason_code": "output_scan_allow"},
            None,
            "benign",
        ),
        (
            {"decision": "allow", "model_output_action": "allow_original", "reason_code": "output_scan_allow"},
            "native_fail_safe",
            "benign",
        ),
        (
            {"decision": "allow", "model_output_action": "allow_original", "reason_code": "output_scan_allow"},
            "python_semantic",
            "secret",
        ),
        (
            {"decision": "deny", "model_output_action": "block", "reason_code": "engine_exception"},
            "python_semantic",
            "secret",
        ),
    ],
)
def test_semantic_validation_rejects_availability_wrong_route_and_wrong_reason(
    response: dict[str, str],
    route: str | None,
    case: str,
) -> None:
    with pytest.raises(RuntimeError, match="semantic validation failed"):
        validate_semantic_response(response, route=route, expected_route="python_semantic", case=case)


def test_python_reference_warm_and_cold_run_real_child(tmp_path: Path) -> None:
    warm = benchmark._bench_python_warm_reference(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )
    cold = benchmark._bench_python_cold(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )
    assert len(warm) == len(cold) == 2
    assert all(value > 0 for value in [*warm, *cold])


def test_native_warm_uses_persistent_authenticated_resident_ipc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, object]] = []
    monkeypatch.setattr(
        benchmark,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64)),
    )

    def fake_resident_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request = benchmark.json.loads(payload)
        assert isinstance(request, dict)
        requests.append(request)
        return (
            b'{"result":{"decision":"allow","model_output_action":"allow_original","reason_code":"output_scan_allow"}}'
        )

    monkeypatch.setattr(benchmark, "native_resident_client_request", fake_resident_request)
    monkeypatch.setattr(benchmark, "_decode_edge", lambda value: value)
    values = benchmark._bench_native_warm(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
        policy_snapshot={"generation": 3, "policy_digest": "a" * 64, "runtime_identity": "b" * 64},
    )
    assert len(values) == 2
    assert all(request["schema"] == "guard-hook-envelope.v2" for request in requests)
    assert all(request["policy_generation"] == 3 for request in requests)
    assert requests[0]["raw_payload"] != requests[1]["raw_payload"]


def test_native_production_warm_requires_resident_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        benchmark,
        "review_post_tool_native",
        lambda *_args, **_kwargs: SimpleNamespace(
            decision="allow", model_output_action="allow_original", reason_code="output_scan_allow"
        ),
    )
    monkeypatch.setattr(benchmark, "native_hook_route", lambda: "native_resident")
    values = benchmark._bench_native_warm_production(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )
    assert len(values) == 2
    monkeypatch.setattr(benchmark, "native_hook_route", lambda: "native_fail_safe")
    with pytest.raises(RuntimeError, match="semantic validation failed"):
        benchmark._bench_native_warm_production(
            workspace=tmp_path,
            guard_home=tmp_path / "guard-home",
            iterations=1,
        )
