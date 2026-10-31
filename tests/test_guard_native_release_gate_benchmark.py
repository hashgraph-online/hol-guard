from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench_guard_native_release_gate.py"
SPEC = importlib.util.spec_from_file_location("bench_guard_native_release_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_native_warm_uses_persistent_authenticated_resident_ipc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[dict[str, object]] = []
    monkeypatch.setattr(
        benchmark,
        "native_runtime_status",
        lambda: SimpleNamespace(
            identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
        ),
    )

    def fake_resident_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request = benchmark.json.loads(payload)
        assert isinstance(request, dict)
        requests.append(request)
        return b'{"schema":"guard-hook-edge-result.v2","authority":"rust","result":{"decision":"allow"}}'

    monkeypatch.setattr(benchmark, "native_resident_client_request", fake_resident_request)
    snapshot = {"generation": 7, "policy_digest": "b" * 64, "runtime_identity": "a" * 64}
    values = benchmark._bench_native_warm(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
        policy_snapshot=snapshot,
    )

    assert len(values) == 2
    assert [request["request_id"] for request in requests] == ["native-warm-0", "native-warm-1"]
    assert all(request["schema"] == "guard-hook-envelope.v2" for request in requests)
    assert all(request["policy_snapshot"] == snapshot for request in requests)
    assert all(request["policy_generation"] == 7 for request in requests)


def test_native_production_warm_requires_resident_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[str] = []

    def fake_review(request: object, *, observe_mode: bool, policy_snapshot: object = None) -> SimpleNamespace:
        del observe_mode
        del policy_snapshot
        requests.append(str(getattr(request, "request_id", None)))
        return SimpleNamespace(decision="allow")

    monkeypatch.setattr(benchmark, "review_post_tool_native", fake_review)
    monkeypatch.setattr(benchmark, "native_hook_route", lambda: "native_resident")
    values = benchmark._bench_native_warm_production(
        workspace=tmp_path,
        guard_home=tmp_path / "guard-home",
        iterations=2,
    )

    assert len(values) == 2
    assert requests == ["native-production-warm-0", "native-production-warm-1"]


def _gate_with_warm_hook_delay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    delay_seconds: float,
) -> tuple[int, str]:
    """Run the enforced gate over the real warm measurement with a fake hook route."""

    def fake_review(request: object, *, observe_mode: bool, policy_snapshot: object = None) -> SimpleNamespace:
        del request, observe_mode, policy_snapshot
        if delay_seconds:
            time.sleep(delay_seconds)
        return SimpleNamespace(decision="allow")

    def fake_run_benchmarks(
        *, runtime: Path, warm_iterations: int, cold_iterations: int
    ) -> tuple[list[float], list[float], list[float], float]:
        del runtime
        warm = benchmark._bench_native_warm_production(
            workspace=tmp_path,
            guard_home=tmp_path / "guard-home",
            iterations=warm_iterations,
        )
        return warm, [1.0] * warm_iterations, [10.0] * cold_iterations, 50.0

    monkeypatch.setattr(benchmark, "review_post_tool_native", fake_review)
    monkeypatch.setattr(benchmark, "native_hook_route", lambda: "native_resident")
    monkeypatch.setattr(benchmark, "_validated_runtime", lambda path: path)
    monkeypatch.setattr(benchmark, "_run_benchmarks", fake_run_benchmarks)
    argv = ["bench", "--runtime", str(tmp_path / "runtime"), "--warm-iterations", "10", "--cold-iterations", "2"]
    monkeypatch.setattr(sys, "argv", [*argv, "--enforce"])
    exit_code = benchmark.main()
    return exit_code, capsys.readouterr().err


def test_enforced_gate_fails_when_the_warm_hook_route_is_deliberately_slowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Every warm hook decision takes longer than the warm p95 ceiling.
    delay_seconds = (benchmark._MAX_WARM_P95_MS + 5.0) / 1_000.0
    exit_code, stderr = _gate_with_warm_hook_delay(tmp_path, monkeypatch, capsys, delay_seconds)

    assert exit_code == 1
    assert "PERFORMANCE GATE: warm native resident p95 exceeds 20ms" in stderr


def test_enforced_gate_passes_the_same_measurement_without_the_slowdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, stderr = _gate_with_warm_hook_delay(tmp_path, monkeypatch, capsys, 0.0)

    assert exit_code == 0
    assert "PERFORMANCE GATE" not in stderr
