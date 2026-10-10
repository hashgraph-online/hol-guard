from __future__ import annotations

import importlib.util
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
