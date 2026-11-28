from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.hook_review import hook_worker_readiness as readiness


def test_native_admission_posture_is_transported_to_rust(monkeypatch, tmp_path: Path) -> None:
    publisher = SimpleNamespace(guard_home=tmp_path / "guard-home", current_runtime_status=lambda: object())
    requests: list[dict[str, object]] = []

    def resident_request(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        requests.append(request)
        return {
            "schema": "guard-hook-policy-admission-result.v1",
            "result": {
                "request_id": request["request_id"],
                "wait_for_ack": False,
            },
        }

    monkeypatch.setattr(readiness, "_resident_request", resident_request)

    assert readiness._native_wait_for_ack(
        publisher, "native_client_timed_out", 4, readiness.time.monotonic() + 1.0
    ) is False
    assert requests[0]["schema"] == "guard-hook-policy-admission-request.v1"
    assert requests[0]["last_error"] == "native_client_timed_out"
    assert requests[0]["resident_failure_streak"] == 4


def test_missing_native_admission_result_uses_python_compatibility_path(tmp_path: Path, monkeypatch) -> None:
    publisher = SimpleNamespace(guard_home=tmp_path / "guard-home", current_runtime_status=lambda: object())
    monkeypatch.setattr(readiness, "_resident_request", lambda **_kwargs: None)

    assert readiness._native_wait_for_ack(
        publisher, "native_client_timed_out", 1, readiness.time.monotonic() + 1.0
    ) is None
