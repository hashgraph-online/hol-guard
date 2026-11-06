from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_bash_ack
from codex_plugin_scanner.guard.native_bash_protocol import NativeBashError
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256


def _valid(request):
    return {
        "schema": "guard-native-bash-ack-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + _canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "acknowledged": True,
    }


def test_ack_retries_the_same_request_after_a_lost_response_and_records_success(monkeypatch, tmp_path):
    requests = []
    successes = []
    sleeps = []
    status = SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))

    def resident(**kwargs):
        requests.append(kwargs["request"])
        return None if len(requests) == 1 else _valid(kwargs["request"])

    monkeypatch.setattr(native_bash_ack, "runtime_status", lambda: status)
    monkeypatch.setattr(native_bash_ack, "_resident_request", resident)
    monkeypatch.setattr(
        native_bash_ack, "native_record_resident_success", lambda digest, home: successes.append((digest, home))
    )
    monkeypatch.setattr(native_bash_ack.time, "sleep", sleeps.append)
    assert native_bash_ack.acknowledge(
        guard_home=tmp_path,
        store_path=tmp_path / "guard.db",
        base_id="bash-operation:" + "b" * 64,
        harness="omp",
        project=tmp_path / "project",
        tool_call_id="call-1",
        exit_code=0,
    )
    assert requests[0] is requests[1]
    assert sleeps == [native_bash_ack._RETRY_DELAY_SECONDS]
    assert successes == [("a" * 64, tmp_path)]


def test_ack_still_refuses_after_two_invalid_responses(monkeypatch, tmp_path):
    requests = []
    status = SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))

    def resident(**kwargs):
        requests.append(kwargs["request"])
        return {"status": "error"}

    monkeypatch.setattr(native_bash_ack, "runtime_status", lambda: status)
    monkeypatch.setattr(native_bash_ack, "_resident_request", resident)
    monkeypatch.setattr(
        native_bash_ack, "native_record_resident_success", lambda *_: pytest.fail("invalid ACK recorded success")
    )
    monkeypatch.setattr(native_bash_ack.time, "sleep", lambda _: None)
    with pytest.raises(NativeBashError, match="native_bash_ack_unavailable"):
        native_bash_ack.acknowledge(
            guard_home=tmp_path,
            store_path=Path(tmp_path / "guard.db"),
            base_id="bash-operation:" + "b" * 64,
            harness="omp",
            project=tmp_path / "project",
            tool_call_id="call-1",
            exit_code=0,
        )
    assert len(requests) == 2
    assert requests[0] is requests[1]


@pytest.mark.parametrize(("recorded", "expected"), [(True, 0), (False, 125)])
def test_ack_cli_reports_a_native_refusal_as_unacknowledged(monkeypatch, tmp_path, capsys, recorded, expected):
    from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_ack_bound_bash_command

    monkeypatch.setattr(native_bash_ack, "acknowledge", lambda **_kwargs: recorded)
    args = SimpleNamespace(operation_id="bash-operation:" + "a" * 64, harness="omp", tool_call_id="call", exit_code=0)
    assert (
        _run_guard_ack_bound_bash_command(
            args, guard_home=tmp_path, workspace=tmp_path / "project", store=SimpleNamespace(path=tmp_path / "guard.db")
        )
        == expected
    )
    assert ("native_bash_ack_not_recorded" in capsys.readouterr().err) is (not recorded)
