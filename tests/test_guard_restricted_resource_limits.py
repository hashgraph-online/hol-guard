"""Virtual cage headroom cannot silently remove the mandatory Linux data cap."""

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox


@pytest.mark.parametrize("current, expected", [((-1, -1), (4096, 4096)), ((2048, 8192), (2048, 4096))])
def test_required_resource_limit_respects_stricter_inherited_limits(monkeypatch, current, expected):
    state = {"limit": current}
    monkeypatch.setattr(
        sandbox,
        "_resource",
        SimpleNamespace(
            getrlimit=lambda name: state["limit"],
            setrlimit=lambda name, values: state.update(limit=values),
        ),
    )
    sandbox._set_resource_limit(1, 4096, required=True)
    assert state["limit"] == expected


@pytest.mark.parametrize("failure", ["unavailable", "set", "readback"])
def test_required_limits_fail_closed_when_missing_unenforced_or_rejected(monkeypatch, failure):
    def setlimit(name, values):
        if failure == "set":
            raise OSError("limit unavailable")

    fake = (
        None
        if failure == "unavailable"
        else SimpleNamespace(
            getrlimit=lambda name: (-1, -1),
            setrlimit=setlimit,
        )
    )
    monkeypatch.setattr(sandbox, "_resource", fake)
    with pytest.raises(RuntimeError, match="resource limits"):
        sandbox._set_resource_limit(1, 4096, required=True)


def test_failed_preexec_limits_report_no_execution_instead_of_raw_subprocess_failure(monkeypatch):
    monkeypatch.setattr(sandbox, "_current_user_process_ceiling", lambda: 64)

    def fail(*args, **kwargs):
        raise sandbox.subprocess.SubprocessError("required preexec limit failed")

    monkeypatch.setattr(sandbox.subprocess, "Popen", fail)
    with pytest.raises(sandbox.RestrictedPytestError, match="execution was not started"):
        sandbox._run_backend_process(["/fixed/program"], env={}, timeout_seconds=10)


def test_linux_node_headroom_requires_data_limit_support_before_process_start(monkeypatch):
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox, "_resource", None)
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("must not start"))
    with pytest.raises(sandbox.RestrictedPytestError, match="execution was not started"):
        sandbox._run_backend_process(
            ["/fixed/program"], env={}, timeout_seconds=10, node_virtual_address_space=True
        )
