from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_daemon_fixture as fixture
from scripts import native_slo_session as session_module
from scripts import native_slo_workspace_server as workspace_module
from scripts.native_slo_failure import FixtureFailureError


@pytest.mark.parametrize("count", [True, 0, 2, 99, 101, 1024, "100"])
def test_workspace_count_cannot_change_registration_bound(count):
    with pytest.raises(ValueError):
        fixture.DaemonFixture(Path("unused"), workspace_count=count)


@pytest.mark.parametrize("count", [None, 1, 10, 100])
def test_existing_fixture_default_and_finite_matrix_accepted(count):
    assert fixture.DaemonFixture(Path("unused"), workspace_count=count).workspace_count == count


@pytest.mark.parametrize("fail_start", [False, True])
def test_observer_is_installed_before_start_and_restored_after_owned_daemon_cleanup(monkeypatch, fail_start):
    calls = []

    class Adapter:
        def __init__(self, *_args, **_kwargs):
            calls.append("construct")

        def __enter__(self):
            assert calls[-1] == "observe"
            calls.append("start")
            if fail_start:
                self.close()
                raise RuntimeError("synthetic startup failure")
            return self

        def close(self):
            calls.append("stop")

        def __exit__(self, *_args):
            self.close()

    class Observer:
        def __enter__(self):
            calls.append("observe")

        def __exit__(self, *_args):
            assert calls[-1] == "witness_close" and calls.index("stop") < calls.index("witness_close")
            calls.append("restore")

    class Workspace:
        def __init__(self, adapter, count):
            assert isinstance(adapter, Adapter) and count == 100
            calls.append("register")
            self.observer = Observer()

        def close(self):
            calls.append("witness_close")

        def startup_failure(self):
            calls.append("failure_retained")
            return {"passed": False, "registered_workspaces": 100}

    monkeypatch.setattr(session_module, "AdapterSession", Adapter)
    monkeypatch.setattr(workspace_module, "WorkspaceScenarioFixture", Workspace)
    monkeypatch.setattr(
        fixture, "StartupDiagnostic", lambda _emit: nullcontext(SimpleNamespace(progress=lambda *_: None))
    )
    monkeypatch.setattr(fixture, "_emit", lambda _value: None)
    monkeypatch.setattr(fixture, "_serve_session", lambda *_args: calls.append("serve"))
    if fail_start:
        # Retaining evidence does not run the installed collector after failed startup.
        with pytest.raises(FixtureFailureError) as error:
            fixture._serve(Path("unused"), workspace_count=100)
        assert error.value.detail["workspace_observation"]["registered_workspaces"] == 100
        calls.remove("failure_retained")
    else:
        assert fixture._serve(Path("unused"), workspace_count=100) == 0
    assert calls == [
        "construct",
        "register",
        "observe",
        "start",
        *([] if fail_start else ["serve"]),
        "stop",
        "witness_close",
        "restore",
    ]
