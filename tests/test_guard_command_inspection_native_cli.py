"""Inspection uses the running daemon and never initializes local authority."""

from argparse import Namespace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.cli import extension_controls_commands as controls
from codex_plugin_scanner.guard.native_daemon_client import GuardDaemonRequestError


@pytest.mark.parametrize("mode", ["test", "explain"])
def test_inspection_uses_daemon_without_initializing_store(monkeypatch, tmp_path, mode):
    emitted = []
    requests = []

    class Client:
        def inspect_command(self, payload, timeout=None):
            requests.append(payload)
            return {"status": "matched", "minimum_action": "review"}

    def client(guard_home):
        assert guard_home == tmp_path
        return Client()

    def forbidden_store(*args, **kwargs):
        pytest.fail("inspection must not initialize a store")

    monkeypatch.setattr(controls, "_client", client)
    monkeypatch.setattr(controls, "GuardStore", forbidden_store)
    monkeypatch.setattr(dispatch, "GuardStore", forbidden_store)
    monkeypatch.setattr(dispatch, "_emit", lambda *args: emitted.append(args), raising=False)
    args = Namespace(command_command=mode, command_text="  git status  ", guard_home=str(tmp_path), json=True)

    assert dispatch._run_guard_command_inspection_command(args) == 0
    assert requests == [{"command": "git status", "cwd": str(Path.cwd()), "home_dir": str(Path.home())}]
    assert emitted[0][1]["mode"] == mode


@pytest.fixture(autouse=True)
def _no_real_daemon_start(monkeypatch):
    from codex_plugin_scanner.guard import native_daemon_manage
    from codex_plugin_scanner.guard.cli import command_inspection_client

    def refuse(*_args, **_kwargs):
        raise RuntimeError("daemon start disabled in this test")

    monkeypatch.setattr(native_daemon_manage, "ensure_guard_daemon", refuse)
    monkeypatch.setattr(command_inspection_client, "WARMUP_BUDGET_SECONDS", 0.0)


@pytest.mark.parametrize("transport_failure", [False, True])
def test_unavailable_inspection_has_nonzero_exit(monkeypatch, tmp_path, transport_failure):
    emitted = []

    class Client:
        def inspect_command(self, payload, timeout=None):
            if transport_failure:
                raise GuardDaemonRequestError("not running")
            return {"status": "native_unavailable", "minimum_action": "review"}

    monkeypatch.setattr(controls, "_client", lambda _: Client())
    monkeypatch.setattr(dispatch, "_emit", lambda *args: emitted.append(args), raising=False)
    args = Namespace(command_command="test", command_text="git status", guard_home=str(tmp_path), json=True)

    assert dispatch._run_guard_command_inspection_command(args) == 2
    assert emitted[0][1]["status"] == "native_unavailable"
    assert emitted[0][1]["minimum_action"] == "review"
    if transport_failure:
        assert emitted[0][1]["classification"]["explicitly_benign"] is False


def test_unavailable_inspection_reports_decision_specific_recovery() -> None:
    from codex_plugin_scanner.guard.runtime.command_inspection import unavailable_command_inspection

    unavailable = unavailable_command_inspection("git status")
    classification = unavailable["classification"]
    assert "native inspection is unavailable" in classification["reason"].lower()
    assert classification["recovery"]
    assert "retry" in classification["recovery"].lower()

    failed = unavailable_command_inspection("git status", native_evaluation_failed=True)
    failed_classification = failed["classification"]
    assert "evaluation failed" in failed_classification["reason"].lower()
    assert failed_classification["recovery"]
    assert "blocked" in failed_classification["recovery"].lower()


def test_direct_and_cli_outage_reports_do_not_require_native_parser(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_rich_command_model
    from codex_plugin_scanner.guard.runtime import command_inspection

    emitted = []
    monkeypatch.setattr(native_rich_command_model, "ensure_resident_prerequisite", lambda _: False)
    monkeypatch.setattr(command_inspection, "review_command_native", lambda *args, **kwargs: None)
    direct = command_inspection.inspect_command("  git status  ", cwd=tmp_path, home_dir=tmp_path)
    assert direct["status"] == "native_unavailable"
    assert direct["command_model"] is None
    assert direct["classification"]["recovery"]

    class Client:
        def inspect_command(self, payload, timeout=None):
            raise GuardDaemonRequestError("not running")

    monkeypatch.setattr(controls, "_client", lambda _: Client())
    monkeypatch.setattr(dispatch, "_emit", lambda *args: emitted.append(args), raising=False)
    args = Namespace(command_command="test", command_text="git status", guard_home=str(tmp_path), json=True)
    assert dispatch._run_guard_command_inspection_command(args) == 2
    assert emitted[0][1]["status"] == "native_unavailable"
    assert emitted[0][1]["command_model"] is None


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _inspect(answers, *, ensure=None, budget=5.0, monkeypatch=None):
    from codex_plugin_scanner.guard.cli import command_inspection_client as client_module

    if monkeypatch is not None:
        monkeypatch.setattr(client_module, "WARMUP_BUDGET_SECONDS", budget)
    calls = []
    timeouts = []

    class Client:
        def inspect_command(self, payload, timeout=None):
            calls.append(payload)
            timeouts.append(timeout)
            answer = answers.pop(0) if answers else answers_tail
            if isinstance(answer, Exception):
                raise answer
            return dict(answer)

    answers_tail = answers[-1]
    clock = _FakeClock()
    payload = client_module.inspect_through_daemon(
        "rm -rf build",
        guard_home=Path("/guard-home"),
        workspace=Path("/workspace"),
        home=Path("/home"),
        client_for=lambda _home: Client(),
        ensure_daemon=ensure or (lambda *_a, **_k: "http://127.0.0.1:1"),
        clock=clock,
        sleep=clock.sleep,
    )
    _inspect.timeouts = timeouts
    return payload, calls, clock


def test_cold_runtime_is_asked_again_until_it_answers(monkeypatch):
    cold = {"status": "native_unavailable", "minimum_action": "review"}
    warm = {"status": "review", "minimum_action": "review"}
    payload, calls, clock = _inspect([cold, cold, warm], monkeypatch=monkeypatch)
    assert payload["status"] == "review"
    assert len(calls) == 3
    assert clock.now <= 5.0


def test_cold_runtime_never_becomes_no_match_when_the_budget_runs_out(monkeypatch):
    cold = {"status": "native_unavailable", "minimum_action": "review"}
    payload, calls, clock = _inspect([cold], monkeypatch=monkeypatch)
    assert payload["status"] == "native_unavailable"
    assert payload["minimum_action"] == "review"
    assert payload["readiness"]["reason_code"] == "native_review_unavailable"
    assert payload["readiness"]["safe_verdict"] is False
    assert clock.now <= 5.0
    assert len(calls) > 1


def test_failed_native_evaluation_is_not_retried(monkeypatch):
    from codex_plugin_scanner.guard.runtime.command_inspection import unavailable_command_inspection

    failed = unavailable_command_inspection("rm -rf build", native_evaluation_failed=True)
    payload, calls, _clock = _inspect([failed], monkeypatch=monkeypatch)
    assert len(calls) == 1
    assert payload["minimum_action"] == "block"
    assert payload["readiness"]["state"] == "failed"


@pytest.mark.parametrize(
    ("error", "reason_code"),
    [
        (TimeoutError("deadline"), "daemon_start_timeout"),
        (RuntimeError("no daemon"), "daemon_start_failed"),
        (OSError("spawn failed"), "daemon_start_failed"),
    ],
)
def test_daemon_start_failures_are_typed_and_reviewed(monkeypatch, error, reason_code):
    def ensure(*_args, **_kwargs):
        raise error

    payload, calls, _clock = _inspect([GuardDaemonRequestError("down")], ensure=ensure, monkeypatch=monkeypatch)
    assert len(calls) == 1
    assert payload["status"] == "native_unavailable"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["readiness"]["reason_code"] == reason_code
    assert payload["readiness"]["recovery_commands"]


def test_request_failure_after_start_is_typed(monkeypatch):
    down = GuardDaemonRequestError("down")
    payload, calls, _clock = _inspect([down, down], monkeypatch=monkeypatch)
    assert len(calls) == 2
    assert payload["readiness"]["reason_code"] == "daemon_request_failed"


def test_unavailable_rendering_cannot_be_read_as_no_match():
    from codex_plugin_scanner.guard.cli.render_command_inspection import plain_text_command_inspection
    from codex_plugin_scanner.guard.runtime.command_inspection import unavailable_command_inspection

    payload = unavailable_command_inspection("rm -rf build", reason_code="daemon_start_timeout")
    text = plain_text_command_inspection(payload)
    assert "NOT EVALUATED (daemon_start_timeout)" in text
    assert "No sensitive action matched" not in text
    assert "Minimum action: REVIEW" in text
    assert "hol-guard daemon repair" in text

    rendered = plain_text_command_inspection(
        {"status": "no_match", "command": "ls", "classification": {"reason": "none"}, "minimum_action": "allow"}
    )
    assert "NO_MATCH" in rendered
    assert "No sensitive action matched" in rendered
    assert "Minimum action" not in rendered


def test_native_hold_reports_review_tier_decisions():
    from codex_plugin_scanner.guard.runtime.command_inspection import _native_hold

    hold = _native_hold(
        {
            "decision": "deny",
            "minimum_action": "require-reapproval",
            "reason_code": "native_git_execution_context_review",
            "reason": "Synthetic git execution context needs review.",
        }
    )
    assert hold == {
        "decision": "deny",
        "minimum_action": "review",
        "native_minimum_action": "require-reapproval",
        "reason_code": "native_git_execution_context_review",
        "reason": "Synthetic git execution context needs review.",
    }


def test_native_hold_reads_a_floor_named_only_as_policy_action():
    from codex_plugin_scanner.guard.runtime.command_inspection import _native_hold

    hold = _native_hold(
        {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_sandbox_required",
            "reason": "Synthetic containment floor.",
        }
    )
    assert hold is not None
    assert hold["minimum_action"] == "review"
    assert hold["native_minimum_action"] == "sandbox-required"


@pytest.mark.parametrize(
    "native",
    [
        {"decision": "allow", "minimum_action": "allow", "reason_code": "native_benign", "reason": "ok"},
        {"decision": "deny", "minimum_action": "require-reapproval", "reason_code": "", "reason": "y"},
        {"decision": "deny", "minimum_action": "review", "reason_code": "", "reason": "y"},
        {"decision": "deny", "minimum_action": "review", "reason": "y"},
        # A plain native review keeps the catalog's no_match answer.
        {"decision": "deny", "minimum_action": "review", "reason_code": "native_review", "reason": "y"},
    ],
)
def test_native_hold_ignores_allows_and_undecoded_replies(native):
    from codex_plugin_scanner.guard.runtime.command_inspection import _native_hold

    assert _native_hold(native) is None


def test_each_retry_is_bounded_by_the_remaining_budget(monkeypatch):
    cold = {"status": "native_unavailable", "minimum_action": "review"}
    _payload, calls, _clock = _inspect([cold], monkeypatch=monkeypatch)
    # The first ask uses the client's own timeout; every retry gets what is left.
    retries = _inspect.timeouts[1:]
    assert len(calls) > 1
    assert all(timeout is not None and 0 < timeout <= 5.0 for timeout in retries)
    assert retries == sorted(retries, reverse=True)


def test_recovery_commands_name_the_guard_home(monkeypatch):
    cold = {"status": "native_unavailable", "minimum_action": "review"}
    payload, _calls, _clock = _inspect([cold], monkeypatch=monkeypatch)
    commands = payload["readiness"]["recovery_commands"]
    assert commands
    assert all("--guard-home /guard-home" in command for command in commands)


def test_recovery_commands_quote_a_guard_home_with_spaces():
    from codex_plugin_scanner.guard.runtime.command_inspection import recovery_commands

    commands = recovery_commands(Path("/tmp/guard home"))
    assert all(command.endswith("--guard-home '/tmp/guard home'") for command in commands)
    assert all("--guard-home" not in command for command in recovery_commands())


@pytest.mark.parametrize("minimum_action", [["review"], {"tier": "review"}, 3])
def test_unhashable_native_action_is_fail_safe(monkeypatch, minimum_action):
    from codex_plugin_scanner.guard import native_pretool

    decoded = native_pretool._decode_pre_tool(
        {"decision": "deny", "minimum_action": minimum_action, "reason_code": "x", "reason": "y"},
        command="ls",
    )
    assert decoded is None
