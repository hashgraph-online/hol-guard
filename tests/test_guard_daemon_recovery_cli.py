from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
from codex_plugin_scanner.guard.cli.approval_gate_prompt import consume_desktop_lifecycle_stdin
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import (
    LifecycleGateContext,
    lifecycle_gate_requirement,
)
from codex_plugin_scanner.guard.daemon.user_recovery import (
    ProcessIdentity,
    ProtectionResult,
    ReadyResult,
    RecoveryHooks,
    ServiceInspection,
    StartResult,
    UserRecoveryCoordinator,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import read_private_state, write_private_state


def _current_owner_marker() -> str:
    return f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user"


def _snapshot(operation_id: uuid.UUID, *, phase: str = "complete") -> dict[str, object]:
    terminal = phase == "complete"
    return {
        "schema": "hol-guard-recovery.v1",
        "capabilities": ["diagnostics", "inspect", "restart", "status"],
        "operationId": str(operation_id),
        "sequence": 1,
        "startedAt": "2026-09-20T12:00:00+00:00",
        "updatedAt": "2026-09-20T12:00:01+00:00",
        "phase": phase,
        "activeElapsedMs": 1000,
        "workerActive": False,
        "retryAllowed": terminal,
        "outcome": "restarted" if terminal else "not_recovered",
        "reasonCode": "healthy" if terminal else "approval_required",
        "service": "ready" if terminal else "unknown",
        "protection": "verified" if terminal else "unknown",
        "requiresHumanAction": not terminal,
        "checks": (
            [{"id": "protection_health", "result": "pass", "reasonCode": "healthy"}]
            if terminal
            else []
        ),
    }


def test_restart_lifecycle_gate_is_strict() -> None:
    args = argparse.Namespace(
        guard_command="daemon",
        daemon_command="recovery",
        daemon_recovery_command="restart",
        dry_run=False,
    )
    requirement = lifecycle_gate_requirement(args)
    assert requirement is not None
    assert requirement.action == "daemon.restart"
    assert requirement.subject == "local-daemon"


def test_private_status_survives_a_new_dispatch(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    cli._persist_snapshot(tmp_path, _snapshot(operation_id))
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 0
    assert json.loads(output.getvalue())["operationId"] == str(operation_id)


def test_status_rejects_cross_operation_lookup(tmp_path: Path) -> None:
    cli._persist_snapshot(tmp_path, _snapshot(uuid.uuid4()))
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(uuid.uuid4())),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert "recovery failed" in error.getvalue()


def test_restart_rejects_invalid_request_id_without_mutation(tmp_path: Path) -> None:
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id="not-a-uuid", json_lines=True),
        guard_home=tmp_path,
        home_dir=None,
        stderr=error,
    )
    assert result == 2
    assert not (tmp_path / "native-runtime" / cli._STATE_NAME).exists()


def test_direct_restart_dispatch_fails_closed_without_lifecycle_authorization(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id=str(operation_id), json_lines=False),
        guard_home=tmp_path,
        home_dir=None,
        stdout=output,
    )
    assert result == 2
    assert "awaiting_approval" in output.getvalue()


def test_direct_restart_rejects_legacy_authorization_without_gate_context(tmp_path: Path) -> None:
    output = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="restart", request_id=str(uuid.uuid4()), json_lines=False),
        guard_home=tmp_path,
        home_dir=None,
        lifecycle_authorized=True,
        stdout=output,
    )
    assert result == 2
    assert "awaiting_approval" in output.getvalue()


@pytest.mark.parametrize(
    ("authority_home_kind", "action", "scope", "subject"),
    [
        ("guard", "daemon.stop", "local-protection", "local-daemon"),
        ("guard", "daemon.restart", "other-scope", "local-daemon"),
        ("guard", "daemon.restart", "local-protection", "other-daemon"),
        ("other", "daemon.restart", "local-protection", "local-daemon"),
    ],
    ids=["wrong-action", "wrong-scope", "wrong-subject", "wrong-authority-home"],
)
def test_direct_restart_rejects_valid_grant_outside_recovery_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_home_kind: str,
    action: str,
    scope: str,
    subject: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    authority_home = guard_home if authority_home_kind == "guard" else tmp_path / "other-home"
    guard_home.mkdir()
    authority_home.mkdir(exist_ok=True)
    password = "correct horse battery staple"
    update_settings(
        authority_home,
        {"enabled": True, "new_password": password, "confirm_password": password},
    )
    grant = require_high_risk(
        authority_home,
        purpose="protection_lifecycle",
        approval_gate_input=ApprovalGateInput(password=password),
        action=action,
        scope=scope,
        subject=subject,
    )
    assert grant is not None
    context = LifecycleGateContext(
        authority_home=authority_home,
        action=action,
        scope=scope,
        subject=subject,
        grant=grant,
        was_enabled=True,
    )
    decisions: list[bool] = []

    class FakeCoordinator:
        def __init__(self, _home: Path, *, hooks: RecoveryHooks, **_kwargs: object) -> None:
            self.hooks = hooks

        def restart(self, *, request_id: object, emit: object = None) -> dict[str, object]:
            del emit
            authorize = self.hooks.authorize
            assert authorize is not None
            decision = authorize(guard_home)
            decisions.append(decision.allowed)
            operation_id = uuid.UUID(str(request_id))
            return _snapshot(
                operation_id,
                phase="complete" if decision.allowed else "awaiting_approval",
            )

    monkeypatch.setattr(cli, "UserRecoveryCoordinator", FakeCoordinator)
    output = io.StringIO()
    error = io.StringIO()
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(
            daemon_recovery_command="restart",
            request_id=str(uuid.uuid4()),
            json_lines=False,
        ),
        guard_home=guard_home,
        home_dir=None,
        lifecycle_authorized=True,
        lifecycle_context=context,
        stdout=output,
        stderr=error,
    )

    assert result == 2
    assert decisions == [False]
    assert "awaiting_approval" in output.getvalue()
    assert error.getvalue() == ""


def _install_counting_recovery_coordinator(
    monkeypatch: pytest.MonkeyPatch,
    counts: dict[str, int],
    *,
    start_entered: threading.Event | None = None,
    start_release: threading.Event | None = None,
) -> None:
    def make_coordinator(home: Path, *, home_dir: Path | None = None, hooks=None):
        guard_home = Path(home).resolve()
        key = str(guard_home)
        identity = ProcessIdentity(
            pid=40_000 + len(counts),
            generation=f"generation-{len(counts) + 1}",
            runtime="runtime-1",
            guard_home=guard_home,
            user=_current_owner_marker(),
            start_marker=f"start-{len(counts) + 1}",
        )
        counts.setdefault(key, 0)

        def inspect(_home: Path, _state: object) -> ServiceInspection:
            return ServiceInspection("unavailable", "service_missing")

        def start(_home: Path, _remaining: float) -> StartResult:
            counts[key] += 1
            if start_entered is not None:
                start_entered.set()
            if start_release is not None:
                start_release.wait(timeout=30.0)
            return StartResult(True, identity)

        custom_hooks = replace(
            hooks,
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=inspect,
            update_busy=lambda _home: False,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            start_process=start,
            verify_ready=lambda _home, _identity, _remaining: ReadyResult(True, identity),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
        )
        return UserRecoveryCoordinator(home, home_dir=home_dir, hooks=custom_hooks)

    monkeypatch.setattr(cli, "UserRecoveryCoordinator", make_coordinator)


def _dispatch_authorized_restart(home: Path, request_id: uuid.UUID, *, authorized: bool = True) -> int:
    lifecycle_context = (
        LifecycleGateContext(
            authority_home=home,
            action="daemon.restart",
            scope="local-protection",
            subject="local-daemon",
            grant=None,
            was_enabled=False,
        )
        if authorized
        else None
    )
    return cli.dispatch_daemon_recovery(
        argparse.Namespace(
            daemon_recovery_command="restart",
            request_id=str(request_id),
            json_lines=True,
        ),
        guard_home=home,
        home_dir=None,
        lifecycle_authorized=authorized,
        lifecycle_context=lifecycle_context,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


@pytest.mark.parametrize("protection_state", ("unknown", "needs_attention"))
def test_restart_cli_requires_verified_protection_for_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protection_state: str,
) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    identity = ProcessIdentity(
        pid=48_101,
        generation="cli-protection-generation",
        runtime="runtime-1",
        guard_home=home,
        user=_current_owner_marker(),
        start_marker="cli-protection-start",
    )
    mutations: list[str] = []

    def make_coordinator(
        recovery_home: Path,
        *,
        home_dir: Path | None = None,
        hooks: RecoveryHooks,
    ) -> UserRecoveryCoordinator:
        custom_hooks = replace(
            hooks,
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=lambda _home, _state: ServiceInspection(
                "ready", "healthy", identity, True, True, True
            ),
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            stop_process=lambda *_args: mutations.append("stop"),
            start_process=lambda *_args: mutations.append("start"),
            verify_ready=lambda _home, _identity, _remaining: ReadyResult(True, identity),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult(
                protection_state, "unknown"
            ),
        )
        return UserRecoveryCoordinator(recovery_home, home_dir=home_dir, hooks=custom_hooks)

    monkeypatch.setattr(cli, "UserRecoveryCoordinator", make_coordinator)
    output = io.StringIO()
    error = io.StringIO()
    operation_id = uuid.UUID("40404040-4040-4040-8040-404040404040")
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(
            daemon_recovery_command="restart",
            request_id=str(operation_id),
            json_lines=True,
        ),
        guard_home=home,
        home_dir=None,
        lifecycle_context=LifecycleGateContext(
            authority_home=home,
            action="daemon.restart",
            scope="local-protection",
            subject="local-daemon",
            grant=None,
            was_enabled=False,
        ),
        stdout=output,
        stderr=error,
    )
    events = [json.loads(line) for line in output.getvalue().splitlines()]
    final = events[-1]

    assert result == 2
    assert final["phase"] == "needs_action"
    assert final["outcome"] == "not_recovered"
    assert final["service"] == "ready"
    assert final["protection"] == protection_state
    assert final["requiresHumanAction"] is True
    assert mutations == []
    assert error.getvalue() == ""


def test_completed_same_uuid_replay_does_not_mutate_again_at_cli_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    home = tmp_path / "guard-home"
    home.mkdir()
    request_id = uuid.UUID("30303030-3030-4030-8030-303030303030")

    assert _dispatch_authorized_restart(home, request_id) == 0
    assert _dispatch_authorized_restart(home, request_id) == 0

    assert counts[str(home.resolve())] == 1


def test_completed_same_uuid_replay_is_scoped_to_each_guard_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    homes = [tmp_path / "home-a", tmp_path / "home-b"]
    for home in homes:
        home.mkdir()
    request_id = uuid.UUID("31313131-3131-4131-8131-313131313131")

    for home in homes:
        assert _dispatch_authorized_restart(home, request_id) == 0
        assert _dispatch_authorized_restart(home, request_id) == 0

    assert counts == {str(home.resolve()): 1 for home in homes}


def test_same_uuid_approval_continuation_requires_fresh_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    home = tmp_path / "guard-home"
    home.mkdir()
    request_id = uuid.UUID("32323232-3232-4232-8232-323232323232")

    assert _dispatch_authorized_restart(home, request_id, authorized=False) == 2
    assert counts[str(home.resolve())] == 0
    assert _dispatch_authorized_restart(home, request_id, authorized=True) == 0
    assert counts[str(home.resolve())] == 1


def test_tampered_receipt_fails_closed_before_a_replayed_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    home = tmp_path / "guard-home"
    home.mkdir()
    request_id = uuid.UUID("33333333-3333-4333-8333-333333333333")

    cli._persist_snapshot(home, _snapshot(request_id))
    write_private_state(home, cli._RECEIPT_NAME, b'{"schema":"tampered"}', cli._MAX_RECEIPT_BYTES)

    assert _dispatch_authorized_restart(home, request_id) == 3
    assert counts[str(home.resolve())] == 0


def test_receipt_copied_to_another_guard_home_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    home_a.mkdir()
    home_b.mkdir()
    request_id = uuid.UUID("38383838-3838-4838-8838-383838383838")

    assert _dispatch_authorized_restart(home_a, request_id) == 0
    cli._persist_snapshot(home_b, _snapshot(request_id, phase="awaiting_approval"))
    receipt = read_private_state(home_a, cli._RECEIPT_NAME, cli._MAX_RECEIPT_BYTES)
    assert receipt is not None
    write_private_state(home_b, cli._RECEIPT_NAME, receipt, cli._MAX_RECEIPT_BYTES)

    assert _dispatch_authorized_restart(home_b, request_id) == 3
    assert counts[str(home_a.resolve())] == 1
    assert counts[str(home_b.resolve())] == 0


def test_same_uuid_unresolved_receipt_does_not_restart_after_old_generation_is_dead(
    tmp_path: Path,
) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    request_id = uuid.UUID("39393939-3939-4939-8939-393939393939")
    identity = ProcessIdentity(41, "generation-old", "runtime-1", home, _current_owner_marker(), "start-old")
    dead_checks: list[ProcessIdentity] = []
    starts: list[str] = []

    cli._persist_snapshot(
        home,
        _snapshot(request_id, phase="starting") | {"workerActive": True, "retryAllowed": False},
    )
    hooks = RecoveryHooks(
        load_state=lambda _home: {"state": "fixture"},
        inspect_service=lambda _home, _state: ServiceInspection(
            "unavailable", "service_unresponsive", identity, process_running=False
        ),
        protection_posture=lambda _home: "on",
        update_busy=lambda _home: False,
        authorize=lambda _home: True,
        recovery_lock=lambda *_args: nullcontext(),
        start_lock=lambda *_args: nullcontext(),
        process_dead=lambda current: dead_checks.append(current) or True,
        start_process=lambda *_args: starts.append("start") or StartResult(True, identity),
        verify_ready=lambda _home, current, _remaining: ReadyResult(True, current),
        protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
        load_snapshot=cli._load_latest_snapshot,
        load_receipt=cli._load_receipt,
        persist_snapshot=cli._persist_snapshot,
    )
    coordinator = UserRecoveryCoordinator(home, hooks=hooks)

    result = coordinator.restart(request_id)

    assert result["operationId"] == str(request_id)
    assert result["phase"] == "starting"
    assert starts == []
    assert dead_checks == [identity]


def test_status_lookup_is_scoped_by_canonical_guard_home(tmp_path: Path) -> None:
    homes = [tmp_path / "home-a", tmp_path / "home-b"]
    for home in homes:
        home.mkdir()
    request_id = uuid.UUID("3a3a3a3a-3a3a-4a3a-8a3a-3a3a3a3a3a3a")

    def make(home: Path, protection_state: str) -> UserRecoveryCoordinator:
        identity = ProcessIdentity(
            41,
            f"generation-{protection_state}",
            "runtime-1",
            home,
            _current_owner_marker(),
            f"start-{protection_state}",
        )
        hooks = RecoveryHooks(
            load_state=lambda _home: {"state": "fixture"},
            inspect_service=lambda _home, _state: ServiceInspection("unavailable", "service_missing"),
            protection_posture=lambda _home: "on",
            update_busy=lambda _home: False,
            authorize=lambda _home: True,
            recovery_lock=lambda *_args: nullcontext(),
            start_lock=lambda *_args: nullcontext(),
            start_process=lambda _home, _remaining: StartResult(True, identity),
            verify_ready=lambda _home, current, _remaining: ReadyResult(True, current or identity),
            protection_health=lambda _home, _identity, _remaining: ProtectionResult(protection_state, "fixture"),
        )
        return UserRecoveryCoordinator(home, hooks=hooks)

    first = make(homes[0], "needs_attention")
    second = make(homes[1], "verified")
    first.restart(request_id)
    second.restart(request_id)

    assert first.status(request_id)["protection"] == "needs_attention"
    assert second.status(request_id)["protection"] == "verified"


def test_stale_starting_receipt_blocks_missing_identity_before_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    _install_counting_recovery_coordinator(monkeypatch, counts)
    home = tmp_path / "guard-home"
    home.mkdir()
    request_id = uuid.UUID("34343434-3434-4434-8434-343434343434")
    cli._persist_snapshot(home, _snapshot(request_id, phase="starting") | {"workerActive": True, "retryAllowed": False})

    assert _dispatch_authorized_restart(home, request_id) == 3
    assert counts[str(home.resolve())] == 0


def test_separate_cli_process_replays_completed_uuid_without_starting_again(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    count_path = tmp_path / "starts.log"
    request_id = "35353535-3535-4535-8535-353535353535"
    script = textwrap.dedent(
        """
        import argparse
        import io
        import os
        import sys
        from dataclasses import replace
        from contextlib import nullcontext
        from pathlib import Path

        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            RecoveryHooks,
            ServiceInspection,
            StartResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )
        from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import LifecycleGateContext

        home = Path(sys.argv[1])
        count_path = Path(sys.argv[2])
        request_id = sys.argv[3]
        identity = ProcessIdentity(
            41,
            "generation-1",
            "runtime-1",
            home,
            f"uid:{os.geteuid()}" if hasattr(os, "geteuid") else "current-user",
            "start-1",
        )

        def make(home, *, home_dir=None, hooks=None):
            def start(_home, _remaining):
                with count_path.open("a", encoding="utf-8") as stream:
                    stream.write("start\\n")
                return StartResult(True, identity)
            custom = replace(
                hooks,
                load_state=lambda _home: {"state": "fixture"},
                inspect_service=lambda _home, _state: ServiceInspection("unavailable", "service_missing"),
                update_busy=lambda _home: False,
                recovery_lock=lambda *_args: nullcontext(),
                start_lock=lambda *_args: nullcontext(),
                start_process=start,
                verify_ready=lambda _home, _identity, _remaining: ReadyResult(True, identity),
                protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            )
            return CoreCoordinator(home, hooks=custom)

        cli.UserRecoveryCoordinator = make
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(daemon_recovery_command="restart", request_id=request_id, json_lines=True),
            guard_home=home,
            home_dir=None,
            lifecycle_context=LifecycleGateContext(
                authority_home=home,
                action="daemon.restart",
                scope="local-protection",
                subject="local-daemon",
                grant=None,
                was_enabled=False,
            ),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        print(code)
        """
    )
    first = subprocess.run(
        [sys.executable, "-c", script, str(home), str(count_path), request_id],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    second = subprocess.run(
        [sys.executable, "-c", script, str(home), str(count_path), request_id],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert count_path.read_text(encoding="utf-8").splitlines() == ["start"]


@pytest.mark.parametrize("same_request", [True, False], ids=["same-id", "different-ids"])
def test_concurrent_cli_requests_share_one_home_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, same_request: bool
) -> None:
    counts: dict[str, int] = {}
    entered = threading.Event()
    release = threading.Event()
    _install_counting_recovery_coordinator(
        monkeypatch,
        counts,
        start_entered=entered,
        start_release=release,
    )
    home = tmp_path / "guard-home"
    home.mkdir()
    request_a = uuid.UUID("36363636-3636-4636-8636-363636363636")
    request_b = request_a if same_request else uuid.UUID("37373737-3737-4737-8737-373737373737")
    results: dict[str, int] = {}

    first = threading.Thread(
        target=lambda: results.setdefault("first", _dispatch_authorized_restart(home, request_a))
    )
    second = threading.Thread(
        target=lambda: results.setdefault("second", _dispatch_authorized_restart(home, request_b))
    )
    first.start()
    assert entered.wait(timeout=5.0)
    second.start()
    second.join(timeout=5.0)
    release.set()
    first.join(timeout=5.0)

    assert not first.is_alive()
    assert not second.is_alive()
    assert results["first"] == 0
    assert results["second"] == 3
    assert counts[str(home.resolve())] == 1


def test_concurrent_cli_processes_do_not_replay_a_home_mutation(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    count_path = tmp_path / "starts.log"
    first_entered = tmp_path / "first-entered"
    second_lock_attempt = tmp_path / "second-lock-attempt"
    release_first = tmp_path / "release-first"
    started = tmp_path / "daemon-started"
    first_request = "38383838-3838-4838-8838-383838383838"
    second_request = "39393939-3939-4939-8939-393939393939"
    script = textwrap.dedent(
        """
        import argparse
        import io
        import json
        import os
        import sys
        import time
        from dataclasses import replace
        from pathlib import Path

        from codex_plugin_scanner.guard import live_process_identity
        from codex_plugin_scanner.guard.cli import commands_daemon_recovery as cli
        from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import LifecycleGateContext
        from codex_plugin_scanner.guard.daemon import manager
        from codex_plugin_scanner.guard.daemon.user_recovery import (
            ProcessIdentity,
            ProtectionResult,
            ReadyResult,
            ServiceInspection,
            StartResult,
            UserRecoveryCoordinator as CoreCoordinator,
        )

        home = Path(sys.argv[1])
        count_path = Path(sys.argv[2])
        request_id = sys.argv[3]
        first_request = sys.argv[4]
        first_entered = Path(sys.argv[5])
        second_lock_attempt = Path(sys.argv[6])
        release_first = Path(sys.argv[7])
        started = Path(sys.argv[8])
        identity = ProcessIdentity(
            41,
            "generation-1",
            "runtime-1",
            home,
            live_process_identity.process_owner_marker(os.getpid()) or "fixture-owner",
            "start-1",
        )

        real_recovery_lock = manager._guard_daemon_recovery_lock
        def track_second_lock(guard_home, **kwargs):
            if request_id != first_request:
                second_lock_attempt.touch(exist_ok=True)
            return real_recovery_lock(guard_home, **kwargs)
        manager._guard_daemon_recovery_lock = track_second_lock

        def make(home, *, home_dir=None, hooks=None):
            def inspect(_home, _state):
                if started.exists():
                    return ServiceInspection("ready", "healthy", identity, True)
                return ServiceInspection("unavailable", "service_missing")

            def start(_home, _remaining):
                with count_path.open("a", encoding="utf-8") as stream:
                    print(request_id, file=stream, flush=True)
                if request_id == first_request:
                    first_entered.touch(exist_ok=True)
                    deadline = time.monotonic() + 20.0
                    while not release_first.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    if not release_first.exists():
                        raise TimeoutError("test owner was not released")
                started.write_text("ready", encoding="utf-8")
                return StartResult(True, identity)

            custom = replace(
                hooks,
                load_state=lambda _home: {"state": "fixture"},
                inspect_service=inspect,
                update_busy=lambda _home: False,
                start_process=start,
                verify_ready=lambda _home, _identity, _remaining: ReadyResult(True, identity),
                protection_health=lambda _home, _identity, _remaining: ProtectionResult("verified", "healthy"),
            )
            return CoreCoordinator(home, hooks=custom, lock_timeout_seconds=0.1)

        cli.UserRecoveryCoordinator = make
        output = io.StringIO()
        error = io.StringIO()
        code = cli.dispatch_daemon_recovery(
            argparse.Namespace(daemon_recovery_command="restart", request_id=request_id, json_lines=True),
            guard_home=home,
            home_dir=None,
            lifecycle_context=LifecycleGateContext(
                authority_home=home,
                action="daemon.restart",
                scope="local-protection",
                subject="local-daemon",
                grant=None,
                was_enabled=False,
            ),
            stdout=output,
            stderr=error,
        )
        if code != 0:
            sys.stderr.write(output.getvalue())
            sys.stderr.write(error.getvalue())
        if request_id == first_request:
            print(code)
        else:
            status_output = io.StringIO()
            status_error = io.StringIO()
            status_code = cli.dispatch_daemon_recovery(
                argparse.Namespace(
                    daemon_recovery_command="status",
                    operation_id=first_request,
                    json_lines=True,
                ),
                guard_home=home,
                home_dir=None,
                stdout=status_output,
                stderr=status_error,
            )
            print(
                json.dumps(
                    {
                        "restartCode": code,
                        "statusCode": status_code,
                        "status": json.loads(status_output.getvalue()) if status_code == 0 else None,
                        "statusError": status_error.getvalue(),
                    },
                    sort_keys=True,
                )
            )
        """
    )

    def spawn_request(request_id: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(home),
                str(count_path),
                request_id,
                first_request,
                str(first_entered),
                str(second_lock_attempt),
                str(release_first),
                str(started),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def wait_for_marker(marker: Path, process: subprocess.Popen[str]) -> None:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if marker.exists():
                return
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(f"process exited before {marker.name}: {stdout} {stderr}")
            time.sleep(0.01)
        raise AssertionError(f"timed out waiting for {marker.name}")

    first: subprocess.Popen[str] | None = None
    second: subprocess.Popen[str] | None = None
    try:
        first = spawn_request(first_request)
        wait_for_marker(first_entered, first)
        second = spawn_request(second_request)
        wait_for_marker(second_lock_attempt, second)
        assert count_path.read_text(encoding="utf-8").splitlines() == [first_request]
        second_stdout, second_stderr = second.communicate(timeout=10)
        assert second.returncode == 0, second_stderr
        second_result = json.loads(second_stdout)
        assert second_result["restartCode"] == 3
        assert second_result["statusCode"] == 0, second_result
        assert second_result["status"]["operationId"] == first_request
        assert second_result["status"]["phase"] == "starting"
        assert second_result["status"]["workerActive"] is True
        release_first.touch()
        first_stdout, first_stderr = first.communicate(timeout=10)
        assert first.returncode == 0, first_stderr
        assert first_stdout.strip() == "0"
        assert count_path.read_text(encoding="utf-8").splitlines() == [first_request]
    finally:
        release_first.touch(exist_ok=True)
        for process in (second, first):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def test_completed_replay_wins_over_a_different_active_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counts: dict[str, int] = {}
    entered = threading.Event()
    release = threading.Event()
    release.set()
    _install_counting_recovery_coordinator(
        monkeypatch,
        counts,
        start_entered=entered,
        start_release=release,
    )
    home = tmp_path / "guard-home"
    home.mkdir()
    completed_id = uuid.UUID("3b3b3b3b-3b3b-4b3b-8b3b-3b3b3b3b3b3b")
    active_id = uuid.UUID("3c3c3c3c-3c3c-4c3c-8c3c-3c3c3c3c3c3c")

    assert _dispatch_authorized_restart(home, completed_id) == 0
    release.clear()
    active_result: dict[str, int] = {}
    worker = threading.Thread(
        target=lambda: active_result.setdefault("code", _dispatch_authorized_restart(home, active_id))
    )
    worker.start()
    assert entered.wait(timeout=5.0)

    output = io.StringIO()
    replay_code = cli.dispatch_daemon_recovery(
        argparse.Namespace(
            daemon_recovery_command="restart",
            request_id=str(completed_id),
            json_lines=True,
        ),
        guard_home=home,
        home_dir=None,
        lifecycle_context=LifecycleGateContext(
            authority_home=home,
            action="daemon.restart",
            scope="local-protection",
            subject="local-daemon",
            grant=None,
            was_enabled=False,
        ),
        stdout=output,
        stderr=io.StringIO(),
    )
    release.set()
    worker.join(timeout=5.0)

    replay_lines = [json.loads(line) for line in output.getvalue().splitlines() if line]
    assert replay_code == 0
    assert replay_lines[-1]["operationId"] == str(completed_id)
    assert active_result["code"] == 0
    assert counts[str(home.resolve())] == 2


def test_status_returns_zero_for_a_valid_human_action_snapshot(tmp_path: Path) -> None:
    operation_id = uuid.uuid4()
    cli._persist_snapshot(tmp_path, _snapshot(operation_id, phase="awaiting_approval"))
    result = cli.dispatch_daemon_recovery(
        argparse.Namespace(daemon_recovery_command="status", operation_id=str(operation_id)),
        guard_home=tmp_path,
        home_dir=None,
        stdout=io.StringIO(),
    )
    assert result == 0


def test_restart_exit_codes_distinguish_human_action_and_owned_work() -> None:
    operation_id = uuid.uuid4()
    approval = _snapshot(operation_id, phase="awaiting_approval")
    busy = dict(approval, phase="waiting_for_owner", requiresHumanAction=False)
    assert cli._restart_exit_code(approval) == 2
    assert cli._restart_exit_code(busy) == 3


def _proof_stdin(monkeypatch: object, payload: bytes) -> None:
    stream = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", stream)  # type: ignore[attr-defined]


def test_recovery_stdin_uses_totp_instead_of_password(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":null,"totpCode":" 123456 "}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=True)
    assert proof is not None
    assert proof.password is None
    assert proof.totp_code == "123456"


def test_recovery_stdin_uses_password_without_totp(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"correct horse","totpCode":null}')
    proof = consume_desktop_lifecycle_stdin(totp_enabled=False)
    assert proof is not None
    assert proof.password == "correct horse"
    assert proof.totp_code is None


def test_recovery_stdin_rejects_conflicting_or_unbounded_proof(monkeypatch: object) -> None:
    _proof_stdin(monkeypatch, b'{"password":"one","totpCode":"123456"}')
    with pytest.raises(ApprovalGateError, match="never both"):
        consume_desktop_lifecycle_stdin(totp_enabled=True)
    _proof_stdin(monkeypatch, b"x" * (4 * 1024 + 1))
    with pytest.raises(ApprovalGateError, match="exceeded"):
        consume_desktop_lifecycle_stdin(totp_enabled=False)


@pytest.mark.parametrize("payload", [b"", b"not-json", b"{}", b'{"password":null,"totpCode":null}'])
def test_recovery_stdin_rejects_missing_or_malformed_proof(
    monkeypatch: object, payload: bytes
) -> None:
    _proof_stdin(monkeypatch, payload)
    with pytest.raises(ApprovalGateError):
        consume_desktop_lifecycle_stdin(totp_enabled=False)
