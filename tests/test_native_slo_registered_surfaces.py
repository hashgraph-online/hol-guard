"""Registration/readback and delivered-process contracts, without live sockets."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts import native_slo_registered_surfaces as registrations
from scripts import native_slo_registered_surfaces_run as execution
from scripts.native_slo_priority_launchers import LauncherSession
from scripts.native_slo_workloads import QualificationCase, build_cases


@pytest.fixture
def context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home with spaces 'quote 雪"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir()
    return HarnessContext(home, workspace, guard_home)


@pytest.fixture
def cases(context: HarnessContext) -> tuple[QualificationCase, ...]:
    assert context.workspace_dir is not None
    return build_cases(context.workspace_dir)


def _case(cases: tuple[QualificationCase, ...], case_id: str) -> QualificationCase:
    return next(case for case in cases if case.case_id == case_id)


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _cursor(context: HarnessContext) -> tuple[registrations.RegisteredSurface, ...]:
    # Only registration mechanics: this worker is never claimed as installed
    # Guard or used to bypass the production interpreter attestation.
    script = context.home_dir / ".cursor/hooks/hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("# synthetic registration worker\n")
    hooks = {
        event: [
            {
                "command": shlex.join((sys.executable, str(script), "--cursor-hook-event", event)),
                "timeout": 45,
                "failClosed": event.startswith("before"),
            }
        ]
        for event in registrations.SURFACE_EVENTS["cursor"]
    }
    _write(context.home_dir / ".cursor/hooks.json", {"version": 1, "hooks": hooks})
    return registrations.read_registered_surfaces(context, "cursor")


def _cline(context: HarnessContext) -> tuple[registrations.RegisteredSurface, ...]:
    root = context.home_dir / "Documents/Cline/Hooks"
    state: dict[str, object] = {"schema_version": 1, "transport": "hooks", "root": str(root)}
    for group, digest_group, worker in (("paths", "sha256", False), ("workers", "worker_sha256", True)):
        paths, digests = {}, {}
        for event in registrations.SURFACE_EVENTS["cline"]:
            parent = context.guard_home / "managed/cline/hook-workers" if worker else root
            suffix = ".py" if worker else ".ps1" if os.name == "nt" else ""
            path = parent / (event + suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# HOL_GUARD_MANAGED_CLINE_HOOK_V1 synthetic registration\n")
            path.chmod(0o700)
            paths[event] = str(path)
            digests[event] = hashlib.sha256(path.read_bytes()).hexdigest()
        state[group], state[digest_group] = paths, digests
    _write(context.guard_home / "managed/cline/native-hooks-state.json", state)
    _write(context.guard_home / "managed/cline/adapter-state.json", {"active_transport": "hooks"})
    return registrations.read_registered_surfaces(context, "cline")


@pytest.mark.parametrize("harness,count", (("copilot", 4), ("kimi", 2), ("grok", 1), ("zcode", 1)))
def test_real_adapters_install_and_read_actual_configurations(
    context: HarnessContext, harness: str, count: int
) -> None:
    if os.name == "nt" and harness == "zcode":
        with pytest.raises(registrations.SurfaceUnavailableError, match="zcode_windows_shell_comment"):
            registrations.install_registered_surface(context, harness)
        return
    surfaces = registrations.install_registered_surface(context, harness)
    assert len(surfaces) == count
    assert registrations.read_registered_surfaces(context, harness) == surfaces
    for item in surfaces:
        assert item.config_path.is_file()
        assert item.argv[1:3] == ("-I", "-c")
        assert json.loads(item.argv[-1])["harness"] == harness
        assert json.loads(item.argv[-1])["guard_home"] == str(context.guard_home.resolve())
        assert item.registration_sha256 == hashlib.sha256(item.config_path.read_bytes()).hexdigest()
    if harness == "copilot":
        assert {item.scope for item in surfaces} == {"global", "project"}
        assert all(item.cwd == context.guard_home for item in surfaces)
    if harness == "zcode":
        assert len(surfaces[0].matchers) == 18


def test_cursor_reads_all_six_exact_aliases_and_worker_digest(context: HarnessContext) -> None:
    surfaces = _cursor(context)
    assert tuple(item.event for item in surfaces) == registrations.SURFACE_EVENTS["cursor"]
    for item in surfaces:
        assert item.argv[-2:] == ("--cursor-hook-event", item.event)
        assert item.artifact_sha256
    script = Path(surfaces[0].argv[1])
    script.write_text("# replacement\n")
    assert registrations.read_registered_surfaces(context, "cursor") != surfaces


@pytest.mark.parametrize("fault", ("duplicate", "disabled", "wrong_event", "wrong_fail_closed", "shell"))
def test_cursor_rejects_ambiguous_or_changed_registration(context: HarnessContext, fault: str) -> None:
    item = _cursor(context)[0]
    config = json.loads(item.config_path.read_text())
    handlers = config["hooks"][item.event]
    if fault == "duplicate":
        handlers.append(copy.deepcopy(handlers[0]))
    elif fault == "disabled":
        handlers[0]["enabled"] = False
    elif fault == "wrong_event":
        handlers[0]["command"] = shlex.join((*item.argv[:-1], "afterShellExecution"))
    elif fault == "wrong_fail_closed":
        handlers[0]["failClosed"] = False
    else:
        handlers[0]["command"] += " ; echo unregistered"
    _write(item.config_path, config)
    with pytest.raises(RuntimeError, match="registered_surface_"):
        registrations.read_registered_surfaces(context, "cursor")


def test_cline_reads_canonical_slots_and_both_artifact_digests(context: HarnessContext) -> None:
    surfaces = _cline(context)
    assert len(surfaces) == 2
    assert all(len(item.artifact_sha256) == 2 for item in surfaces)
    path = context.guard_home / "managed/cline/hook-workers/PreToolUse.py"
    path.write_text("changed")
    with pytest.raises(RuntimeError, match="cline_artifact_changed"):
        registrations.read_registered_surfaces(context, "cline")


@pytest.mark.parametrize("fault", ("inactive", "path"))
def test_cline_rejects_inactive_or_redirected_slots(context: HarnessContext, fault: str) -> None:
    item = _cline(context)[0]
    if fault == "inactive":
        _write(context.guard_home / "managed/cline/adapter-state.json", {"active_transport": "mcp"})
    else:
        state = json.loads(item.config_path.read_text())
        target = context.home_dir / "unregistered"
        target.write_text("# replacement")
        state["paths"][item.event] = str(target)
        _write(item.config_path, state)
    with pytest.raises(RuntimeError, match="registered_surface_cline_"):
        registrations.read_registered_surfaces(context, "cline")


def test_cline_custom_guard_home_is_explicitly_unavailable_before_install(context: HarnessContext) -> None:
    changed = replace(context, guard_home=context.home_dir / "guard-home")
    with pytest.raises(registrations.SurfaceUnavailableError, match="cline_requires_default_guard_home"):
        registrations.install_registered_surface(changed, "cline")
    assert not (context.home_dir / "Documents").exists()


def test_ambient_home_override_cannot_redirect_install(
    context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KIMI_CODE_HOME", "/some/other/home")
    with pytest.raises(registrations.SurfaceUnavailableError, match="ambient_home_override"):
        registrations.install_registered_surface(context, "kimi")
    assert not (context.home_dir / ".kimi-code").exists()


def test_windows_parser_uses_os_abi_and_lossless_roundtrip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # ABI dispatch test on every host; real Win32 parsing is exercised below on Windows.
    argv = (str(tmp_path / "python with spaces.exe"), "-I", "literal\\trail\\", 'quote"雪')
    command = subprocess.list2cmdline(argv)
    seen = []

    def parse(value: str) -> list[str]:
        seen.append(value)
        return list(argv)

    monkeypatch.setattr(registrations, "windows_command_line_to_argv", parse)
    assert registrations._command(command, windows=True) == argv
    assert seen == [command]
    with pytest.raises(RuntimeError, match="not_lossless"):
        registrations._command(command + " extra", windows=True)


@pytest.mark.skipif(os.name != "nt", reason="real Win32 CommandLineToArgvW qualification")
def test_real_windows_command_line_abi_roundtrip(tmp_path: Path) -> None:
    argv = (str(tmp_path / "with spaces 雪.exe"), 'literal"quote', "backslash\\trail\\", "", "$(literal);#")
    assert registrations._command(subprocess.list2cmdline(argv), windows=True) == argv


def test_zcode_windows_comment_is_not_silently_removed(tmp_path: Path) -> None:
    command = subprocess.list2cmdline((str(tmp_path / "python.exe"), "-I")) + " # HOL_GUARD_MANAGED_ZCODE"
    with pytest.raises(registrations.SurfaceUnavailableError, match="zcode_windows_shell_comment"):
        registrations._command(command, windows=True, zcode=True)


def test_configuration_limit(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(b" " * (registrations.CONFIG_LIMIT + 1))
    with pytest.raises(RuntimeError, match="configuration_limit"):
        registrations._read(path)


def _response(case: QualificationCase) -> tuple[dict[str, object], int]:
    expected, code = execution.delivery_expectation(case)
    result: dict[str, object] = {}
    for name, value in {**expected.fields, **dict.fromkeys(expected.nonempty_fields, "synthetic reason")}.items():
        current = result
        parts = name.split(".")
        for part in parts[:-1]:
            nested = current.setdefault(part, {})
            assert isinstance(nested, dict)
            current = nested
        current[parts[-1]] = value
    return result, code


def test_each_registered_alias_has_frozen_normal_cases(
    context: HarnessContext, cases: tuple[QualificationCase, ...]
) -> None:
    for harness, events in registrations.SURFACE_EVENTS.items():
        for event in events:
            item = registrations.RegisteredSurface(
                harness, event, "global", (), (), context.home_dir, context.home_dir, "a" * 64
            )
            selected = execution.surface_cases(cases, item)
            assert selected, (harness, event)
            for case in selected:
                response, code = _response(case)
                execution.validate_surface_delivery(case, response, code, "synthetic stderr")
                with pytest.raises(AssertionError, match="exit_mismatch"):
                    execution.validate_surface_delivery(case, response, code + 1, "synthetic stderr")


@pytest.mark.parametrize(
    "case_id,decision,code",
    (
        ("cursor/beforeReadFile/normal/small", "deny", 2),
        ("cursor/beforeWriteFile/normal/small", "ask", 0),
        ("cursor/beforeMCPExecution/normal/small", "ask", 0),
        ("cursor/afterShellExecution/block/1k", "observation_only", 0),
        ("cline/PostToolUse/block/1k", "observation_only", 0),
    ),
)
def test_review_and_observation_delivery_cannot_be_called_allow_or_output_block(
    cases: tuple[QualificationCase, ...],
    case_id: str,
    decision: str,
    code: int,
) -> None:
    expected, wanted = execution.delivery_expectation(_case(cases, case_id))
    assert (expected.decision, wanted) == (decision, code)
    if decision == "observation_only":
        assert expected.model_action == "unreviewed_original"


def test_copilot_daemon_envelope_does_not_satisfy_installed_native_stdout(cases: tuple[QualificationCase, ...]) -> None:
    from codex_plugin_scanner.guard.adapters.bounded_cli_hook_daemon import _daemon_response_to_native

    case = _case(cases, "copilot/preToolUse/benign/small")
    stdout, stderr, code = _daemon_response_to_native(
        {
            "policy_action": "allow",
            "reason_code": "native_exact_safe_command",
            "continue": True,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        },
        harness="copilot",
        event_name="PreToolUse",
    )
    execution.validate_surface_delivery(case, json.loads(stdout), code, stderr)
    with pytest.raises(AssertionError, match="native_qualification_mismatch"):
        execution.validate_surface_delivery(
            case,
            {
                "policy_action": "allow",
                "hookSpecificOutput": {"permissionDecision": "allow"},
            },
            0,
            "",
        )


def test_actual_process_runs_read_back_cursor_script(
    context: HarnessContext, cases: tuple[QualificationCase, ...]
) -> None:
    item = _cursor(context)[0]
    script = Path(item.argv[1])
    script.write_text(
        "import json,os,sys\n"
        "p=json.load(sys.stdin)\n"
        "assert p['tool_input']['command']=='pwd'\n"
        "assert 'HOL_GUARD_CLINE_CANARY' not in os.environ\n"
        "assert 'HOL_GUARD_NATIVE_BINARY' not in os.environ\n"
        "assert sys.argv[-1]=='beforeShellExecution'\n"
        "print(json.dumps({'permission':'allow'}))\n"
    )
    item = registrations.read_registered_surfaces(context, "cursor")[0]
    session = cast(
        LauncherSession,
        cast(
            object,
            SimpleNamespace(root=context.home_dir, workspace=context.workspace_dir, guard_home=context.guard_home),
        ),
    )
    process, elapsed = execution.observe_registered_surface(
        session, item, _case(cases, "cursor/beforeShellExecution/benign/small")
    )
    assert process == {"stdout_checked": True, "exit_checked": True}
    assert elapsed > 0


@pytest.mark.parametrize("failure", ("timed_out", "containment_failed", "output_limit_exceeded"))
def test_bounded_process_failures_never_become_samples(
    context: HarnessContext,
    cases: tuple[QualificationCase, ...],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    item = _cursor(context)[0]
    result = BoundedHookProcessResult(0, '{"permission":"allow"}', False, False)
    failed = replace(result, **{failure: True})
    monkeypatch.setattr(execution, "run_isolated_hook_process", lambda *args, **kwargs: failed)
    session = cast(
        LauncherSession,
        cast(
            object,
            SimpleNamespace(root=context.home_dir, workspace=context.workspace_dir, guard_home=context.guard_home),
        ),
    )
    with pytest.raises(RuntimeError, match="process_containment_failed"):
        execution.observe_registered_surface(session, item, _case(cases, "cursor/beforeShellExecution/benign/small"))


def test_remaining_surfaces_do_not_claim_managed_json_is_host_activation() -> None:
    assessment = {item["harness"]: item for item in execution.remaining_surface_assessment()}
    assert assessment["openclaw"]["host_activation"] == "unproven"
    assert assessment["opencode"]["host_activation"] == "unproven"
    assert assessment["hermes"]["status"] == "not_executed"
    assert assessment["pi"]["full_host_activation"] is False
    assert assessment["zcode"]["post"] == "normalizer_only_not_installed"


@pytest.mark.parametrize("route", ("native_resident", "legacy"))
def test_runner_requires_native_witness_and_reports_observation_only(
    context: HarnessContext,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
) -> None:
    surfaces = tuple(item for item in _cursor(context) if item.event == "afterShellExecution")
    state: dict[str, object] = {"count": 0}

    class Metrics:
        def snapshot(self) -> dict[str, object]:
            return {"routes": {route: state["count"]}}

    def control(operation: str, **_arguments: object) -> dict[str, object]:
        if operation == "case_before":
            return {}
        case = state["case"]
        assert isinstance(case, QualificationCase) and case.native_expected is not None
        return {
            "setup": {"isolated_store": True, "effective_policy_allow": True, "policy_ack_current": True},
            "native_result": dict(case.native_expected.fields),
        }

    def observe(*_arguments: object, **_kwargs: object) -> tuple[dict[str, object], float]:
        state["count"] = int(str(state["count"])) + 1
        state["case"] = _arguments[-1]
        attempt = _kwargs["attempt"]
        assert isinstance(attempt, execution.SurfaceAttempt)
        attempt.attempted_exit = 0
        return {"stdout_checked": True, "exit_checked": True}, 1.0

    session = cast(
        execution.SurfaceSession,
        cast(
            object,
            SimpleNamespace(
                root=context.home_dir,
                workspace=context.workspace_dir,
                guard_home=context.guard_home,
                control=control,
                daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=Metrics()))),
            ),
        ),
    )
    monkeypatch.setattr(execution, "install_registered_surface", lambda *_args: surfaces)
    monkeypatch.setattr(execution, "observe_registered_surface", observe)
    evidence_path = context.home_dir / "evidence.jsonl"
    if route != "native_resident":
        from scripts.native_slo_failure import FixtureFailureError

        with pytest.raises(FixtureFailureError, match="native_route_mismatch") as failure:
            execution.run_registered_surface_corpus(session, harnesses=("cursor",), evidence_file=evidence_path)
        detail = failure.value.detail
        assert detail["category"] == "AssertionError"
        assert detail["case"] == "cursor.afterShellExecution.benign.1k"
        assert detail["surface_scope"] == "global"
        assert detail["expected_route"] == "native_resident"
        assert detail["observed_route"] == "legacy"
        assert detail["routes_before"] == {"legacy": 0}
        assert detail["routes_after"] == {"legacy": 1}
        assert detail["witness_capture"] == "after_failure"
        assert detail["witness_available"] is True
        records = [json.loads(line) for line in evidence_path.read_text().splitlines()]
        assert [record["status"] for record in records] == ["offered", "failed"]
        assert records[-1]["route"] == "legacy"
        assert records[-1]["attempted_exit"] == 0
        return
    report = execution.run_registered_surface_corpus(session, harnesses=("cursor",), evidence_file=evidence_path)
    assert report["validated_cases"] == 2
    assert report["qualification_complete"] is False
    assert report["full_host_activation"] is False
    assert all(item["model_action"] == "unreviewed_original" for item in cast(list[dict[str, object]], report["cases"]))
    records = [json.loads(line) for line in evidence_path.read_text().splitlines()]
    assert [record["status"] for record in records] == ["offered", "completed", "offered", "completed"]


def test_runner_keeps_unavailable_path_visible(context: HarnessContext) -> None:
    session = cast(
        execution.SurfaceSession,
        cast(
            object,
            SimpleNamespace(
                root=context.home_dir,
                workspace=context.workspace_dir,
                guard_home=context.home_dir / "custom-guard-home",
            ),
        ),
    )
    report = execution.run_registered_surface_corpus(session, harnesses=("cline",))
    assert report["validated_cases"] == 0
    assert report["qualification_complete"] is False
    assert report["unsupported"] == [
        {"harness": "cline", "reason": "cline_requires_default_guard_home", "executed": False}
    ]
