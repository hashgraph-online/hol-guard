"""The installed-acceptance lane fails the builds qualification lets through.

These tests drive the lane against stub executables rather than a real build,
because the point under test is the lane's own judgement: a build that reports
a successful install while registering nothing must fail, and a build that
answers the same payload two different ways must fail as a defect rather than
being retried until it agrees.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from ci.gauntlet.installed_lane import run_lane
from ci.gauntlet.installed_registration import (
    GateBlockedError,
    assess_harness,
    install_harness,
    load_contract,
)
from ci.gauntlet.installed_replay import NON_DECISION_REASONS, handler_argv, registered_argv, replay_case
from ci.gauntlet.installed_runtime import (
    FROZEN_ONEDIR,
    SCRIPT,
    SHIM,
    InstalledRuntimeError,
    classify,
    resolve_runtime,
)
from ci.gauntlet.installed_store import STALE_COMMAND


@pytest.mark.parametrize(
    "reason_code",
    sorted(NON_DECISION_REASONS),
)
def test_infrastructure_denials_do_not_count_as_attack_protection(tmp_path, monkeypatch, reason_code):
    import subprocess

    response = {
        "policy_action": "block",
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "HOL Guard could not prepare the native policy safely.",
        },
    }
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 2, json.dumps(response), "")
    )
    result = replay_case(
        ["registered-hook"],
        {"id": "attack", "expect": "not-allow", "payload": {}},
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=2,
    )
    assert any("infrastructure failed" in failure for failure in result["failures"])
    assert result["runs"][0]["reason_code"] == reason_code


HARNESSES = ["claude-code"]


def test_lane_owned_infrastructure_codes_cover_product_availability_failures():
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
        _INTEGRITY_FAIL_CLOSED_REASON_CODES,
        _REVIEW_CANNOT_FINISH_REASON_CODES,
    )

    # The oracle stays lane-owned; adding a product outage code cannot silently
    # make that denial qualify as policy protection.
    assert (_INTEGRITY_FAIL_CLOSED_REASON_CODES | _REVIEW_CANNOT_FINISH_REASON_CODES) <= NON_DECISION_REASONS


def test_registered_hook_percentiles_include_timeouts(tmp_path, monkeypatch):
    import subprocess

    clock = iter([0.0, 0.001, 1.0, 1.005, 2.0, 2.009])
    monkeypatch.setattr("ci.gauntlet.installed_replay.time.monotonic", lambda: next(clock))
    outcomes = iter([True, False, True])

    def respond(*args, **kwargs):
        if not next(outcomes):
            raise subprocess.TimeoutExpired(args, 120)
        return subprocess.CompletedProcess(args, 0, '{"decision":"allow"}', "")

    monkeypatch.setattr(subprocess, "run", respond)
    result = replay_case(
        ["registered-hook"],
        {"id": "timed", "expect": "allow", "payload": {}},
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=3,
    )
    assert result["latency"] == {
        "method": "nearest-rank",
        "scope": "registered-hook-process-round-trip",
        "samples": 3,
        "missing_samples": 0,
        "timeouts": 1,
        "p50_ms": 5.0,
        "p90_ms": 9.0,
        "p95_ms": 9.0,
        "p99_ms": 9.0,
        "max_ms": 9.0,
        "mean_ms": 5.0,
    }
    assert result["failures"]


@pytest.mark.parametrize("nested", [True, False])
def test_zcode_requires_current_events_layout_and_replays_its_registered_command(tmp_path, nested):
    expectation = load_contract()["harnesses"]["zcode"]
    hook = tmp_path / "hol-guard-hook"
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o700)
    handler = {"type": "command", "command": str(hook)}
    events = {event: [{"matcher": "*", "hooks": [handler]}] for event in expectation["required_events"]}
    config = {"hooks": {"events": events} if nested else events}
    path = tmp_path / expectation["config"]
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(config))
    result = assess_harness(tmp_path, "zcode", expectation)
    assert result["registered"] is nested
    assert registered_argv(tmp_path, expectation, config) == ([str(hook)] if nested else None)


_CLAUDE_EVENTS = ("PreToolUse", "PermissionRequest", "PostToolUse", "Notification", "Stop", "SessionStart")

_STUB_HEAD = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

EVENTS = {events!r}
REGISTER = {register!r}
VERDICTS = {verdicts!r}
COUNTER = Path(os.environ["STUB_COUNTER"])
STALE = {stale!r}


def value(flag, default=None):
    argv = sys.argv
    return argv[argv.index(flag) + 1] if flag in argv else default


def install():
    if not REGISTER:
        print(json.dumps({{"installed": True, "harness": value("--harness", "claude-code")}}))
        return 0
    home = Path(value("--home"))
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    existing = json.loads(settings.read_text()) if settings.exists() else {{}}
    hooks = {{}}
    for event in EVENTS:
        hooks[event] = [
            {{"matcher": "Bash", "hooks": [{{"type": "command", "command": sys.argv[0], "args": ["hook"]}}]}}
        ]
    if STALE:
        for event, group in (existing.get("hooks") or {{}}).items():
            if event in hooks and isinstance(group, list):
                hooks[event].extend(group)
    existing["hooks"] = hooks
    settings.write_text(json.dumps(existing, indent=2))
    print(json.dumps({{"installed": True, "harness": value("--harness", "claude-code")}}))
    return 0


def hook():
    sys.stdin.read()
    seen = int(COUNTER.read_text()) if COUNTER.exists() else 0
    COUNTER.write_text(str(seen + 1))
    decision = VERDICTS[seen % len(VERDICTS)]
    print(json.dumps({{"hookSpecificOutput": {{"permissionDecision": decision}}}}))
    return 0


if "--version" in sys.argv:
    print("hol-guard 0.0.0-stub")
    raise SystemExit(0)
raise SystemExit(install() if sys.argv[1] == "install" else hook())
"""


def _stub(path: Path, *, register: bool, verdicts: list[str], stale: bool = False) -> Path:
    path.write_text(
        _STUB_HEAD.format(events=list(_CLAUDE_EVENTS), register=register, verdicts=verdicts, stale=stale),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture(autouse=True)
def _counter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STUB_COUNTER", str(tmp_path / "counter"))


def _run(tmp_path: Path, runtime: Path, *, repeat: int = 4) -> dict:
    return run_lane(
        runtime_path=runtime,
        harnesses=HARNESSES,
        repeat=repeat,
        require_frozen=False,
        aged_store=False,
        output=tmp_path / "evidence",
        work_root=tmp_path / "work",
    )


def test_a_build_that_registers_nothing_fails_the_lane(tmp_path: Path) -> None:
    """3.46.0 on the user's Mac reported a successful install and had no hooks."""

    runtime = _stub(tmp_path / "hol-guard", register=False, verdicts=["allow"])
    evidence = _run(tmp_path, runtime)
    assert evidence["accepted"] is False
    assert any("carries no Guard handler" in failure for failure in evidence["failures"])


def test_real_registration_and_a_steady_verdict_pass(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow", "allow"])
    evidence = _run(tmp_path, runtime)
    replay = evidence["harnesses"]["claude-code"]["replay"]
    assert replay["deterministic"] is True
    # The attack cases expect a deny, which this stub never gives, so the lane
    # must still refuse the build: a build that allows everything is not quiet,
    # it is absent.
    assert evidence["accepted"] is False
    assert all("disagreeing verdicts" not in failure for failure in evidence["failures"])
    assert any("attack payload was allowed" in failure for failure in evidence["failures"])


def test_a_verdict_split_across_identical_runs_fails(tmp_path: Path) -> None:
    """The 60/40 allow-vs-deny split that qualification scored as a pass."""

    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow", "deny"])
    evidence = _run(tmp_path, runtime)
    assert evidence["accepted"] is False
    assert any("disagreeing verdicts" in failure for failure in evidence["failures"])
    replay = evidence["harnesses"]["claude-code"]["replay"]
    assert replay["deterministic"] is False


def test_a_console_script_cannot_stand_in_for_the_frozen_bundle(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    assert classify(runtime)[0] == SCRIPT
    with pytest.raises(InstalledRuntimeError, match="console script"):
        resolve_runtime(runtime, require_frozen=True)


def test_a_shell_shim_onto_a_frozen_bundle_is_accepted(tmp_path: Path) -> None:
    """The Desktop install is reached through two `/bin/sh` wrappers.

    Its first two bytes are `#!`, so judging packaging by them would refuse a
    genuinely frozen install under --require-frozen. What settles it is that
    the executable still answers with no interpreter on PATH.
    """

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    real = bundle / "hol-guard"
    real.write_text("#!/bin/sh\necho 'hol-guard 9.9.9'\n", encoding="utf-8")
    real.chmod(real.stat().st_mode | stat.S_IEXEC)
    shim = tmp_path / "hol-guard"
    shim.write_text(f'#!/bin/sh\nexec "{real}" "$@"\n', encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    assert classify(shim)[0] == SCRIPT
    runtime = resolve_runtime(shim, require_frozen=True)
    assert runtime.kind == SHIM
    assert runtime.frozen is True


def test_a_frozen_layout_without_a_sealed_manifest_is_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    internal = bundle / "_internal" / "codex_plugin_scanner" / "_native"
    internal.mkdir(parents=True)
    (internal / "hol-guard-runtime").write_text("", encoding="utf-8")
    runtime = bundle / "hol-guard"
    runtime.write_bytes(b"\x7fELF not really")
    runtime.chmod(runtime.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(InstalledRuntimeError):
        resolve_runtime(runtime, require_frozen=True)


def test_a_stale_handler_left_by_an_older_build_fails_the_aged_pass(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"], stale=True)
    evidence = run_lane(
        runtime_path=runtime,
        harnesses=HARNESSES,
        repeat=1,
        require_frozen=False,
        aged_store=True,
        output=tmp_path / "evidence",
        work_root=tmp_path / "work",
    )
    aged = evidence["aged_store"]
    assert aged["passed"] is False
    assert any(STALE_COMMAND in failure for failure in aged["stale_handlers"])


def test_a_pip_console_script_is_refused_even_with_no_interpreter_on_path(tmp_path: Path) -> None:
    """pip writes an absolute shebang, which the kernel resolves without PATH.

    Such a script answers `--version` with an empty PATH exactly as a frozen
    bundle does, so an empty-PATH answer alone cannot tell the two apart. The
    shebang can: it hands the file to a language runtime that is not there.
    """

    script = tmp_path / "hol-guard"
    script.write_text(f"#!{sys.executable}\nprint('hol-guard 0.0.0-stub')\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    assert classify(script)[0] == SCRIPT
    with pytest.raises(InstalledRuntimeError, match="console script"):
        resolve_runtime(script, require_frozen=True)


def test_a_onedir_launcher_without_its_sealed_runtime_stays_a_onedir(tmp_path: Path) -> None:
    """A damaged onedir must be refused by name, not read as a onefile.

    Classifying it by what the bundle still contains would call it a onefile
    and skip the very artifacts this lane exists to check.
    """

    bundle = tmp_path / "bundle"
    (bundle / "_internal").mkdir(parents=True)
    runtime = bundle / "hol-guard"
    # A launcher that still answers, so the refusal comes from the empty bundle
    # rather than from the executable failing to run at all.
    runtime.write_text("#!/bin/sh\necho 'hol-guard 9.9.9'\n", encoding="utf-8")
    runtime.chmod(runtime.stat().st_mode | stat.S_IEXEC)
    kind, bundled = classify(runtime)
    assert kind == FROZEN_ONEDIR
    assert bundled is None
    with pytest.raises(InstalledRuntimeError, match="is missing"):
        resolve_runtime(runtime, require_frozen=True)


def test_a_handler_naming_a_command_this_machine_lacks_is_not_registration(tmp_path: Path) -> None:
    """A hook entry the harness could never run is not proof Guard is installed."""

    expectation = load_contract()["harnesses"]["claude-code"]
    settings = tmp_path / expectation["config"]
    settings.parent.mkdir(parents=True, exist_ok=True)
    handler = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": STALE_COMMAND, "args": ["hook"]}],
    }
    hooks = {event: [handler] for event in expectation["required_events"]}
    settings.write_text(json.dumps({expectation["hooks_key"]: hooks}), encoding="utf-8")
    assessment = assess_harness(tmp_path, "claude-code", expectation)
    assert assessment["registered"] is False
    assert assessment["dangling"]
    assert any(STALE_COMMAND in failure for failure in assessment["failures"])


def test_a_legacy_codex_hook_does_not_stand_in_for_config_toml(tmp_path: Path) -> None:
    """Codex runs config.toml. A leftover hooks.json is not that file."""

    expectation = load_contract()["harnesses"]["codex"]
    command = tmp_path / "bin" / "hol-guard"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    command.chmod(command.stat().st_mode | stat.S_IEXEC)
    legacy = tmp_path / expectation["alternate_config"]
    legacy.parent.mkdir(parents=True, exist_ok=True)
    handler = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": str(command), "args": ["hook"]}],
    }
    legacy.write_text(
        json.dumps({expectation["hooks_key"]: {expectation["replay_event"]: [handler]}}),
        encoding="utf-8",
    )
    assessment = assess_harness(tmp_path, "codex", expectation)
    assert assessment["registered"] is False
    assert assessment["carriers"] == {}
    assert any("not the file Codex runs" in failure for failure in assessment["failures"])


def test_an_extension_the_harness_never_loads_is_not_registration(tmp_path: Path) -> None:
    """Oh My Pi runs the extensions its settings list, not the files on disk."""

    expectation = load_contract()["harnesses"]["omp"]
    loaded_by = expectation["loaded_by"]
    for relative in expectation["required_files"]:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export default {};\n", encoding="utf-8")
    settings = tmp_path / loaded_by["config"]
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({loaded_by["list_key"]: []}), encoding="utf-8")
    unloaded = assess_harness(tmp_path, "omp", expectation)
    assert unloaded["registered"] is False
    assert any("does not load" in failure for failure in unloaded["failures"])

    # The agent resolves a relative entry against its own settings directory.
    relative = Path(loaded_by["file"]).name
    settings.write_text(json.dumps({loaded_by["list_key"]: [f"extensions/{relative}"]}), encoding="utf-8")
    loaded = assess_harness(tmp_path, "omp", expectation)
    assert loaded["registered"] is True


def test_a_hook_that_falls_over_on_an_attack_payload_is_not_a_denial(tmp_path: Path) -> None:
    """A crash denies nothing: the harness is left with no answer to act on."""

    hook = tmp_path / "crashing-hook"
    hook.write_text("#!/bin/sh\ncat >/dev/null\nexit 1\n", encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IEXEC)
    case = {"id": "crashing", "expect": "not-allow", "payload": {"tool_name": "Bash"}}
    result = replay_case(
        [str(hook)],
        case,
        home=tmp_path,
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        repeat=2,
    )
    assert any("never answered an attack payload" in failure for failure in result["failures"])


def test_the_contract_is_the_lanes_own_and_covers_every_claude_event() -> None:
    """Asserting against the product's contract would let an emptied one pass."""

    contract = load_contract()
    assert set(contract["harnesses"]["claude-code"]["required_events"]) == set(_CLAUDE_EVENTS)
    assert contract["harnesses"]["omp"]["replay"] is False
    assert contract["harnesses"]["omp"]["replay_gap"]
    expectations = [case["expect"] for case in contract["replay_cases"]]
    assert "allow" in expectations and "not-allow" in expectations


def test_registration_reads_the_harness_file_not_the_install_report(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {event: [] for event in _CLAUDE_EVENTS}}))
    expectation = load_contract()["harnesses"]["claude-code"]
    assessment = assess_harness(home, "claude-code", expectation)
    assert assessment["registered"] is False
    assert len(assessment["failures"]) == len(_CLAUDE_EVENTS)


def test_an_advisory_enrolment_notice_is_not_a_gate(tmp_path: Path) -> None:
    """Guard prints the approval-password notice on hosts with no gate at all.

    The notice says it does not block the command, so a failing install that
    happens to carry it is an ordinary failure. Reading it as a gate hid the
    real error behind "run this somewhere else".
    """

    runtime_path = tmp_path / "hol-guard"
    runtime_path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "hol-guard 0.0.0-stub"; exit 0; fi\n'
        'echo "Local Guard approval protection is not enabled. ... set an \\`Approval password\\`."\n'
        'echo "could not write the harness configuration" >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    runtime_path.chmod(runtime_path.stat().st_mode | stat.S_IEXEC)
    runtime = resolve_runtime(runtime_path, require_frozen=False)
    (tmp_path / "workspace").mkdir()
    result = install_harness(
        runtime,
        "claude-code",
        home=tmp_path / "home",
        guard_home=tmp_path / "home" / ".hol-guard",
        workspace=tmp_path / "workspace",
    )
    assert result["exit_code"] == 1
    assert "could not write the harness configuration" in result["stderr_tail"]


def test_a_real_gate_refusal_names_what_the_install_printed(tmp_path: Path) -> None:
    runtime_path = tmp_path / "hol-guard"
    runtime_path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "hol-guard 0.0.0-stub"; exit 0; fi\n'
        'echo "{\\"error\\": \\"approval_gate_required\\"}" >&2\n'
        "exit 4\n",
        encoding="utf-8",
    )
    runtime_path.chmod(runtime_path.stat().st_mode | stat.S_IEXEC)
    runtime = resolve_runtime(runtime_path, require_frozen=False)
    (tmp_path / "workspace").mkdir()
    with pytest.raises(GateBlockedError, match="approval_gate_required"):
        install_harness(
            runtime,
            "claude-code",
            home=tmp_path / "home",
            guard_home=tmp_path / "home" / ".hol-guard",
            workspace=tmp_path / "workspace",
        )


def test_the_lane_never_touches_the_operators_own_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sdk = str(tmp_path / "host-python-sdk")
    monkeypatch.setenv("LD_LIBRARY_PATH", sdk)
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    runtime.write_text(
        runtime.read_text().replace(
            "import json, os, sys", "import json, os, sys\nassert 'LD_LIBRARY_PATH' not in os.environ"
        )
    )
    before = os.environ.get("HOME")
    _run(tmp_path, runtime, repeat=1)
    assert os.environ.get("HOME") == before
    assert os.environ["LD_LIBRARY_PATH"] == sdk
    for relative in (".claude/settings.json", ".codex/config.toml"):
        assert not (tmp_path / "work" / relative).exists()


def test_report_only_prints_the_findings_and_still_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pull request that changes the lane must not gate on the build's defects.

    The findings still have to be written and printed, or report-only would be
    indistinguishable from a lane that found nothing.
    """

    from ci.gauntlet.__main__ import main

    runtime = _stub(tmp_path / "hol-guard", register=False, verdicts=["allow"])
    exit_code = main(
        [
            "installed",
            "--runtime",
            str(runtime),
            "--harness",
            "claude-code",
            "--repeat",
            "1",
            "--no-aged-store",
            "--report-only",
            "--output",
            str(tmp_path / "evidence"),
        ]
    )
    assert exit_code == 0
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed["accepted"] is False
    assert any("carries no Guard handler" in failure for failure in printed["failures"])
    written = json.loads((tmp_path / "evidence" / "installed-acceptance.json").read_text(encoding="utf-8"))
    assert written["accepted"] is False


def test_the_summary_names_every_finding(tmp_path: Path) -> None:
    """Evidence nobody downloads is the same as no evidence."""

    from ci.gauntlet.summarise_installed_acceptance import render

    (tmp_path / "wheel").mkdir()
    (tmp_path / "wheel" / "installed-acceptance.json").write_text(
        json.dumps(
            {
                "accepted": False,
                "repeat": 5,
                "runtime": {"version": "hol-guard 3.46.0", "kind": "shim"},
                "failures": ["benign-git-status: ordinary work was not allowed quietly (deny)"],
            }
        ),
        encoding="utf-8",
    )
    rendered = "\n".join(render(tmp_path))
    assert "hol-guard 3.46.0" in rendered
    assert "benign-git-status" in rendered
    assert "not accepted" in rendered


def test_the_summary_says_so_when_the_lane_never_ran(tmp_path: Path) -> None:
    from ci.gauntlet.summarise_installed_acceptance import render

    assert "did not get as far as running" in "\n".join(render(tmp_path / "missing"))


def test_a_shell_quoted_command_line_is_split_the_way_a_shell_would() -> None:
    """Codex records one shell command line, not an argv list.

    Taking that string whole made the entire quoted line a single filename, so
    the lane reported FileNotFoundError against a path ending in the JSON
    argument instead of running the bridge.
    """

    handler = {
        "command": "/opt/guard/hol-guard-runtime codex-hook-bridge /opt/guard/hol-guard "
        '--_hol-guard-codex-bridge \'{"state_path":"/home/a b/.hol-guard/state.json"}\''
    }

    argv = handler_argv(handler)

    assert argv == [
        "/opt/guard/hol-guard-runtime",
        "codex-hook-bridge",
        "/opt/guard/hol-guard",
        "--_hol-guard-codex-bridge",
        '{"state_path":"/home/a b/.hol-guard/state.json"}',
    ]


def test_an_argv_list_command_is_left_alone() -> None:
    assert handler_argv({"command": ["/opt/guard/hol-guard", "hook"], "args": ["--harness", "codex"]}) == [
        "/opt/guard/hol-guard",
        "hook",
        "--harness",
        "codex",
    ]


def test_an_unbalanced_quote_registers_no_argv_rather_than_an_invented_one() -> None:
    assert handler_argv({"command": "/opt/guard/hol-guard --flag 'unterminated"}) == []
