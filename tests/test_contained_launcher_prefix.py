"""A launcher runs the program it names; the sink plans that program.

Which names are launchers is the native parser's to answer. The sink keeps no
list of its own, so a name the parser learns to read reaches the planners
without a second edit here.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_command_prefix import (
    _split_command_prefix,
    peel_run_prefixes,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    PYTEST_INVALID_COMMAND_REASON_CODE,
    RestrictedPytestError,
)

# Where native authority reads the program for each launcher shape; the grammar
# itself is tested in `guard-command` (`parser_launchers_tests.rs`).
_PROGRAM = {
    ("nice", "-n", "10", "pytest", "-q"): 3,
    ("nice", "pytest", "-q"): 1,
    ("stdbuf", "-oL", "pytest", "-q"): 2,
    ("exec", "pytest", "-q"): 1,
    ("nice", "-n", "10", "timeout", "20", "pytest", "-q"): 3,
    ("stdbuf", "-oL", "env", "CI=1", "pytest", "-q"): 2,
}
# And where it reads the program behind a transparent prefix; that grammar is
# tested in `guard-command` (`parser_wrappers.rs`).
_PREFIX = {
    ("env", "CI=1", "pytest", "-q"): 2,
    ("/usr/bin/env", "CI=1", "pytest", "-q"): 2,
    ("command", "pytest", "-q"): 1,
    ("env", "REPORT_DIR=/tmp/r", "pytest", "-q"): 2,
}
_KINDS = dict.fromkeys(("inline_eval", "node_test", "vitest", "git", "node_tool"), False)


def _native(operation: str, fields: dict[str, object], expected: object) -> object:
    if operation == "launcher_program":
        return _PROGRAM.get(tuple(fields["command"]))  # type: ignore[arg-type]
    if operation == "transparent_prefix":
        return _PREFIX.get(tuple(fields["command"]))  # type: ignore[arg-type]
    return dict(_KINDS) if operation == "contained_kind" else None


@pytest.fixture(autouse=True)
def _native_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_restricted_pytest, "restricted_native", _native)


def test_launchers_and_clocks_peel_in_either_order() -> None:
    assert peel_run_prefixes(shlex.split("nice -n 10 timeout 20 pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("timeout 20 stdbuf -oL pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("stdbuf -oL env CI=1 pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("exec pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("nohup pytest -q")) == (["nohup", "pytest", "-q"], None)


def test_the_parser_names_the_transparent_prefixes_too() -> None:
    """The sink holds no list of those names either, for the same reason.

    The parser reads `/usr/bin/env` and `/bin/env` as the `env` they name,
    while the copy the sink held knew only the bare spelling, so
    `/usr/bin/env CI=1 pytest -q` reached the planners with `/usr/bin/env` as
    its program. The copy also peeled a bare `env pytest`, which the parser
    deliberately leaves alone.
    """
    assert _split_command_prefix(shlex.split("/usr/bin/env CI=1 pytest -q")) == (["pytest", "-q"], {"CI": "1"})
    assert _split_command_prefix(shlex.split("env CI=1 pytest -q")) == (["pytest", "-q"], {"CI": "1"})
    assert _split_command_prefix(shlex.split("command pytest -q")) == (["pytest", "-q"], {})
    # An `env` carrying no assignment only bypasses shell functions, so it
    # stays the executable and the planners refuse it.
    assert _split_command_prefix(shlex.split("env pytest -q")) == (["env", "pytest", "-q"], {})


def test_a_setting_the_runner_cannot_carry_leaves_the_prefix_whole() -> None:
    """The names are the parser's; which settings may travel stays the sink's.

    Native authority reads `env REPORT_DIR=/tmp/r pytest` through to its
    program, but only an inert assignment is exported to the runner's source
    environment, so the prefix stays in place and the planners refuse it
    rather than run the program with a setting nobody filtered.
    """
    original = shlex.split("env REPORT_DIR=/tmp/r pytest -q")
    assert _split_command_prefix(original) == (original, {})
    # With a contained receipt already drawn, the read-only profile would drop
    # that setting anyway, so the peel stands.
    assert _split_command_prefix(original, drop_data=True) == (["pytest", "-q"], {})


def test_an_answer_outside_the_command_leaves_it_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    for answer in (0, 2, -1, True, "1", None):
        monkeypatch.setattr(native_restricted_pytest, "restricted_native", lambda *_, a=answer: a)
        assert peel_run_prefixes(["nice", "pytest"]) == (["nice", "pytest"], None), answer


def test_the_parser_names_the_launchers_and_the_sink_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every command that could carry one is put to the parser, and only it decides.

    Holding the names here instead is what drifted: the parser learned to read
    the shell's `exec`, the copy in the sink did not, and `exec pytest -q`
    reached the planners with `exec` as its program.
    """

    asked: list[object] = []

    def native(operation: str, fields: dict[str, object], expected: object) -> object:
        asked.append((operation, fields["command"]))
        return _native(operation, fields, expected)

    monkeypatch.setattr(native_restricted_pytest, "restricted_native", native)
    # A launcher stands as a bare name in front of a program. A command with
    # nothing behind the first word cannot carry one, and a first word spelled
    # as a path is a program of the user's own that shares the name.
    for text in ("pytest", "./nice pytest -q", "/usr/bin/nice pytest -q"):
        peel_run_prefixes(shlex.split(text))
    assert asked == []
    # Every other command is asked about, including the ones the sink once
    # held a name for and the one it did not.
    assert peel_run_prefixes(shlex.split("nice pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("exec pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("wget https://example.test")) == (
        ["wget", "https://example.test"],
        None,
    )
    # A peeled launcher leaves a command that may carry a transparent prefix of
    # its own, and that grammar is the parser's too. `wget` is no launcher, so
    # nothing is left to peel and nothing further is asked.
    assert asked == [
        ("launcher_program", ["nice", "pytest", "-q"]),
        ("transparent_prefix", ["pytest", "-q"]),
        ("launcher_program", ["pytest", "-q"]),
        ("launcher_program", ["exec", "pytest", "-q"]),
        ("transparent_prefix", ["pytest", "-q"]),
        ("launcher_program", ["pytest", "-q"]),
        ("launcher_program", ["wget", "https://example.test"]),
    ]


def _required() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def _plan_only_pytest(command: list[str], **_: object) -> None:
    if command[0] != "pytest":
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, "accepts only a pytest executable")


@pytest.mark.parametrize("text", ["nice -n 10 pytest -q", "nice pytest -q", "stdbuf -oL pytest -q", "exec pytest -q"])
def test_the_sink_runs_the_program_the_receipt_authorized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    executed: list[list[str]] = []
    asked: list[str] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda command, **_: executed.append(command) or 0)

    def authorize(original: dict[str, object]) -> dict[str, object]:
        asked.append(original["tool_input"]["command"])  # type: ignore[index]
        return _required()

    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    assert sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize) == 0
    # The receipt is drawn for the command as issued; only its program runs.
    assert asked == [text]
    assert executed == [["pytest", "-q"]]


@pytest.mark.parametrize(
    "text", ["./nice -n 10 pytest -q", "stdbuf pytest -q", "nohup pytest -q", "exec -a name pytest -q"]
)
def test_the_sink_still_refuses_a_launcher_native_authority_does_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: pytest.fail("ran"))
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: pytest.fail("ran"))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    with pytest.raises(RestrictedPytestError) as refused:
        sink.run_authorized_contained_test(
            payload, workspace=tmp_path, timeout_seconds=20, authorize=lambda _: _required()
        )
    assert refused.value.reason_code == "contained_run_authorization_failed"


def _unavailable(*_: object, **__: object) -> object:
    raise RestrictedPytestError("native_contained_argv_unavailable", "native authority is unavailable")


def test_a_native_failure_in_the_receipt_peel_still_reaches_the_workspace_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The peel asks native authority, so its failure must not escape the sink.

    Rust may still have chosen the workspace sandbox for this command. The
    receipt-time peel raises `RestrictedPytestError`, not `ValueError`, so a
    handler that reads only `ValueError` would refuse the command before the
    live decision was ever asked for.
    """
    ran: list[object] = []
    monkeypatch.setattr(native_restricted_pytest, "restricted_native", _unavailable)
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *_, **__: ran.append(True) or 0)
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
        "command_binding_digest": "0" * 64,
    }
    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "nice pytest -q"}}
    assert (
        sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=lambda _: receipt)
        == 0
    )
    assert ran == [True]


def test_a_native_failure_with_no_workspace_receipt_refuses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """With no live workspace receipt the command is still refused, closed."""
    monkeypatch.setattr(native_restricted_pytest, "restricted_native", _unavailable)
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *_, **__: pytest.fail("ran"))
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *_, **__: pytest.fail("ran"))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "nice pytest -q"}}
    with pytest.raises(RestrictedPytestError) as refused:
        sink.run_authorized_contained_test(
            payload, workspace=tmp_path, timeout_seconds=20, authorize=lambda _: _required()
        )
    assert refused.value.reason_code == "native_contained_argv_unavailable"
