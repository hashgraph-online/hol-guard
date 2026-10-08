from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_vitest
from codex_plugin_scanner.guard.runtime.contained_wrapper import output_filter_suffix, peel_contained_wrapper
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError


def required_profile() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def test_peels_verified_cd_and_bounded_filters(tmp_path: Path) -> None:
    web = tmp_path / "web dir"
    web.mkdir()
    resolved = web.resolve()
    assert peel_contained_wrapper(f"cd '{web}' && pytest -q 2>&1 | tail -20", workspace=tmp_path) == (
        "pytest -q",
        resolved,
    )
    assert peel_contained_wrapper("pytest -k 'a b' | head -n 5", workspace=tmp_path) == (
        "pytest -k 'a b'",
        tmp_path,
    )
    assert peel_contained_wrapper(f"cd {tmp_path} && pytest -q", workspace=tmp_path) == (
        "pytest -q",
        tmp_path.resolve(),
    )
    assert peel_contained_wrapper("pytest -q", workspace=tmp_path) is None


@pytest.mark.parametrize(
    "command",
    [
        "cd {web} && pytest -q && rm -rf /",
        "cd {web} && pytest -q; ls",
        "cd {web} && cd .. && pytest -q",
        "cd {outside} && pytest -q",
        "cd {web}/missing && pytest -q",
        "cd web && pytest -q",
        "cd {web}; pytest -q",
        "pytest -q | tail -f",
        "pytest -q | tail -20 notes.txt",
        "pytest -q | tail -n 1234567",
        "pytest -q | sh",
        "pytest -q | tee out.txt",
        "pytest -q | tail -20 | sh",
        "pytest -q 2>/dev/null | tail -20",
        "pytest -q > out.txt | tail -20",
        "pytest -q | tail -20 &",
    ],
)
def test_rejects_other_wrapper_shapes(tmp_path: Path, command: str) -> None:
    workspace = tmp_path / "project"
    (workspace / "web").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    with pytest.raises((ValueError, OSError)):
        peel_contained_wrapper(command.format(web=workspace / "web", outside=tmp_path / "outside"), workspace=workspace)


@pytest.mark.parametrize("command", ["pytest -q '|' tail -20", "pytest -q |& tail -20", "pytest -q || tail -20"])
def test_other_operators_are_left_to_the_strict_unwrapped_path(tmp_path: Path, command: str) -> None:
    assert peel_contained_wrapper(command, workspace=tmp_path) is None


def test_sink_reauthorizes_the_core_in_its_resolved_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)

    def execute(*args, **kwargs):
        calls.append(("execute", (args, kwargs["workspace"], kwargs["cwd"])))
        return 0

    def authorize(original):
        calls.append(("authorize", (original["tool_input"]["command"], original.get("cwd"))))
        return required_profile()

    monkeypatch.setattr(sink, "run_restricted_pytest", execute)
    original = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"cd {web} && pytest -q 2>&1 | tail -20"},
        "cwd": str(tmp_path),
    }
    exit_code = sink.run_authorized_contained_test(
        original, workspace=tmp_path, timeout_seconds=20, authorize=authorize
    )
    assert exit_code == 0
    resolved = web.resolve()
    assert calls == [
        ("authorize", (original["tool_input"]["command"], str(tmp_path))),
        ("authorize", ("pytest -q", str(resolved))),
        ("execute", ((["pytest", "-q"],), resolved, resolved)),
    ]


@pytest.mark.parametrize("failure", ["allow", "review", "watch", "no-profile"])
def test_sink_needs_a_receipt_for_the_wrapped_original(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    executed = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: executed.append(args) or 0)
    wrapped = required_profile()
    if failure == "allow":
        wrapped.update(decision="allow", policy_action="allow")
    elif failure == "review":
        wrapped["policy_action"] = "review"
    elif failure == "watch":
        wrapped["observe_mode"] = True
    else:
        del wrapped["required_execution_profile"]

    def authorize(original):
        return wrapped if "|" in original["tool_input"]["command"] else required_profile()

    original = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "pytest -q | tail -5"}}
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(original, workspace=tmp_path, timeout_seconds=20, authorize=authorize)
    assert executed == []


def test_sink_rejects_unpeelable_wrappers_before_authority(tmp_path: Path) -> None:
    original = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "pytest -q | sh"}}
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(
            original, workspace=tmp_path, timeout_seconds=20, authorize=lambda value: pytest.fail("authorized")
        )


def test_output_filter_suffix_is_strict() -> None:
    assert output_filter_suffix("bunx vitest run x 2>&1 | tail -20") == " 2>&1 | tail -20"
    assert output_filter_suffix("bun run typecheck | head -n 5") == " | head -n 5"
    for command in ["pytest -q", "pytest -q | tail -f", "pytest -q | tail -20 | sh", "pytest -q | tail -20; id"]:
        assert output_filter_suffix(command) == ""


def test_bunx_cwd_selects_a_directory_inside_the_workspace(tmp_path: Path) -> None:
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd", "web", "vitest", "run", "x"]) == (
        "web",
        ("run", "x"),
    )
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd=web", "vitest", "run"]) == ("web", ("run",))
    assert restricted_vitest.bun_vitest_invocation(["bunx", "vitest", "run"]) is None
    assert restricted_vitest.bun_vitest_invocation(["bunx", "--cwd", "web", "x", "vitest", "run"]) is None
    workspace = tmp_path / "project"
    workspace.mkdir()
    (tmp_path / "other").mkdir()
    with pytest.raises(RestrictedPytestError, match="working directory"):
        restricted_vitest.prepare_restricted_vitest(
            ["bunx", "--cwd", "../other", "vitest", "run"], workspace=workspace, cwd=workspace
        )
