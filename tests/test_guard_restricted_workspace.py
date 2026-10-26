"""The workspace sandbox sink runs only a receipt-bound, natively planned command."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_containment_route as containment_route
from codex_plugin_scanner.guard import native_restricted_pytest as native
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError

COMMAND = "./todo.py add x"


def payload(command: str = COMMAND) -> dict[str, object]:
    return {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}}


def receipt(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
        "command_binding_digest": "a" * 64,
    }
    return value | changes


def plan(workspace: Path, text: str = COMMAND, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "profile_version": "workspace-contained-v1",
        "backend": "macos-seatbelt",
        "backend_executable": "/usr/bin/sandbox-exec",
        "workspace": str(workspace.resolve()),
        "cwd": str(workspace.resolve()),
        "executable": "/bin/sh",
        "command": ["/bin/sh", "-c", text],
        "command_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "allowed_executables": [],
        "read_only_roots": [],
        "exec_roots": [],
        "write_denials": [],
        "linked_git": None,
        "sandbox_path": "/usr/bin:/bin",
        "bootstrap_git": None,
        "prefix_command": None,
        "native_suffix": None,
        "denied_capabilities": [],
        "grant_identity_hash": None,
        "capabilities": [],
    }
    return value | changes


@pytest.mark.parametrize(
    "changes",
    [
        {"observe_mode": True},
        {"decision": "allow"},
        {"policy_action": "review"},
        {"reason_code": "native_pytest_readonly_containment_required"},
        {"required_execution_profile": "pytest-readonly-v2"},
        {"command_binding_digest": None},
    ],
)
def test_only_a_live_workspace_receipt_matches(changes: dict[str, object]) -> None:
    assert workspace_sink.receipt_matches(receipt())
    assert not workspace_sink.receipt_matches(receipt(**changes))
    assert not workspace_sink.receipt_matches(None)


@pytest.mark.parametrize("kind", ["git", "inline_eval", "node_tool", None])
def test_a_workspace_receipt_runs_what_the_read_only_parsers_reject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str | None
) -> None:
    # `git add -A && git commit` classifies as git and `node -e` as inline
    # eval; their read-only parsers reject both, so the receipt must decide.
    def reject(*args: object, **kwargs: object) -> None:
        raise RestrictedPytestError("pytest_restricted_invalid_command", "read-only parser")

    kinds = dict.fromkeys(("inline_eval", "node_test", "vitest", "git", "node_tool"), False)
    if kind is not None:
        kinds[kind] = True
    ran: list[object] = []
    monkeypatch.setattr(native, "restricted_native", lambda *args, **kwargs: kinds)
    for parser in ("prepare_restricted_pytest", "prepare_restricted_inline_eval"):
        monkeypatch.setattr(sink, parser, reject)
    monkeypatch.setattr(sink.restricted_git, "prepare_restricted_git", reject)
    monkeypatch.setattr(sink.restricted_node_tool, "prepare_restricted_node_tool", reject)
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: ran.append(kwargs) or 0)
    assert (
        sink.run_authorized_contained_test(
            payload(), workspace=tmp_path, timeout_seconds=20, authorize=lambda original: receipt()
        )
        == 0
    )
    assert len(ran) == 1
    for denied in (None, receipt(observe_mode=True), receipt(reason_code="native_policy_sandbox_required")):
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                payload(), workspace=tmp_path, timeout_seconds=20, authorize=lambda original, denied=denied: denied
            )
    assert len(ran) == 1


@pytest.mark.parametrize(
    "command",
    [
        "node --test 2>&1 | awk '/user.test/' | head -20",
        "git status --short && git add -A 2>&1; echo EXIT=$?",
        "cd /nonexistent && npm test",
    ],
)
def test_a_workspace_receipt_runs_shapes_the_wrapper_cannot_peel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str
) -> None:
    ran: list[object] = []
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: ran.append(args[0]) or 0)
    assert (
        sink.run_authorized_contained_test(
            payload(command), workspace=tmp_path, timeout_seconds=20, authorize=lambda original: receipt()
        )
        == 0
    )
    assert ran == [payload(command)]
    for denied in (None, receipt(observe_mode=True), receipt(required_execution_profile="pytest-readonly-v2")):
        with pytest.raises(RestrictedPytestError) as error:
            sink.run_authorized_contained_test(
                payload(command),
                workspace=tmp_path,
                timeout_seconds=20,
                authorize=lambda original, denied=denied: denied,
            )
        assert error.value.reason_code == "contained_run_authorization_failed"
    assert len(ran) == 1


def test_changed_evidence_before_launch_never_starts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(workspace_sink, "restricted_native", lambda *args, **kwargs: plan(tmp_path))
    started: list[object] = []
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda *args, **kwargs: started.append(args) or 0)
    with pytest.raises(RestrictedPytestError):
        workspace_sink.run_workspace_contained(
            payload(),
            workspace=tmp_path,
            cwd=tmp_path,
            authorize=lambda original: receipt(command_binding_digest="b" * 64),
            first_receipt=receipt(),
        )
    assert started == []


@pytest.mark.parametrize(
    "changes",
    [
        {"command": ["/bin/sh", "-c", "rm -rf x"]},
        {"backend": "linux-bubblewrap"},
        {"allowed_executables": ["/bin/sh"]},
        {"profile_version": "pytest-readonly-v2"},
        {"command_sha256": "0" * 64},
        {"prefix_command": "./todo.py"},
        {"linked_git": "/repo/.git"},
        {"linked_git": {"common": "/repo/.git"}},
        {"linked_git": {"common": "repo/.git", "admin": "/repo/.git/worktrees/w"}},
        {"linked_git": {"common": "/repo/.git", "admin": "/repo/.git/worktrees/w", "extra": "/x"}},
        {"linked_git": {"common": "/repo/.git", "admin": 3}},
    ],
)
def test_a_plan_that_differs_from_the_authorized_command_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changes: dict[str, object]
) -> None:
    monkeypatch.setattr(workspace_sink, "restricted_native", lambda *args, **kwargs: plan(tmp_path, **changes))
    started: list[object] = []
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda *args, **kwargs: started.append(args) or 0)
    with pytest.raises(RestrictedPytestError):
        workspace_sink.run_workspace_contained(
            payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
        )
    assert started == []


def test_a_read_grant_is_one_canonical_script_the_command_names(tmp_path: Path) -> None:
    (tmp_path / "scratch").mkdir()
    script = (tmp_path / "scratch" / "check.py").resolve()
    script.write_text("print(1)\n", encoding="utf-8")
    link = tmp_path / "scratch" / "link.py"
    link.symlink_to(script)
    text = f"python3 {script}"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    accepted = workspace_sink._validated_plan(plan(workspace, text, read_only_roots=[str(script)]), text, workspace)
    assert accepted["read_only_roots"] == [str(script)]
    for roots in (
        [str(script.parent)],
        [str(link)],
        ["check.py"],
        [str(tmp_path / "scratch" / "missing.py")],
        [str(tmp_path / "scratch" / "other.py")],
        str(script),
        [3],
    ):
        with pytest.raises(RestrictedPytestError):
            workspace_sink._validated_plan(plan(workspace, text, read_only_roots=roots), text, workspace)


@pytest.fixture(autouse=True)
def macos_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "macos-seatbelt")


def test_matching_plan_launches_in_the_sandbox_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[str] = []
    sent: list[object] = []
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "g"))

    def fake_native(operation: str, fields: object, expected: object) -> object:
        calls.append(operation)
        if isinstance(fields, dict) and operation == "prepare_workspace_contained":
            sent.append(fields["git_environment"])
        return "(version 1)" if operation == "macos_profile" else plan(tmp_path)

    launched: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(
        workspace_sink,
        "_restricted_environment",
        lambda source, **kwargs: {"HOME": str(kwargs["private_home"]), "PATH": "/host/bin"},
    )
    monkeypatch.setattr(
        workspace_sink,
        "_run_backend_process",
        lambda argv, **kwargs: launched.append((list(argv), kwargs["env"])) or 0,
    )
    assert (
        workspace_sink.run_workspace_contained(
            payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
        )
        == 0
    )
    argv, env = launched[0]
    assert argv[:2] == ["/usr/bin/sandbox-exec", "-p"]
    assert argv[-3:] == ["/bin/sh", "-c", COMMAND]
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert calls == ["prepare_workspace_contained", "macos_profile"]
    # Global Git configuration is located from the caller's variables, not the resident's.
    assert sent[0]["XDG_CONFIG_HOME"] == str(tmp_path / "cfg")
    assert sent[0]["GIT_CONFIG_GLOBAL"] == str(tmp_path / "g")
    assert "PATH" not in sent[0]


INIT_COMMAND = "mkdir src && git init -b main && git add -A"


@pytest.mark.parametrize(("prefix_exit", "expected"), [(0, ["mkdir src", "init", "git add -A"]), (3, ["mkdir src"])])
def test_work_before_git_init_runs_contained_and_gates_the_init(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prefix_exit: int, expected: list[str]
) -> None:
    events: list[str] = []
    init_plan = plan(tmp_path, "git add -A", bootstrap_git=["-b", "main"], prefix_command="mkdir src")
    monkeypatch.setattr(
        workspace_sink,
        "restricted_native",
        lambda operation, fields, expected: "(version 1)" if operation == "macos_profile" else init_plan,
    )
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {})
    monkeypatch.setattr(workspace_sink, "_bootstrap_init", lambda arguments, **kwargs: events.append("init"))

    def launch(argv: list[str], **kwargs: object) -> int:
        events.append(argv[-1])
        return prefix_exit if argv[-1] == "mkdir src" else 0

    monkeypatch.setattr(workspace_sink, "_run_backend_process", launch)
    exit_code = workspace_sink.run_workspace_contained(
        payload(INIT_COMMAND),
        workspace=tmp_path,
        cwd=tmp_path,
        authorize=lambda original: receipt(),
        first_receipt=receipt(),
    )
    assert exit_code == prefix_exit
    assert events == expected


def test_a_prefix_outside_the_authorized_command_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for prefix in ("rm -rf src", "mkdir src && git init -b main && git add -A"):
        bad = plan(tmp_path, "git add -A", bootstrap_git=["-b", "main"], prefix_command=prefix)
        monkeypatch.setattr(workspace_sink, "restricted_native", lambda *args, bad=bad, **kwargs: bad)
        with pytest.raises(RestrictedPytestError):
            workspace_sink.run_workspace_contained(
                payload(INIT_COMMAND),
                workspace=tmp_path,
                cwd=tmp_path,
                authorize=lambda original: receipt(),
                first_receipt=receipt(),
            )


def test_adapters_map_the_workspace_reason_to_its_profile(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Linux runs only this profile, so the resident naming it there pins the mapping.
    monkeypatch.setattr(containment_route, "host_platform", lambda: "linux")
    sink = containment_route.native_containment_sink(
        receipt(), harness="claude-code", bridge=False, payload=payload(), guard_home=native_approval_reuse_runtime
    )
    assert sink == ("workspace-contained-v1", None)


def test_linux_runs_in_an_overlay_and_applies_only_after_exit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "linux-bubblewrap")
    linux_plan = plan(tmp_path, backend="linux-bubblewrap", backend_executable="/usr/bin/bwrap")
    calls: list[tuple[str, dict[str, object]]] = []
    order: list[str] = []

    def fake_native(operation: str, fields: dict[str, object], expected: object) -> object:
        calls.append((operation, dict(fields)))
        order.append(operation)
        if operation == "workspace_bubblewrap_argv":
            return ["/usr/bin/bwrap", "--", *fields["command"]]
        if operation == "apply_workspace_overlay":
            return {"applied": 1}
        return linux_plan

    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {"PATH": "/host/bin"})

    def run(argv: list[str], **kwargs: object) -> int:
        order.append("run")
        return 3

    monkeypatch.setattr(workspace_sink, "_run_backend_process", run)
    status = workspace_sink.run_workspace_contained(
        payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
    )
    assert status == 3
    assert order == ["prepare_workspace_contained", "workspace_bubblewrap_argv", "run", "apply_workspace_overlay"]
    argv_fields = calls[1][1]
    upper = Path(str(argv_fields["upper"]))
    assert upper.parent == Path(str(argv_fields["work"])).parent
    assert not upper.parent.exists()
    assert calls[2][1]["upper"] == argv_fields["upper"]


def test_a_denied_overlay_change_fails_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "linux-bubblewrap")
    linux_plan = plan(tmp_path, backend="linux-bubblewrap", backend_executable="/usr/bin/bwrap")
    roots: list[Path] = []

    def fake_native(operation: str, fields: dict[str, object], expected: object) -> object:
        if operation == "workspace_bubblewrap_argv":
            roots.append(Path(str(fields["upper"])).parent)
            return ["/usr/bin/bwrap"]
        if operation == "apply_workspace_overlay":
            raise RestrictedPytestError("workspace_contained_write_denied", "denied")
        return linux_plan

    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {"PATH": "/host/bin"})
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda argv, **kwargs: 0)
    with pytest.raises(RestrictedPytestError) as raised:
        workspace_sink.run_workspace_contained(
            payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
        )
    assert raised.value.reason_code == "workspace_contained_write_denied"
    assert roots and not roots[0].exists()


LINKED = {"common": "/repo/.git", "admin": "/repo/.git/worktrees/report"}


def test_a_linked_worktree_overlays_the_shared_git_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "linux-bubblewrap")
    linux_plan = plan(tmp_path, backend="linux-bubblewrap", backend_executable="/usr/bin/bwrap", linked_git=LINKED)
    calls: dict[str, dict[str, object]] = {}

    def fake_native(operation: str, fields: dict[str, object], expected: object) -> object:
        calls[operation] = dict(fields)
        if operation == "workspace_bubblewrap_argv":
            assert Path(str(fields["shared_upper"])).is_dir() and Path(str(fields["shared_work"])).is_dir()
            return ["/usr/bin/bwrap", "--", *fields["command"]]
        return {"applied": 1} if operation == "apply_workspace_overlay" else linux_plan

    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {"PATH": "/host/bin"})
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda argv, **kwargs: 0)
    status = workspace_sink.run_workspace_contained(
        payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
    )
    assert status == 0
    argv_fields, applied = calls["workspace_bubblewrap_argv"], calls["apply_workspace_overlay"]
    shared_upper = Path(str(argv_fields["shared_upper"]))
    assert argv_fields["linked_git"] == applied["linked_git"] == LINKED
    assert shared_upper.parent.parent == Path(str(argv_fields["upper"])).parent
    assert applied["shared_upper"] == shared_upper
    assert "shared_work" not in applied
    assert not shared_upper.parent.parent.exists()


def test_macos_profile_receives_the_linked_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    profiles: list[dict[str, object]] = []

    def fake_native(operation: str, fields: dict[str, object], expected: object) -> object:
        if operation == "macos_profile":
            profiles.append(dict(fields))
            return "(version 1)"
        return plan(tmp_path, linked_git=LINKED)

    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {"PATH": "/host/bin"})
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda argv, **kwargs: 0)
    workspace_sink.run_workspace_contained(
        payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
    )
    assert profiles[0]["linked_git"] == LINKED


def sibling_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    session = home / "projects" / "app"
    sibling = home / "projects" / "app-report"
    for root in (session, sibling):
        (root / ".git").mkdir(parents=True)
        (root / "web").mkdir()
    return home, session, sibling


@pytest.mark.parametrize("target", ["sibling", "session"])
def test_a_workspace_receipt_runs_a_cd_below_the_root_from_that_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str
) -> None:
    # The sandbox starts only at its root, so the `cd` into a package directory
    # runs inside it as issued instead of being peeled to a cwd it refuses.
    home, session, sibling = sibling_layout(tmp_path)
    root = sibling if target == "sibling" else session
    command = f"cd {root / 'web'} && ./node_modules/.bin/vite build"
    ran: list[tuple[object, Path, Path]] = []

    def run(original: object, *, workspace: Path, cwd: Path, **kwargs: object) -> int:
        ran.append((original, workspace, cwd))
        return 0

    monkeypatch.setattr(sink, "run_workspace_contained", run)
    authorized: list[object] = []
    status = sink.run_authorized_contained_test(
        payload(command),
        workspace=session,
        timeout_seconds=20,
        authorize=lambda original: authorized.append(original) or receipt(),
        home_dir=home,
    )
    assert status == 0
    assert authorized == [payload(command)]
    assert ran == [(payload(command), root.resolve(), root.resolve())]


def test_a_cd_below_a_sibling_root_without_a_workspace_receipt_never_runs_there(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, session, sibling = sibling_layout(tmp_path)
    command = f"cd {sibling / 'web'} && ./node_modules/.bin/vite build"
    ran: list[object] = []
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: ran.append(args[0]) or 0)
    other = receipt(
        reason_code="native_pytest_readonly_containment_required", required_execution_profile="pytest-readonly-v2"
    )
    for denied in (None, receipt(observe_mode=True), other):
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                payload(command),
                workspace=session,
                timeout_seconds=20,
                authorize=lambda original, denied=denied: denied if "cd " in str(original) else None,
                home_dir=home,
            )
    assert ran == []


def test_read_grants_need_a_launched_single_canonical_script(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.restricted_workspace_grants import read_grants_valid

    root = tmp_path.resolve()
    upper = root / "Build.JS"
    good = root / "good.py"
    upper.write_text("x")
    good.write_text("x")
    assert read_grants_valid([str(upper)], f"node {upper}")
    assert not read_grants_valid([str(good)], f"python3 {root}/other/good.py")
    assert not read_grants_valid([str(good), str(upper)], f"node {upper}; python3 {good}")
    assert read_grants_valid([str(good)], f"python3 {good};echo ok")
    assert read_grants_valid([str(good)], f"python3 {good}|head")
    assert read_grants_valid([str(good)], f"python3 {good}>out.log")
    hashed = root / "run#2"
    hashed.mkdir()
    (hashed / "good.py").write_text("x")
    assert read_grants_valid([str(hashed / "good.py")], f"python3 {hashed}/good.py")
    assert not read_grants_valid([str(good)], f"python3 {good}#x")
