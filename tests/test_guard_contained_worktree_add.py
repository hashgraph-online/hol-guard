"""A command that creates a linked worktree and runs checks in it runs each part as proven."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook, contained_worktree_add
from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from tests.test_guard_restricted_workspace import payload, receipt

_RUST = Path(__file__).resolve().parents[1] / "rust/crates/guard-command/src/pretool/contained_worktree_add.rs"
ADD = "git worktree add --detach ../app-fix HEAD"
ENTERED = "cd ../app-fix && npm test"
COMMAND = f"{ADD} && {ENTERED}"


def test_the_worktree_reason_matches_rust_exactly() -> None:
    source = _RUST.read_text(encoding="utf-8")
    body = source.split("const REASON_TEXT: &str = concat!(", 1)[1].split("\n);", 1)[0]
    assert "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body)) == contained_worktree_add.WORKTREE_ADD_REASON


def chain_receipt(**changes: object) -> dict[str, object]:
    return receipt(reason=contained_worktree_add.WORKTREE_ADD_REASON, **changes)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """`tmp_path/org/app` on `main`, one commit deep, under a private HOME."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "XDG_CONFIG_HOME",
    ):
        monkeypatch.delenv(name, raising=False)
    primary = tmp_path / "org" / "app"
    primary.mkdir(parents=True)
    (primary / "index.js").write_text("console.log('app')\n", encoding="utf-8")
    for arguments in (
        ["init", "-q", "-b", "main"],
        ["add", "."],
        ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", "-C", str(primary), *arguments], check=True)
    return primary


def run_chain(
    monkeypatch: pytest.MonkeyPatch,
    workspace: Path,
    *,
    split: object = None,
    chain: dict[str, object] | None = None,
    add_verdict: dict[str, object] | None = None,
    rest: object = 0,
    entered: str = ENTERED,
    rest_verdict: dict[str, object] | None = None,
) -> tuple[int, list[str], list[dict[str, object]]]:
    """Route the chain through the workspace sink; return its exit, authorizations and rest calls."""
    asked: list[str] = []
    rested: list[dict[str, object]] = []
    # Rust reads the checkout out of the chain; the sink only takes it from there.
    native = {"add": ADD, "entered": entered, "checkout": str(workspace.parent / "app-fix")}
    answer = {"worktree_add": native} if split is None else split
    monkeypatch.setattr(contained_worktree_add, "native_contained_wrapper_plan", lambda command, **kwargs: answer)

    def authorize(request: dict[str, object]) -> dict[str, object]:
        command = request["tool_input"]["command"]  # type: ignore[index]
        asked.append(command)
        if command == ADD:
            return add_verdict or {"decision": "allow", "policy_action": "allow"}
        if command == entered:
            return rest_verdict or receipt()
        return chain or chain_receipt()

    def run_rest(request: dict[str, object], **kwargs: object) -> int:
        rested.append({"command": request["tool_input"]["command"], **kwargs})  # type: ignore[index]
        if isinstance(rest, Exception):
            raise rest
        return int(rest)  # type: ignore[call-overload]

    monkeypatch.setattr(contained_test_hook, "run_authorized_contained_test", run_rest)
    exit_code = workspace_sink.run_workspace_contained(
        payload(f"{ADD} && {entered}"),
        workspace=workspace,
        cwd=workspace,
        authorize=authorize,
        first_receipt=chain_receipt(),
        home_dir=workspace.parents[1],
        timeout_seconds=30,
    )
    return exit_code, asked, rested


def test_the_proven_add_runs_then_the_rest_is_judged_in_the_checkout(
    monkeypatch: pytest.MonkeyPatch, repository: Path
) -> None:
    exit_code, asked, rested = run_chain(monkeypatch, repository)
    assert exit_code == 0
    # The chain keeps its receipt, the add is proven again on its own, and
    # the rest is judged once more against the new checkout.
    assert asked == [COMMAND, ADD, ENTERED]
    assert (repository.parent / "app-fix" / "index.js").is_file()
    assert [call["command"] for call in rested] == [ENTERED]
    assert rested[0]["workspace"] == repository
    assert rested[0]["cwd"] == repository


@pytest.mark.parametrize(
    "verdict",
    [
        {"decision": "deny", "policy_action": "review"},
        {"decision": "allow", "policy_action": "allow", "observe_mode": True},
        {"decision": "deny", "policy_action": "sandbox-required"},
    ],
)
def test_an_add_that_no_longer_passes_creates_nothing(
    monkeypatch: pytest.MonkeyPatch, repository: Path, verdict: dict[str, object]
) -> None:
    with pytest.raises(RestrictedPytestError):
        run_chain(monkeypatch, repository, add_verdict=verdict)
    assert not (repository.parent / "app-fix").exists()


@pytest.mark.parametrize(
    ("split", "chain"),
    [
        # A resident too old to split the chain.
        ({}, None),
        ({"worktree_add": {"add": ADD}}, None),
        # Rust named no checkout, so the sink has nothing it could keep out of the run.
        ({"worktree_add": {"add": ADD, "entered": ENTERED}}, None),
        ({"worktree_add": {"add": ADD, "entered": ENTERED, "checkout": ""}}, None),
        # The chain's evidence changed after it was routed here.
        (None, chain_receipt(command_binding_digest="b" * 64)),
        (None, receipt()),
        (None, chain_receipt(observe_mode=True)),
    ],
)
def test_a_chain_that_no_longer_splits_the_same_way_creates_nothing(
    monkeypatch: pytest.MonkeyPatch, repository: Path, split: object, chain: dict[str, object] | None
) -> None:
    with pytest.raises(RestrictedPytestError):
        run_chain(monkeypatch, repository, split=split, chain=chain)
    assert not (repository.parent / "app-fix").exists()


@pytest.mark.parametrize(("check", "expected"), [("test -f index.js", 0), ("test -f missing.js", 1)])
def test_a_rest_that_passes_on_its_own_runs_directly_in_the_checkout(
    monkeypatch: pytest.MonkeyPatch, repository: Path, check: str, expected: int
) -> None:
    allowed = {"decision": "allow", "policy_action": "allow"}
    exit_code, _, rested = run_chain(monkeypatch, repository, entered=f"cd ../app-fix && {check}", rest_verdict=allowed)
    assert exit_code == expected
    assert rested == []


def test_a_failed_add_never_reaches_the_rest(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    occupied = repository.parent / "app-fix"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("keep\n", encoding="utf-8")
    exit_code, _, rested = run_chain(monkeypatch, repository)
    assert exit_code != 0
    assert rested == []
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "keep\n"


def test_a_rest_that_is_refused_says_the_worktree_exists(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    refused = RestrictedPytestError("contained_run_authorization_failed", "Guard refused the checks.")
    with pytest.raises(RestrictedPytestError) as caught:
        run_chain(monkeypatch, repository, rest=refused)
    assert caught.value.reason_code == "contained_run_authorization_failed"
    assert "worktree was created" in str(caught.value)
    assert ENTERED in str(caught.value)


def test_the_checkout_comes_from_the_native_answer(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    """The sink keeps the directory Rust named out of the add, wherever it sits."""
    elsewhere = repository.parent.parent / "elsewhere"
    split = {"worktree_add": {"add": ADD, "entered": ENTERED, "checkout": str(elsewhere)}}
    excluded: list[object] = []
    real = contained_worktree_add.run_on_host

    def record(command: str, **kwargs: object) -> int:
        excluded.append(kwargs.get("excluded"))
        return real(command, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(contained_worktree_add, "run_on_host", record)
    exit_code, _, _ = run_chain(monkeypatch, repository, split=split)
    assert exit_code == 0
    assert excluded[0] == (elsewhere,)


def test_host_steps_skip_the_new_checkout_on_path_and_find_git_from_the_checkout(
    monkeypatch: pytest.MonkeyPatch, repository: Path
) -> None:
    checkout = repository.parent / "app-fix"
    planted = checkout / "bin"
    monkeypatch.setenv("PATH", f"{planted}{os.pathsep}{os.environ['PATH']}")
    # A repository location the agent inherited must not redirect Git.
    monkeypatch.setenv("GIT_DIR", str(repository.parent / "elsewhere.git"))
    allowed = {"decision": "allow", "policy_action": "allow"}
    check = 'git rev-parse --is-inside-work-tree >/dev/null && case ":$PATH:" in *app-fix*) exit 3;; esac'
    exit_code, _, rested = run_chain(monkeypatch, repository, entered=f"cd ../app-fix && {check}", rest_verdict=allowed)
    assert exit_code == 0
    assert rested == []
