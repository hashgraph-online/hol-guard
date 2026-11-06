from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.native_command_test_support import inspect_command_native_test as inspect_command

_INDEX_SCAN = """git diff --cached --check; echo "CHECK_EXIT=$?"

echo "==== PATH SCAN ===="
if git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' \\
  | rg -n 'unique-token-alpha'; then
  echo "PATH_SCAN=FAIL"
else
  echo "PATH_SCAN=PASS"
fi"""


@pytest.fixture(autouse=True)
def _isolate_user_git_config(  # pyright: ignore[reportUnusedFunction]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "git-config-home"
    config = home / ".config"
    config.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    for variable in (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_NAMESPACE",
        "GIT_WORK_TREE",
    ):
        monkeypatch.delenv(variable, raising=False)


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    return home, repository


def test_execution_config_cached_diff_keeps_native_uncertainty(tmp_path: Path) -> None:
    payload = inspect_command("git -c diff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.index-inspection"


def test_attached_config_override_keeps_native_uncertainty(tmp_path: Path) -> None:
    payload = inspect_command("git -cdiff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.index-inspection"


@pytest.mark.parametrize(
    "command",
    ("git diff -- --cached", "git diff -- --staged"),
)
def test_pathspec_index_flag_names_are_not_owned(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command(command, cwd=repository, home_dir=home)

    # The terminator makes these paths, not index flags. A host that can prove
    # Git helpers are inert reports no_match; every other host keeps review.
    assert payload["status"] in {"review", "no_match"}
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])
    if payload["status"] == "no_match":
        return
    # The native generic diff owner still requires proof that Git helpers cannot execute.
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == "git read command"
    assert payload["controlling_rule_id"] == "command.git.diff"
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])


@pytest.mark.parametrize(
    "command",
    (
        "git diff --cached --check",
        "git diff --cached --numstat",
        "git diff --cached --quiet",
        "git diff --cached -U3",
        "git diff --staged --stat",
        "git diff --cached --name-only HEAD",
    ),
)
def test_bounded_cached_diffs_leave_the_decision_to_the_read_proof(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command(command, cwd=repository, home_dir=home)

    # Printing the staged diff to the terminal reads no more than `git diff HEAD`.
    # A review here is the ordinary diff owner, never an index-inspection ask.
    assert payload["status"] in {"review", "no_match"}
    assert payload["classification"]["action_class"] != "git index inspection"
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])
    if payload["status"] == "no_match":
        return
    assert payload["classification"]["action_class"] == "git read command"
    assert payload["controlling_rule_id"] == "command.git.diff"


@pytest.mark.parametrize(
    "command",
    (
        "git diff --cached package.json",
        "git diff --staged src/one.ts package.json",
        "git diff --cached src",
        "git diff --cached --stat package.json",
    ),
)
def test_present_pathspec_operands_leave_the_decision_to_the_read_proof(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    (repository / "package.json").write_text("{}\n", encoding="utf-8")
    (repository / "src").mkdir()
    (repository / "src" / "one.ts").write_text("export {};\n", encoding="utf-8")
    payload = inspect_command(command, cwd=repository, home_dir=home)

    # Narrowing the staged diff to files that are already there prints the same
    # staged content as the `--` form, which the ordinary diff owner decides.
    assert payload["status"] in {"review", "no_match"}
    assert payload["classification"]["action_class"] != "git index inspection"
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])
    if payload["status"] == "no_match":
        return
    assert payload["classification"]["action_class"] == "git read command"
    assert payload["controlling_rule_id"] == "command.git.diff"


@pytest.mark.parametrize(
    "command",
    (
        # A branch is not a file in the working tree, so Git reads it as a
        # revision and compares the index against another commit.
        "git diff --cached origin/main",
        "git diff --cached ../other-project",
        "git diff --cached missing/report.json",
        "git diff --cached --output=staged.diff package.json",
    ),
)
def test_unbounded_cached_diff_operands_keep_the_index_owner(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    (repository / "package.json").write_text("{}\n", encoding="utf-8")
    payload = inspect_command(command, cwd=repository, home_dir=home)

    assert payload["status"] == "review"
    assert any(rule["rule_id"] == "command.git.index-inspection" for rule in payload["rules"])
