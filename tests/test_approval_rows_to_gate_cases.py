"""The approval-row converter must keep the replayed action and drop identifying text."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "approval_rows_to_gate_cases", Path(__file__).parents[1] / "scripts" / "approval_rows_to_gate_cases.py"
)
assert _SPEC is not None and _SPEC.loader is not None
converter = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(converter)


def test_project_paths_keep_the_file_inside_the_checkout() -> None:
    assert converter.scrub("cat /Users/alice/proj/src/a.ts", []) == "cat ${WORKTREE}/src/a.ts"
    assert converter.scrub("git -C /home/u/proj status", []) == "git -C ${WORKTREE} status"


def test_repository_owners_are_replaced_without_an_owner_flag() -> None:
    assert converter.scrub("gh api repos/acme/secret/pulls/3", []) == "gh api repos/o/r/pulls/3"
    assert converter.scrub("gh pr view 3 --repo acme/secret", []) == "gh pr view 3 --repo o/r"
    assert converter.scrub("git clone git@github.com:acme/secret.git", []) == "git clone git@github.com:o/r.git"


def test_rows_with_string_input_are_skipped_and_reasons_are_scrubbed() -> None:
    assert converter.to_case({"tool_name": "bash", "tool_input": '"ls"'}, []) is None
    case = converter.to_case(
        {"tool_name": "bash", "tool_input": {"command": "ls"}, "reason_code": "review /Users/alice/proj"}, []
    )
    assert case is not None and case["observed_reason_code"] == "review ${WORKTREE}"


def test_writes_hidden_behind_read_verbs_are_not_reads() -> None:
    for command in (
        "env rm -rf x",
        "find . -delete",
        "find . -exec rm {} +",
        "find . -fprint out.txt",
        "awk 'BEGIN{system(\"id\")}'",
        "sort -o out.txt in.txt",
        "uniq in.txt out.txt",
        "rg --pre ./run x",
        "git stash",
        # ``--`` makes ``list`` a path, so the stash is created, not listed.
        "git stash -- list",
        "git worktree --porcelain list",
        "git tag release-1",
        "git diff --output=report.patch",
        "git stash show --ext-diff",
        "git log --unknown-flag",
        "git -c core.pager=sh log",
        "git branch topic",
        "git config user.name someone",
        "gh api -XPOST repos/o/r/issues",
        "gh api --method=POST repos/o/r/issues",
        "gh repo clone o/r",
        "ls & rm x",
        "ls &> out.txt",
    ):
        assert not converter.reads_only(command), command


def test_proven_reads_still_pass() -> None:
    for command in (
        "cd ${WORKTREE} && git log --oneline -5 && git show --stat HEAD | head -30",
        "find ${WORKTREE} -maxdepth 2 -name notes.md -type f 2>/dev/null",
        "rg -c x ${WORKTREE} | sort -t: -k2 -rn | head -10",
        "git stash list",
        "git -C ${WORKTREE} config --get user.email",
        "gh api repos/o/r/check-runs/1/annotations --paginate 2>&1 | head -40",
        "gh pr view 3 --json title",
    ):
        assert converter.reads_only(command), command


def test_renaming_never_touches_option_tokens_and_ids_are_scrubbed() -> None:
    assert converter.rename_names("grep -rIl uniqueproj src", {}).startswith("grep -rIl ")
    assert converter.option_names("git log --grep=uniqueproj")
    # A name glued into a short option is left byte for byte too, so the row is dropped.
    assert converter.option_names("rg -eacmeinternal ${WORKTREE}")
    assert converter.option_names("git blame -L:chargeAcmeCustomer src/a.ts")
    assert not converter.option_names("git log --oneline -5 --name-only")
    assert converter.scrub("gh api repos/a/b/actions/jobs/115481239214/logs", []) == (
        "gh api repos/o/r/actions/jobs/123456789012/logs"
    )


def test_verb_skips_the_directory_change() -> None:
    assert converter.verb_of("cd sub && ls") == "ls"
    assert converter.verb_of("cd ${WORKTREE} && git status") == "git"


def test_two_character_names_are_scrubbed_as_path_components() -> None:
    # A private name can be two characters long, and a path component is the
    # one place a two-letter word is a name rather than a verb or a flag.
    table: dict[str, str] = {}
    assert converter.rename_names("cat ${WORKTREE}/ab", table) != "cat ${WORKTREE}/ab"
    assert table["ab"] != "ab"
    # Short verbs and flag bundles keep their bytes, so the command shape the
    # gate measures survives and the row is not dropped.
    assert converter.rename_names("cd sub && ls -la ${WORKTREE}/src", {}) == "cd sub && ls -la ${WORKTREE}/src"
    assert not converter.option_names("ls -la")
    assert not converter.option_names("grep -rn pattern")


def test_mined_ids_continue_after_the_ids_the_fixture_already_holds(tmp_path: Path) -> None:
    fixture = tmp_path / "gate.json"
    fixture.write_text(
        '{"cases": [{"id": "observed-grep-07"}, {"id": "observed-grep-03"}, '
        '{"id": "observed-git-12"}, {"id": "hand-written-01"}]}',
        encoding="utf-8",
    )
    counts = converter.existing_identities(fixture)
    assert counts["grep"] == 7
    assert counts["git"] == 12
    assert counts["ls"] == 0
