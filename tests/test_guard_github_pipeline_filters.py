"""Regression coverage for read-only GitHub output-filter pipelines."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
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
