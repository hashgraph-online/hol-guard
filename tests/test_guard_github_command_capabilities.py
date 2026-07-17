from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("args", "capability", "reason_code"),
    (
        (("pr", "view", "17"), "read_remote", "github.command.proven-read"),
        (("issue", "list"), "read_remote", "github.command.proven-read"),
        (("auth", "token"), "read_local", "github.command.local-auth-read"),
        (("run", "cancel", "--help"), "read_local", "github.command.local-help"),
        (
            ("--repo", "example/project", "workflow", "view", "release.yml"),
            "read_remote",
            "github.command.proven-read",
        ),
        (("api", "repos/example/project"), "read_remote", "github.api.proven-get"),
        (
            ("api", "repos/example/project", "-X", "GET", "-f", "per_page=1"),
            "read_remote",
            "github.api.proven-get",
        ),
        (
            ("api", "graphql", "-f", "query=query { viewer { login } }"),
            "read_remote",
            "github.graphql.proven-query",
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                "query=mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}",
                "-f",
                "threadId=PRRT_example",
            ),
            "maintain_remote",
            "github.graphql.proven-maintenance",
        ),
        (("pr", "merge", "17", "--squash", "--delete-branch"), "maintain_remote", "github.command.pr-maintenance"),
        (("pr", "merge", "17", "--admin"), "mutate_remote", "github.command.remote-mutation"),
        (("pr", "edit", "17", "--title", "updated"), "mutate_remote", "github.command.remote-mutation"),
        (
            ("api", "repos/example/project", "-f", "name=updated"),
            "mutate_remote",
            "github.api.implicit-write-method",
        ),
        (
            ("api", "repos/example/project", "-X", "DELETE"),
            "mutate_remote",
            "github.api.mutating-method",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { updateThing(input: {}) { id } }"),
            "mutate_remote",
            "github.graphql.remote-mutation",
        ),
        (
            ("api", "graphql", "-f", "query=subscription { eventStream { id } }"),
            "mutate_remote",
            "github.graphql.remote-mutation",
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                "query=mutation { resolveReviewThread(input: {threadId: \"T_1\"}) { thread { id } } "
                "deleteRepository(input: {repositoryId: \"R_1\"}) { repository { id } } }",
            ),
            "mutate_remote",
            "github.graphql.remote-mutation",
        ),
        (("api", "graphql", "--input", "-"), "unknown", "github.api.input-body"),
        (("project-alias",), "unknown", "github.command.extension-or-alias"),
    ),
)
def test_classify_github_cli_capabilities(args, capability, reason_code):
    assessment = classify_github_cli(args)

    assert assessment.capability == capability
    assert assessment.reason_code == reason_code


@pytest.mark.parametrize(
    "args",
    (
        ("api", "graphql", "-f", "query=query A { viewer { login } } query B { viewer { login } }"),
        ("api", "graphql", "-f", "query={ viewer { login } } { viewer { login } }"),
        ("api", "graphql", "-f", "query=query { mutationResult: viewer { login } }"),
        ("api", "graphql", "-F", "query=@query.graphql"),
        ("api", "graphql", "-f", "query=query { viewer { login } }", "-F", "owner=@owner.txt"),
        (
            "api",
            "graphql",
            "-f",
            "query=query { viewer { login } }",
            "-H",
            "X-HTTP-Method-Override: POST",
        ),
        ("api", "graphql", "-X", "GET", "-f", "query=query { viewer { login } }"),
    ),
)
def test_classify_github_cli_rejects_ambiguous_graphql_inputs(args):
    assessment = classify_github_cli(args)

    assert assessment.capability == "unknown"


@pytest.mark.parametrize(
    "command",
    (
        "gh pr view 17",
        "gh pr view ${PR_NUMBER}",
        "gh issue list --limit 10",
        "gh issue list --repo ${REPO}",
        "gh api repos/example/project -X GET -f per_page=1 --jq '.name'",
        "gh api graphql -f 'query=query { viewer { login } }' | jq -r '.data.viewer.login'",
        (
            "gh api graphql -f "
            "'query=mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
            "-f threadId=PRRT_example"
        ),
        "gh pr merge 17 --repo example/project --squash --delete-branch",
        (
            "gh api graphql -f 'query=query { viewer { login } }' 2>&1 | "
            "python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['viewer']['login'])\""
        ),
    ),
)
def test_guard_keeps_proven_github_reads_prompt_free(tmp_path, command):
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None


@pytest.mark.parametrize(
    ("command", "action_class"),
    (
        (
            "gh api repos/example/project -f name=updated --jq '.name' | jq -r '.'",
            "GitHub remote mutation command",
        ),
        (
            "gh api graphql -f 'query=mutation { updateThing(input: {}) { id } }' | jq -r '.data'",
            "GitHub remote mutation command",
        ),
        (
            "gh api graphql -f "
            "'query=mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}} "
            "deleteRepository(input:{repositoryId:$threadId}){repository{id}}}' -f threadId=R_123",
            "GitHub remote mutation command",
        ),
        ("gh pr edit 17 --title updated | jq -r '.'", "GitHub remote mutation command"),
        ("gh pr merge 17 --admin", "GitHub remote mutation command"),
        ("env GH_HOST=github.example command gh pr edit 17 --title updated", "GitHub remote mutation command"),
        ("sh -c 'gh pr edit 17 --title updated | jq -r .'", "GitHub remote mutation command"),
        ("gh project-alias | jq -r '.'", "Unverified GitHub command capability"),
        ("gh pr view 17 | tee result.json", "destructive shell command"),
        ("gh pr view 17 > result.json", "destructive shell command"),
    ),
)
def test_guard_requires_confirmation_for_github_mutations_and_unverified_compositions(
    tmp_path,
    command,
    action_class,
):
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == action_class
    assert "confirm" in match.reason.lower()
