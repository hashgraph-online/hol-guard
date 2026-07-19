from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("args", "capability", "reason_code"),
    (
        (("pr", "view", "17"), "read_remote", "github.command.proven-read"),
        (("issue", "list"), "read_remote", "github.command.proven-read"),
        (("auth", "status"), "read_local", "github.command.local-auth-read"),
        (("auth", "token"), "secret_remote", "github.command.auth-token-read"),
        (("auth", "status", "--show-token"), "secret_remote", "github.command.auth-token-read"),
        (("auth", "status", "-t"), "secret_remote", "github.command.auth-token-read"),
        (("ssh-key", "list"), "read_remote", "github.command.proven-access-read"),
        (("gpg-key", "list"), "read_remote", "github.command.proven-access-read"),
        (("ssh-key", "delete", "123"), "access_remote", "github.command.access-mutation"),
        (("run", "cancel", "--help"), "workflow_remote", "github.command.workflow-mutation"),
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
            "github.graphql.maintain",
        ),
        (("pr", "merge", "17", "--squash", "--delete-branch"), "delete_remote", "github.command.pr-merge"),
        (("pr", "merge", "17", "--admin"), "merge_remote", "github.command.pr-merge"),
        (("pr", "edit", "17", "--title", "updated"), "content_remote", "github.command.content-mutation"),
        (("issue", "close", "17"), "content_remote", "github.command.content-mutation"),
        (("issue", "delete", "17"), "delete_remote", "github.command.delete-mutation"),
        (("cache", "delete", "123"), "delete_remote", "github.command.delete-mutation"),
        (("release", "create", "v1.2.3"), "publish_remote", "github.command.release-publication"),
        (("release", "delete", "v1.2.3"), "delete_remote", "github.command.delete-mutation"),
        (("repo", "edit", "--visibility", "private"), "access_remote", "github.command.repository-access-mutation"),
        (("repo", "sync", "--force"), "force_remote", "github.command.force-mutation"),
        (("secret", "set", "TOKEN"), "secret_remote", "github.command.secret-mutation"),
        (
            ("api", "repos/example/project", "-f", "name=updated"),
            "mutate_remote",
            "github.api.mutate",
        ),
        (
            ("api", "repos/example/project", "-X", "PATCH", "-f", "visibility=private"),
            "access_remote",
            "github.api.access",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { updateThing(input: {}) { id } }"),
            "mutate_remote",
            "github.graphql.mutate",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { closeIssue(input: {}) { issue { id } } }"),
            "content_remote",
            "github.graphql.content",
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                'query=fragment Maint on Mutation { resolveReviewThread(input: {threadId: "T_1"}) '
                '{ thread { id } } } mutation { deleteRepository(input: {repositoryId: "R_1"}) '
                "{ repository { id } } }",
            ),
            "mutate_remote",
            "github.graphql.remote-mutation",
        ),
        (
            ("api", "graphql", "-f", "query=subscription { eventStream { id } }"),
            "mutate_remote",
            "github.graphql.remote-mutation",
        ),
        (
            ("api", "repos/example/project", "-X", "DELETE"),
            "delete_remote",
            "github.api.delete",
        ),
        (
            ("api", "repos/example/project/git/refs/heads/main", "-X", "PATCH", "-f", "force=true"),
            "force_remote",
            "github.api.force",
        ),
        (
            (
                "api",
                "repos/example/project/contents/.github/workflows/ci.yml",
                "-X",
                "PUT",
                "-f",
                "message=update workflow",
                "-f",
                "content=ZWNobyBvaw==",
            ),
            "workflow_remote",
            "github.api.workflow",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { updateRepository(input: {}) { repository { id } } }"),
            "access_remote",
            "github.graphql.access",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { createDeployKey(input: {}) { clientMutationId } }"),
            "access_remote",
            "github.graphql.access",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { createRef(input: {}) { ref { id } } }"),
            "mutate_remote",
            "github.graphql.mutate",
        ),
        (
            ("api", "graphql", "-f", "query=mutation { deleteIssue(input: {}) { clientMutationId } }"),
            "delete_remote",
            "github.graphql.delete",
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                "query=mutation { removeOutsideCollaborator(input: {}) { clientMutationId } }",
            ),
            "access_remote",
            "github.graphql.mixed-mutation",
        ),
        (
            ("api", "repos/example/project/issues/comments/123", "-X", "DELETE"),
            "delete_remote",
            "github.api.mixed-mutation",
        ),
        (
            ("api", "orgs/example/memberships/alice", "-X", "PUT", "-f", "role=admin"),
            "access_remote",
            "github.api.access",
        ),
        (
            ("api", "repos/example/project/pages", "-X", "POST", "-f", "source=main"),
            "mutate_remote",
            "github.api.mutate",
        ),
        (
            ("api", "repos/example/project/actions/runners/registration-token", "-X", "POST"),
            "secret_remote",
            "github.api.secret",
        ),
        (
            ("api", "repos/example/project/actions/runs/123/rerun", "-X", "POST"),
            "workflow_remote",
            "github.api.workflow",
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                'query=mutation { resolveReviewThread(input: {threadId: "T_1"}) { thread { id } } '
                'deleteRepository(input: {repositoryId: "R_1"}) { repository { id } } }',
            ),
            "access_remote",
            "github.graphql.mixed-mutation",
        ),
        (("api", "graphql", "--input", "-"), "unknown", "github.api.input-body"),
        (
            ("api", "repos/example/project/issues/17/comments", "-X", "POST", "-F", "body=@body.md"),
            "unknown",
            "github.api.external-field-value",
        ),
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
        "gh ssh-key list",
        "gh gpg-key list",
        "gh api repos/example/project -X GET -f per_page=1 --jq '.name'",
        "gh api graphql -f 'query=query { viewer { login } }' | jq -r '.data.viewer.login'",
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
            'gh api graphql -f \'query=mutation { deleteRepository(input: {repositoryId: "R_1"}) '
            "{ clientMutationId } }' | jq -r '.data'",
            "GitHub access mutation command",
        ),
        (
            "gh api graphql -f "
            "'query=mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}} "
            "deleteRepository(input:{repositoryId:$threadId}){repository{id}}}' -f threadId=R_123",
            "GitHub access mutation command",
        ),
        (
            "gh api graphql -f "
            "'query=mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
            "-f threadId=PRRT_example",
            "GitHub bounded maintenance command",
        ),
        ("gh pr edit 17 --title updated", "GitHub content mutation command"),
        ("gh issue close 17", "GitHub content mutation command"),
        ("gh release create v1.2.3 --notes 'release notes'", "GitHub release publication command"),
        ("gh api repos/example/project/issues/17/comments -f body='looks good'", "GitHub content mutation command"),
        ("gh pr merge 17 --repo example/project --squash --delete-branch", "GitHub delete command"),
        ("gh pr merge 17 --admin", "GitHub merge command"),
        ("gh workflow run ci.yml", "GitHub workflow mutation command"),
        ("gh repo sync --force", "GitHub force mutation command"),
        ("gh repo delete example/project --yes", "GitHub delete command"),
        ("gh issue delete 17 --yes", "GitHub delete command"),
        ("gh release delete v1.2.3 --yes", "GitHub delete command"),
        ("gh secret set TOKEN --body value", "GitHub secret mutation command"),
        ("gh secret set TOKEN --body --help", "GitHub secret mutation command"),
        ("gh pr edit 17 --title --help", "GitHub content mutation command"),
        ("gh auth token", "GitHub secret mutation command"),
        ("gh auth status --show-token", "GitHub secret mutation command"),
        ("gh repo edit --visibility private", "GitHub access mutation command"),
        ("gh ssh-key delete 123 --yes", "GitHub access mutation command"),
        ("gh repo set-default o/r", "GitHub local configuration write"),
        ("gh pr lock 1; gh repo delete o/r --yes", "GitHub delete command"),
        (
            "gh api graphql -f 'query=mutation { resolveReviewThread(input: {}) { thread { id } } }'; "
            "gh secret set TOKEN --body value",
            "GitHub secret mutation command",
        ),
        ("gh api repos/example/project -X DELETE", "GitHub delete command"),
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
