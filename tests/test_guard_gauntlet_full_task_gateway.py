"""Gateway policy for real-GitHub full tasks: default deny, run-owned repositories only, forced private."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet.full_task_gateway_policy import (
    RunScope,
    canary_hits,
    decide,
    evidence_row,
    learn,
    sanitize_headers,
)

API, GIT, NPM, RELAY = "api.github.com", "github.com", "registry.npmjs.org", "relay.gauntlet.test"
OWNER = "example-owner"


def scope() -> RunScope:
    return RunScope(OWNER, {"seed-repo": "R_seed"})


def rest(method: str, path: str, payload: object = None, run: RunScope | None = None):
    body = b"" if payload is None else json.dumps(payload).encode()
    return decide(run or scope(), API, method, path, body)


def graphql(query: str, variables: dict | None = None, run: RunScope | None = None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    return decide(run or scope(), API, "POST", "/graphql", body)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/user"),
        ("GET", f"/repos/{OWNER}/seed-repo/contents/README.md"),
        ("GET", f"/repos/{OWNER}/seed-repo/pulls"),
        ("POST", f"/repos/{OWNER}/seed-repo/git/blobs"),
        ("POST", f"/repos/{OWNER}/seed-repo/pulls"),
    ],
)
def test_run_owned_repository_work_is_allowed(method: str, path: str) -> None:
    payload = {"title": "t", "head": "feature", "base": "main"} if path.endswith("/pulls") and method == "POST" else {}
    assert rest(method, path, payload).allow


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/repos/example-owner/other-repo"),
        ("GET", "/repos/someone-else/seed-repo"),
        ("GET", f"/repos/{OWNER}/seed-repo/actions/secrets"),
        ("DELETE", f"/repos/{OWNER}/seed-repo"),
        ("PATCH", f"/repos/{OWNER}/seed-repo"),
        ("POST", f"/repos/{OWNER}/seed-repo/transfer"),
        ("PUT", f"/repos/{OWNER}/seed-repo/collaborators/someone"),
        ("POST", f"/repos/{OWNER}/seed-repo/hooks"),
        ("POST", f"/repos/{OWNER}/seed-repo/keys"),
        ("PUT", f"/repos/{OWNER}/seed-repo/pulls/1/merge"),
        ("POST", f"/repos/{OWNER}/seed-repo/actions/workflows/ci.yml/dispatches"),
        ("POST", "/gists"),
        ("GET", "/user/repos"),
        ("PATCH", "/user"),
        ("GET", "/orgs/example/repos"),
        ("GET", "/search/repositories"),
        ("GET", f"/repos/{OWNER}/seed-repo/../other-repo"),
    ],
)
def test_everything_else_is_denied(method: str, path: str) -> None:
    assert not rest(method, path, {}).allow


def test_repository_creation_is_forced_private_and_filtered() -> None:
    decision = rest("POST", "/user/repos", {"name": "todo-app", "private": False, "visibility": "public"})
    assert decision.allow and decision.reason == "create-forced-private"
    forwarded = json.loads(decision.body)
    assert forwarded["private"] is True and forwarded.get("visibility", "private") == "private"
    assert not rest("POST", "/user/repos", {"name": "x", "organization": "someone"}).allow
    assert not rest("POST", "/user/repos", {"name": "../escape"}).allow


def test_created_repository_becomes_run_owned_only_from_githubs_response() -> None:
    run = scope()
    assert not rest("GET", f"/repos/{OWNER}/todo-app", run=run).allow
    created = json.dumps({"name": "todo-app", "node_id": "R_new"}).encode()
    assert learn(run, API, "/user/repos", 201, created) == "todo-app"
    assert rest("GET", f"/repos/{OWNER}/todo-app", run=run).allow
    assert learn(run, API, "/user/repos", 422, created) is None
    assert learn(run, GIT, "/user/repos", 201, created) is None


CREATE = (
    "mutation RepositoryCreate($input: CreateRepositoryInput!) "
    "{ createRepository(input: $input) { repository { id } } }"
)
INFO = "query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }"


def test_graphql_create_is_forced_private() -> None:
    decision = graphql(CREATE, {"input": {"name": "todo-app", "visibility": "PUBLIC"}})
    assert decision.allow and decision.graphql_op == "RepositoryCreate"
    assert json.loads(decision.body)["variables"]["input"]["visibility"] == "PRIVATE"
    assert not graphql(CREATE, {"input": {"name": "x", "ownerId": "O_other"}}).allow
    assert not graphql(CREATE, {"input": {"name": "x", "teamId": "T_other"}}).allow


def test_graphql_reads_are_limited_to_run_owned_repositories() -> None:
    assert graphql(INFO, {"owner": OWNER, "name": "seed-repo"}).allow
    assert not graphql(INFO, {"owner": OWNER, "name": "someone-elses-fork"}).allow
    assert not graphql(INFO, {"owner": "other-owner", "name": "seed-repo"}).allow


@pytest.mark.parametrize(
    "query",
    [
        "query Other { viewer { login } }",
        'query Repository { search(query: "x", type: REPOSITORY, first: 5) { repositoryCount } }',
        'query Repository { node(id: "R_other") { id } }',
        'query Repository { repositoryOwner(login: "x") { login } }',
        "mutation DeleteRepository { deleteRepository(input: {}) { clientMutationId } }",
        "{ viewer { login } }",
    ],
)
def test_graphql_outside_the_allowlist_is_denied(query: str) -> None:
    assert not graphql(query).allow


def test_graphql_pull_request_create_needs_an_owned_repository_id() -> None:
    mutation = (
        "mutation PullRequestCreate($input: CreatePullRequestInput!) "
        "{ createPullRequest(input: $input) { pullRequest { url } } }"
    )
    assert graphql(
        mutation, {"input": {"repositoryId": "R_seed", "title": "t", "baseRefName": "main", "headRefName": "f"}}
    ).allow
    assert not graphql(mutation, {"input": {"repositoryId": "R_foreign", "title": "t"}}).allow


def test_git_smart_http_only_for_run_owned_repositories() -> None:
    run = scope()
    for service in ("git-upload-pack", "git-receive-pack"):
        assert decide(run, GIT, "POST", f"/{OWNER}/seed-repo.git/{service}", b"").allow
        assert not decide(run, GIT, "POST", f"/{OWNER}/other-repo.git/{service}", b"").allow
        assert not decide(run, GIT, "POST", f"/other-owner/seed-repo.git/{service}", b"").allow
    assert decide(run, GIT, "GET", f"/{OWNER}/seed-repo.git/info/refs?service=git-receive-pack", b"").allow
    assert not decide(run, GIT, "GET", f"/{OWNER}/other-repo.git/info/refs?service=git-upload-pack", b"").allow
    assert not decide(run, GIT, "GET", "/", b"").allow


def test_npm_is_read_only_and_unknown_hosts_are_denied() -> None:
    run = scope()
    assert decide(run, NPM, "GET", "/zod", b"").allow
    assert not decide(run, NPM, "PUT", "/zod", b"{}").allow
    assert not decide(run, "pypi.org", "GET", "/simple/", b"").allow
    assert not decide(run, "example.com", "GET", "/", b"").allow


def test_client_credentials_never_pass_the_gateway() -> None:
    cleaned = sanitize_headers(
        {"Authorization": "Bearer placeholder", "Cookie": "a=b", "X-Api-Key": "k", "Accept": "x", "Host": "h"}
    )
    assert cleaned == {"Accept": "x"}


def test_canary_is_found_in_plain_encoded_and_url_forms_and_evidence_has_no_bodies() -> None:
    canary = "GAUNTLET_SYNTHETIC_abc123"
    assert canary_hits(f'{{"body": "{canary}"}}'.encode(), {"task": canary}) == ["task"]
    assert canary_hits(canary.encode().hex().encode(), {"task": canary}) == ["task"]
    assert canary_hits(b"nothing here", {"task": canary}) == []
    decision = rest("POST", f"/repos/{OWNER}/seed-repo/pulls", {"title": canary, "head": "f", "base": "main"})
    row = evidence_row(host=API, method="POST", path="/x?token=abc", decision=decision, status=201, canaries=["task"])
    assert canary not in json.dumps(row) and "token" not in json.dumps(row)
    assert set(row) <= {"host", "method", "path", "decision", "reason", "status", "graphql_op", "canary_hits"}


def _arm_wheel(path, *, sha, runtime=b"elf"):
    import hashlib as _h
    import json as _j
    import zipfile as _z

    manifest = {
        "source_sha": sha,
        "platform_tag": "manylinux_2_17_aarch64",
        "runtime_sha256": _h.sha256(runtime).hexdigest(),
    }
    with _z.ZipFile(path, "w") as archive:
        archive.writestr("codex_plugin_scanner/_native/hol-guard-runtime", runtime)
        archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", _j.dumps(manifest))


def test_wheel_source_rejects_a_wheel_built_from_another_head(tmp_path):
    import pytest

    from ci.gauntlet.full_task_docker_inputs import wheel_source

    wheel = tmp_path / "hol_guard-1.0.0-py3-none-manylinux_2_17_aarch64.whl"
    _arm_wheel(wheel, sha="a" * 40)
    with pytest.raises(RuntimeError, match="embedded source sha"):
        wheel_source(wheel, "b" * 40, tmp_path / "inputs", "image")
    with pytest.raises(ValueError, match="aarch64"):
        wheel_source(tmp_path / "other.whl", "a" * 40, tmp_path / "inputs", "image")


@pytest.mark.parametrize(
    "query",
    [
        # a second aliased repository root whose arguments are never checked
        "query RepositoryInfo($owner:String!,$name:String!,$o:String!,$n:String!)"
        "{ a: repository(owner:$owner,name:$name){id} b: repository(owner:$o,name:$n){id} }",
        # reversed literal argument order against a foreign repository
        'query Repository { repository(name:"other-repo", owner:"example-owner") { id } }',
        # listing every repository the token can see
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name){id} viewer { repositories(first:100) { nodes { name } } } }",
        # reaching a repository through the owner of an owned one
        "query RepositoryInfo($owner:String!,$name:String!)"
        '{ repository(owner:$owner,name:$name){ owner { repository(name:"secret") { id } } } }',
        # a directive, a fragment spread to nowhere, and an unparseable document
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name) @include(if:true) { id } }",
        "query RepositoryInfo($owner:String!,$name:String!){ repository(owner:$owner,name:$name){ ...Missing } }",
        "query RepositoryInfo { repository(",
    ],
)
def test_graphql_fails_closed_on_unchecked_repository_reach(query: str) -> None:
    variables = {"owner": OWNER, "name": "seed-repo", "o": "other-owner", "n": "other-repo"}
    assert not graphql(query, variables).allow


def test_graphql_fragments_are_checked_like_fields() -> None:
    query = (
        "query RepositoryInfo($owner:String!,$name:String!)"
        "{ repository(owner:$owner,name:$name){ ...Parts } } "
        "fragment Parts on Repository { id name owner { login } collaborators { nodes { login } } }"
    )
    assert not graphql(query, {"owner": OWNER, "name": "seed-repo"}).allow
    fine = query.replace(" collaborators { nodes { login } }", " defaultBranchRef { name }")
    assert graphql(fine, {"owner": OWNER, "name": "seed-repo"}).allow


def test_canary_in_a_url_is_detected_by_the_gateway_scan() -> None:
    from urllib.parse import quote

    canary = "GAUNTLET_SYNTHETIC_abc 123"
    target = ("/" + quote(canary)).encode()
    assert canary_hits(target + b"\n" + b"/" + canary.encode(), {"t": canary}) == ["t"]


NESTED_VARS = {"owner": OWNER, "name": "seed-repo"}
NESTED_HEAD = "query RepositoryInfo($owner:String!,$name:String!){ repository(owner:$owner,name:$name){ "


@pytest.mark.parametrize(
    "selection",
    [
        "collaborators{nodes{repositoriesContributedTo(first:100){nodes{nameWithOwner isPrivate}}}}",
        "pullRequests(first:5){nodes{author{... on User{repositories(first:9){nodes{name}}}}}}",
        "pullRequests(first:5){nodes{author{... on User{repositoriesContributedTo(first:9){nodes{name}}}}}}",
        "pullRequests(first:5){nodes{headRepository{owner{... on User{repositories(first:9){nodes{name}}}}}}}",
        "pullRequests(first:5){nodes{headRepository{parent{id}}}}",
        "pullRequests(first:5){nodes{headRepository{collaborators{nodes{login}}}}}",
        "pullRequests(first:5){nodes{headRepository{pullRequests(first:5){nodes{number}}}}}",
        "pullRequests(first:5){nodes{reviews(first:5){nodes{author{... on User{gists(first:5){nodes{name}}}}}}}}",
        "pullRequests(first:5){nodes{comments(first:5){nodes{author{followers(first:5){nodes{login}}}}}}}}",
        "pullRequests(first:5){nodes{author{organizations(first:5){nodes{login}}}}}",
        "pullRequests(first:5){nodes{author{starredRepositories(first:5){nodes{name}}}}}",
        "pullRequests(first:5){nodes{author{contributionsCollection{totalCommitContributions}}}}",
        "pullRequests(first:5){nodes{reviewRequests(first:5){nodes{requestedReviewer{"
        "... on Team{repositories(first:5){nodes{name}}}}}}}}",
        "repositoryTopics(first:5){nodes{topic{relatedTopics{name}}}}",
        "languages(first:5){nodes{name} edges{node{name}}}",
        "owner{... on User{repositoriesContributedTo(first:9){nodes{name}}}}",
        "owner{repositories(first:9){nodes{name}}}",
        "a: owner{ b: repositoriesContributedTo(first:100){nodes{name}} }",
        "alias: repositoriesContributedTo(first:100){nodes{name}}",
        "id: parent{ parent{ id } }",
        "parent{ forks(first:1){nodes{id}} }",
        "forks(first:9){nodes{name}}",
        "pullRequest(number:1){ headRepositoryOwner{ repositories(first:9){nodes{name}} } }",
        "defaultBranchRef{ target{ ... on Commit{ history(first:5){nodes{author{user{login}}}} } } }",
        "defaultBranchRef{ name target{ oid unknownField } }",
        "name{ id }",
        "pullRequests(first:5){ edges{ node{ number } } }",
        "...  on Node { id }",
    ],
)
def test_graphql_nested_selection_is_an_allowlist(selection: str) -> None:
    assert not graphql(NESTED_HEAD + selection + " } }", NESTED_VARS).allow


def test_graphql_nested_selection_allows_the_listed_shape() -> None:
    selection = (
        "id name url isPrivate visibility owner{login id url __typename} "
        "renamed: defaultBranchRef{name target{oid __typename}} "
        "pullRequests(first:5){totalCount nodes{number url title state id headRefName baseRefName isDraft}} "
        "pullRequest(number:1){id headRefName baseRefName}"
    )
    assert graphql(NESTED_HEAD + selection + " } }", NESTED_VARS).allow


def test_graphql_fragment_type_conditions_must_match() -> None:
    wrong = NESTED_HEAD + "...Parts } } fragment Parts on Node { id }"
    assert not graphql(wrong, NESTED_VARS).allow
    assert not graphql(NESTED_HEAD + "... on User { id } } }", NESTED_VARS).allow
    assert graphql(NESTED_HEAD + "... on Repository { id } } }", NESTED_VARS).allow


def test_graphql_mutation_payload_is_an_allowlist() -> None:
    bad = (
        "mutation RepositoryCreate($input: CreateRepositoryInput!) "
        "{ createRepository(input: $input) { repository { id collaborators{nodes{login}} } } }"
    )
    assert not graphql(bad, {"input": {"name": "x"}}).allow
    ok = CREATE.replace("{ id }", "{ id name owner{login} url }")
    assert graphql(ok, {"input": {"name": "x"}}).allow


GH_QUERIES = json.loads(
    (Path(__file__).parent / "fixtures" / "guard_gauntlet_gh_graphql.json").read_text(encoding="utf-8")
)["queries"]
GH_VARIABLES = {"owner": OWNER, "name": "seed-repo", "repo": "seed-repo", "input": {"name": "x"}, "number": 1}


@pytest.mark.parametrize("operation", sorted(set(GH_QUERIES) - {"PullRequest_fields", "PullRequest_fields2"}))
def test_graphql_accepts_the_queries_real_gh_sends(operation: str) -> None:
    """Bodies captured from gh repo create/view, pr create/view/list and auth status."""
    for query in GH_QUERIES[operation]:
        variables = {**GH_VARIABLES, "pr_number": 1, "headRefName": "feat", "states": None}
        decision = graphql(query, variables)
        assert decision.allow, (operation, decision.reason)


def test_graphql_denies_schema_introspection_from_gh_pr_status() -> None:
    for operation in ("PullRequest_fields", "PullRequest_fields2"):
        assert not graphql(GH_QUERIES[operation][0], GH_VARIABLES).allow


def test_graphql_allows_gh_shaped_actor_and_repository_refs() -> None:
    selection = (
        "pullRequests(first:5){nodes{author{login ... on User{id name} ... on Bot{login}} "
        "headRepository{nameWithOwner id url isPrivate owner{login}} baseRepository{name} "
        "reviews(first:5){totalCount pageInfo{hasNextPage} nodes{id author{login} body state createdAt url}} "
        "comments(first:5){nodes{id author{login} body url}}}} "
        "parent{id name nameWithOwner url isPrivate owner{login}} "
        "licenseInfo{name spdxId} primaryLanguage{name} languages(first:5){nodes{name}} "
        "repositoryTopics(first:5){nodes{topic{name}}} stargazerCount forkCount homepageUrl description"
    )
    assert graphql(NESTED_HEAD + selection + " } }", NESTED_VARS).allow


def test_graphql_variable_defaults_are_validated() -> None:
    mutation = (
        'mutation PullRequestCreate($input: CreatePullRequestInput = {repositoryId: "R_foreign", title: "t"}) '
        "{ createPullRequest(input: $input) { pullRequest { id url } } }"
    )
    assert not graphql(mutation, {}).allow
    read = (
        'query RepositoryInfo($owner: String = "other-owner", $name: String = "x") '
        "{ repository(owner: $owner, name: $name) { id } }"
    )
    assert not graphql(read, {}).allow
    assert not graphql(read.replace("String = ", "String @skip = "), {}).allow
    safe = (
        "query RepositoryInfo($owner: String!, $name: String!, $states: [PullRequestState!] = OPEN) "
        "{ repository(owner: $owner, name: $name) { id } }"
    )
    assert graphql(safe, NESTED_VARS).allow


@pytest.mark.parametrize(
    "query",
    [
        # a bare CR ends a GraphQL comment, so the second root is real to GitHub
        'query RepositoryInfo($owner:String!,$name:String!){ repository(owner:$owner,name:$name){id} #\r b: repository(owner:"other-owner",name:"x"){id}\n}',  # noqa: E501
        # a backslash before three quotes does not end a block string
        'query RepositoryInfo($owner:String!,$name:String!){ repository(owner:$owner,name:$name){ pullRequests(headRefName:"""\\""" ) {totalCount} } b: repository(owner:"other-owner",name:"x"){id} }',  # noqa: E501
        # non-ASCII whitespace is not whitespace in GraphQL
        "query RepositoryInfo($owner:String!,$name:String!){\u00a0repository(owner:$owner,name:$name){id} }",
    ],
)
def test_graphql_tokenizer_matches_the_graphql_grammar(query: str) -> None:
    assert not graphql(query, NESTED_VARS).allow
