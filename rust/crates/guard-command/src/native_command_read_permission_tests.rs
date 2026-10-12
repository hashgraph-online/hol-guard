use super::*;

fn controls_with(enabled: &[&str]) -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    if !enabled.is_empty() {
        let controls: Vec<_> = enabled
            .iter()
            .map(|id| serde_json::json!({"target_kind": "permission", "target_id": id, "state": "enabled"}))
            .collect();
        binding.layers = serde_json::from_value(serde_json::json!([{
            "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
            "global_lockdown": false, "controls": controls
        }]))
        .unwrap();
    }
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn action(controls: &CompiledNativeCommandControls, command: &str) -> String {
    crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(controls),
        None,
    )
    .minimum_action
}

#[test]
fn read_only_graphql_queries_need_no_prompt_but_mutations_do() {
    let controls = controls_with(&[]);
    for endpoint in ["graphql", "/graphql"] {
        let query = format!(
            "gh api {endpoint} -f query='query{{repository(owner:\"example-org\",name:\"example-repo\"){{id}}}}'"
        );
        assert_eq!(action(&controls, &query), "allow", "{query}");
        // Words inside string arguments do not change the operation type.
        let search = format!(
            "gh api {endpoint} -f query='query{{search(query:\"mutation testing\",type:ISSUE,first:5){{issueCount}}}}'"
        );
        assert_eq!(action(&controls, &search), "allow", "{search}");
        for command in [
            format!("gh api {endpoint} -f query='subscription{{a}}'"),
            format!("gh api {endpoint} -f query='query{{mutation:viewer{{login}}}}'"),
            format!("gh api {endpoint} -f query='query a{{b}} mutation c{{d}}'"),
            format!("gh api {endpoint} -f query='mutation{{addStar(input:{{starrableId:\"X\"}}){{clientMutationId}}}}'"),
            format!("gh api {endpoint} -X PATCH -f query='query{{viewer{{login}}}}'"),
            format!("gh api {endpoint} -f query='query{{a}}' -f query='mutation{{b}}'"),
            format!("gh api {endpoint} -F query=@query.graphql"),
        ] {
            assert_ne!(action(&controls, &command), "allow", "{command}");
        }
    }
    assert_ne!(
        action(
            &controls,
            "gh api /repos/example-org/example-repo/git/blobs -F content=@file.txt"
        ),
        "allow"
    );
}

#[test]
fn kubectl_reads_are_an_opt_in_permission_that_never_covers_exec_or_secrets() {
    let read = "kubectl --context example -n example-namespace get deploy example-app -o jsonpath='{.status.readyReplicas}'";
    assert_ne!(action(&controls_with(&[]), read), "allow");
    let controls = controls_with(&["command.kubernetes-operations.permission.read-resources"]);
    for command in [
        read,
        "kubectl get pods -n example-namespace -l app=example-app",
        "kubectl describe deploy example-app -n example-namespace",
        "kubectl get pods -o wide",
        "kubectl get deploy example-app --output=json",
        "kubectl get pods -o custom-columns=NAME:.metadata.name",
        &format!("{read} | jq -r ."),
    ] {
        assert_eq!(action(&controls, command), "allow", "{command}");
    }
    for command in [
        "kubectl exec deploy/example-app -- sh -c id",
        "kubectl get pods -w",
        "kubectl get pods --raw /api",
        "kubectl get pods --kubeconfig /tmp/example/config",
        "kubectl get pods --server https://example.invalid",
        "kubectl get secret example-secret -o yaml",
        "kubectl get pods/example-app secrets/example-secret -o yaml",
        "kubectl describe deploy example-app secret/example-secret",
        "oc get pods/example-app secrets/example-secret -o yaml",
        "kubectl get pods -o go-template-file=/etc/passwd",
        "kubectl get pods -o jsonpath-file=/etc/passwd",
        "kubectl get pods --output=custom-columns-file=/etc/passwd",
        "kubectl get pods --output template-file=/etc/passwd",
        "kubectl get pods --template=@/etc/passwd -o go-template-file",
        "kubectl get pods -o go-template --template /etc/passwd",
        "kubectl delete pod example-app",
        &format!("{read} | python3 -c 'import os; os.system(0)'"),
        &format!("{read} > out.txt"),
    ] {
        assert_ne!(action(&controls, command), "allow", "{command}");
    }
}

#[test]
fn review_thread_queries_with_variables_and_newlines_are_reads() {
    let controls = controls_with(&[]);
    let threads = "reviewThreads(first:100){nodes{id,isResolved,isOutdated,path}}";
    for command in [
        format!("gh api graphql -f query='query{{repository(owner:\"o\",name:\"r\"){{pullRequest(number:1){{{threads}}}}}}}'"),
        format!("gh api /graphql -f query='query{{repository(owner:\"o\",name:\"r\"){{pullRequest(number:1){{{threads}}}}}}}'"),
        format!(
            "gh api graphql -F owner=o -F repo=r -F number=1 -f query='\nquery($owner:String!, $repo:String!, $number:Int!, $after:String) {{\n  repository(owner:$owner, name:$repo) {{ pullRequest(number:$number) {{ {threads} }} }}\n}}'"
        ),
    ] {
        assert_eq!(action(&controls, &command), "allow", "{command}");
    }
    for command in [
        "gh api graphql -f query='query($a:String!) { x(a:$HOME) }'".to_owned(),
        "gh api graphql -f query=\"query{ x(a:\\\"$(id)\\\") }\"".to_owned(),
        "gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){clientMutationId}}' -f id=x".to_owned(),
        "gh api graphql --input body.json".to_owned(),
        "gh api graphql -F query=@q.graphql".to_owned(),
        "gh api repos/example-org/example-repo/issues -f 'query=a $b'".to_owned(),
        // Double quotes let the shell expand `$NAME` into the request even when
        // the document repeats it as a declaration.
        "gh api graphql -f \"query=query{viewer{login}} # $DATABASE_URL: \"".to_owned(),
        "gh api graphql -f \"query=query{viewer{login}} # $FOO :\"".to_owned(),
        "gh api graphql -f query=\"query($n:Int!){viewer{login}}\"".to_owned(),
        "gh search issues \"query=$DATABASE_URL:\"".to_owned(),
        "gh search issues 'query=$GITHUB_TOKEN:'".to_owned(),
    ] {
        assert_ne!(action(&controls, &command), "allow", "{command}");
    }
}

const GITHUB_PERMISSIONS: &[&str] = &[
    "command.github.permission.access-remote",
    "command.github.permission.content-remote",
    "command.github.permission.delete-remote",
    "command.github.permission.maintain-remote",
    "command.github.permission.merge-remote",
    "command.github.permission.mutate-remote",
    "command.github.permission.read-remote",
    "command.github.permission.routine-review-thread-remote",
    "command.github.permission.unknown",
];

const RESOLVE_WITH_VARIABLE: &str = "gh api graphql -f query='
mutation($id:ID!) {
  resolveReviewThread(input:{threadId:$id}) {
    thread { id isResolved }
  }
}' -f id='PRRT_kwDOexample1234'";
const RESOLVE_LITERAL_COMMAS: &str = "gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:\"PRRT_kwDOexample1234\"}){thread{id,isResolved}}}'";
const RESOLVE_ALIASED_BATCH: &str = "gh api graphql -f query='
mutation {
  r1: resolveReviewThread(input:{threadId:\"PRRT_kwDOexample1234\"}) { thread { id } }
  r2: resolveReviewThread(input:{threadId:\"PRRT_kwDOexample5678\"}) { thread { id } }
}'";
const REPLY_MENTION: &str = "gh api repos/example-org/example-repo/pulls/1/comments/2/replies -f body='@example-bot Fixed in the latest push, thanks.'";

#[test]
fn enabled_github_permissions_cover_graphql_mutations_and_literal_mentions() {
    let controls = controls_with(GITHUB_PERMISSIONS);
    for command in [
        RESOLVE_WITH_VARIABLE,
        RESOLVE_LITERAL_COMMAS,
        RESOLVE_ALIASED_BATCH,
        REPLY_MENTION,
        "gh api graphql -f query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id isResolved}}}' -f threadId=PRRT_kwDOexample1234 --jq .data.resolveReviewThread.thread.isResolved",
        "gh api repos/example-org/example-repo/issues/1/comments -f 'body=Line one
@example-bot line two'",
        "gh api --raw-field 'body=@example-bot done' repos/example-org/example-repo/issues/1/comments",
        &format!("{RESOLVE_LITERAL_COMMAS} && {REPLY_MENTION}"),
        "gh api graphql -f query='mutation { resolveReviewThread(input: { threadId: \"PRRT_kwDOexample1234\" }) { thread { id isResolved } } }'",
        "gh api graphql -f query='mutation($t: ID!) { resolveReviewThread(input: { threadId: $t }) { thread { isResolved } } }' -f t=PRRT_kwDOexample1234",
    ] {
        assert_eq!(action(&controls, command), "allow", "{command}");
    }
    // Local file reads, undeclared variables, stdin bodies and shell expansion
    // remain unproven even when every GitHub permission is enabled.
    for command in [
        "gh api repos/example-org/example-repo/git/blobs -F content=@file.txt",
        "gh api repos/example-org/example-repo/issues/1/comments -F body=@.env",
        "gh api repos/example-org/example-repo/issues/1/comments --field 'body=@notes.md'",
        "gh api repos/example-org/example-repo/issues/1/comments -f body=\"$(cat .env)\"",
        "gh api graphql -f query='mutation{addComment(input:{subjectId:\"$HOME\",body:\"x\"}){clientMutationId}}'",
        "gh api user --jq env.GH_TOKEN",
        "gh api user --jq '.login, env'",
        "gh pr view 1 --json title --jq env",
        "gh api user --jq '$ENV.GH_TOKEN'",
        "gh pr view 1 --json title -q '$ENV'",
        "gh pr list --json title -q 'import \"x\" as x; .'",
        "printf '%s' '{\"query\":\"mutation{resolveReviewThread(input:{threadId:\\\"PRRT_kwDOexample1234\\\"}){thread{id}}}\"}' | gh api graphql --input -",
    ] {
        assert_ne!(action(&controls, command), "allow", "{command}");
    }
}

#[test]
fn routine_review_thread_permission_alone_covers_only_one_static_resolution() {
    let controls = controls_with(&["command.github.permission.routine-review-thread-remote"]);
    let projected =
        format!("{RESOLVE_WITH_VARIABLE} --jq .data.resolveReviewThread.thread.isResolved");
    for command in [
        RESOLVE_WITH_VARIABLE,
        RESOLVE_LITERAL_COMMAS,
        projected.as_str(),
    ] {
        assert_eq!(action(&controls, command), "allow", "{command}");
    }
    for command in [
        RESOLVE_ALIASED_BATCH,
        REPLY_MENTION,
        "gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$other}){thread{id}}}' -f id=PRRT_kwDOexample1234",
        "gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}' -f id=PRRT_kwDOexample1234 -f extra=1",
        "gh api graphql -f query='mutation{unresolveReviewThread(input:{threadId:\"PRRT_kwDOexample1234\"}){thread{id}}}'",
        "gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:\"PRRT_kwDOexample1234\"}){thread{id}}}' --jq 'env'",
    ] {
        assert_ne!(action(&controls, command), "allow", "{command}");
    }
    let unset = controls_with(&[]);
    for command in [RESOLVE_WITH_VARIABLE, RESOLVE_ALIASED_BATCH, REPLY_MENTION] {
        assert_ne!(action(&unset, command), "allow", "{command}");
    }
}

#[test]
fn a_github_segment_needs_every_permission_it_observes() {
    // `gh auth status` reads local and remote state; the local grant alone
    // must not cover it, even after a granted mutation in the same chain.
    let partial = controls_with(&[
        "command.github.permission.content-remote",
        "command.github.permission.mutate-remote",
        "command.github.permission.read-local",
    ]);
    let chain = "gh issue comment 1 --body hi && gh auth status";
    assert_ne!(action(&partial, chain), "allow");
    let full = controls_with(&[
        "command.github.permission.content-remote",
        "command.github.permission.mutate-remote",
        "command.github.permission.read-local",
        "command.github.permission.read-remote",
    ]);
    assert_eq!(action(&full, chain), "allow");
}

#[test]
fn a_generic_mutation_grant_does_not_cover_fields_hidden_in_fragments() {
    let controls = controls_with(&["command.github.permission.mutate-remote"]);
    for command in [
        "gh api graphql -f query='mutation { ... on Mutation { deleteRepository(input:{repositoryId:\"R_x\"}) { clientMutationId } } }'",
        "gh api graphql -f query='mutation { ...M } fragment M on Mutation { deleteRepository(input:{repositoryId:\"R_x\"}) { clientMutationId } }'",
        "gh api graphql -f query='subscription { a }'",
    ] {
        assert_ne!(action(&controls, command), "allow", "{command}");
    }
    assert_eq!(
        action(
            &controls,
            "gh api graphql -f query='mutation{addStar(input:{starrableId:\"X\"}){clientMutationId}}'"
        ),
        "allow"
    );
}
