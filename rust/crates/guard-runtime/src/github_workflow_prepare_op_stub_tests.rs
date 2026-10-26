//! End-to-end `describe`/`verify`/`lineage` runs against stub `git`/`gh` executables.

use super::tests::{temp_dir, write_executable};
use super::*;
use std::path::PathBuf;

#[cfg(unix)]
struct Stub {
    root: PathBuf,
    workspace: PathBuf,
    environment: BTreeMap<String, String>,
}

#[cfg(unix)]
fn stub(label: &str, remote: &str, gh_script: &str) -> Stub {
    let root = temp_dir(label);
    let bin = root.join("bin");
    let workspace = root.join("work");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    write_executable(
        &bin.join("git"),
        &format!("#!/bin/sh\necho '{remote}'\n"),
        0o755,
    );
    write_executable(&bin.join("gh"), gh_script, 0o755);
    std::fs::write(workspace.join("package.json"), "{}").unwrap();
    let environment = BTreeMap::from([
        ("PATH".to_owned(), bin.to_str().unwrap().to_owned()),
        ("HOME".to_owned(), root.to_str().unwrap().to_owned()),
    ]);
    Stub {
        root,
        workspace,
        environment,
    }
}

#[cfg(unix)]
fn describe_request(stub: &Stub, command: &str) -> GithubWorkflowPrepareRequestV1 {
    GithubWorkflowPrepareRequestV1 {
        schema: GITHUB_WORKFLOW_PREPARE_REQUEST_SCHEMA.to_owned(),
        request_id: "r1".to_owned(),
        mode: "describe".to_owned(),
        command_text: command.to_owned(),
        workspace: Some(stub.workspace.to_str().unwrap().to_owned()),
        config_path: Some("/cfg/config.toml".to_owned()),
        configuration: Some(json!({"default_action": "warn"})),
        sandbox: Some(json!({"analysis": "off", "required": false})),
        environment: Some(stub.environment.clone()),
        policy_version: Some("policy.v1@abc".to_owned()),
        record: None,
        approval_request: None,
        operation: None,
        session: None,
    }
}

#[cfg(unix)]
fn run(request: &GithubWorkflowPrepareRequestV1) -> GithubWorkflowPrepareResultV1 {
    serde_json::from_slice(&evaluate_github_workflow_prepare_request(request).unwrap()).unwrap()
}

#[cfg(unix)]
const VIEWER_GH: &str = "#!/bin/sh\necho '{\"login\":\"Octocat\",\"id\":1}'\n";

#[cfg(unix)]
#[test]
fn describe_binds_viewer_repository_and_executable() {
    let stub = stub("describe", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    let result = run(&describe_request(&stub, &command));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let record = GitHubWorkflowApprovalRecord::decode(&result.record.unwrap()).unwrap();
    assert_eq!(record.operation_kind, "lock-issue");
    assert_eq!(record.binding.executable_sha256, file_sha256(&gh).unwrap());
    assert_eq!(
        record.binding.repository_sha256,
        github_repository_sha256("example/repo").unwrap()
    );
    assert!(result
        .command_identity
        .unwrap()
        .starts_with("command-security-v2:"));
    // The persisted command re-verifies against the record it produced.
    let mut verify = describe_request(&stub, &command);
    verify.mode = "verify".to_owned();
    verify.record = Some(record.to_value());
    assert_eq!(run(&verify).verified, Some(true));
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
fn lineage_request(
    stub: &Stub,
    approval_request: Option<Value>,
    operation: Option<Value>,
    session: Option<Value>,
) -> GithubWorkflowPrepareRequestV1 {
    GithubWorkflowPrepareRequestV1 {
        mode: "lineage".to_owned(),
        approval_request,
        operation,
        session,
        ..describe_request(stub, "")
    }
}

/// The three store rows for one lock-issue retry, bound to the stub workspace.
#[cfg(unix)]
fn lineage_rows(command: &str, workspace: &str, record: &Value) -> (Value, Value, Value) {
    let approval_request = json!({
        "request_id": "req-1",
        "harness": "claude-code",
        "artifact_type": "tool_action_request",
        "scanner_evidence": [{"source": "github_workflow_approval_record", "record": record}],
    });
    let operation = json!({
        "operation_id": "op-1",
        "session_id": "sess-1",
        "harness": "claude-code",
        "operation_type": "tool_call",
        "status": "waiting_on_approval",
        "approval_request_ids": ["req-1"],
        "metadata": {
            "hook_event_name": "PreToolUse",
            "command_text": command,
            "workspace": workspace,
        },
    });
    let session = json!({
        "session_id": "sess-1",
        "harness": "claude-code",
        "surface": "harness-adapter",
        "capabilities": ["approval-resolution"],
        "workspace": workspace,
    });
    (approval_request, operation, session)
}

#[cfg(unix)]
#[test]
fn lineage_validates_real_rows_and_returns_their_identities() {
    let stub = stub("lineage", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    let record = run(&describe_request(&stub, &command)).record.unwrap();
    let workspace = stub.workspace.to_str().unwrap().to_owned();
    let (approval_request, operation, session) = lineage_rows(&command, &workspace, &record);

    let result = run(&lineage_request(
        &stub,
        Some(approval_request.clone()),
        Some(operation.clone()),
        Some(session.clone()),
    ));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let lineage = result.lineage.unwrap();
    assert_eq!(lineage["request_id"], "req-1");
    assert_eq!(lineage["operation_id"], "op-1");
    assert_eq!(lineage["session_id"], "sess-1");
    // The op carries the identities the lineage names the capability by, so the
    // host looks a capability up under the digest the resident derived.
    assert_eq!(
        lineage["capability_id"],
        "gwc-04caee1311432ac664fb0049886efc8542650745e0ae8d1f196e9d59e679d2e3"
    );
    assert_eq!(
        lineage["nonce"],
        "8181504e4207c78e7a25469f287b65a4d76ba8efd47133cac27a0335be52ccee"
    );
    assert_eq!(
        GitHubWorkflowApprovalRecord::decode(&lineage["record"]).unwrap(),
        GitHubWorkflowApprovalRecord::decode(&record).unwrap()
    );

    // A persisted command that no longer derives the record breaks the lineage.
    let mut moved = operation.clone();
    moved["metadata"]["command_text"] = json!(format!(
        "{} issue lock 18 --repo example/repo",
        gh.display()
    ));
    let broken = run(&lineage_request(
        &stub,
        Some(approval_request.clone()),
        Some(moved),
        Some(session),
    ));
    assert_eq!(
        (broken.status.as_str(), broken.code.as_str()),
        ("ok", "none")
    );
    assert!(broken.lineage.is_none());

    // A missing row is a malformed request, not a broken lineage.
    let missing = run(&lineage_request(
        &stub,
        Some(approval_request),
        Some(operation),
        None,
    ));
    assert_eq!(
        (missing.status.as_str(), missing.code.as_str()),
        ("error", "native_github_workflow_prepare_invalid")
    );
    assert!(missing.lineage.is_none());
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
#[test]
fn describe_declines_unbindable_contexts() {
    let stub = stub("decline", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let none = |request: &GithubWorkflowPrepareRequestV1| {
        let result = run(request);
        assert_eq!(result.code, "none");
        assert!(result.record.is_none());
    };
    none(&describe_request(
        &stub,
        &format!("{} issue lock 17 --repo other/repo", gh.display()),
    ));
    none(&describe_request(
        &stub,
        &format!("{} issue close 17 --repo example/repo", gh.display()),
    ));
    none(&describe_request(&stub, "echo hello"));
    none(&describe_request(&stub, ""));
    let mut relative_path = describe_request(
        &stub,
        &format!("{} issue lock 17 --repo example/repo", gh.display()),
    );
    relative_path.environment.as_mut().unwrap().insert(
        "PATH".to_owned(),
        format!(".:{}", stub.root.join("bin").display()),
    );
    none(&relative_path);
    let mut without_path = describe_request(
        &stub,
        &format!("{} issue lock 17 --repo example/repo", gh.display()),
    );
    without_path.environment.as_mut().unwrap().remove("PATH");
    none(&without_path);
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
#[test]
fn describe_requires_an_exact_github_remote_and_viewer() {
    let other_remote = stub("remote", "https://example.com/Example/Repo.git", VIEWER_GH);
    let gh = other_remote.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    assert_eq!(run(&describe_request(&other_remote, &command)).code, "none");
    let _ = std::fs::remove_dir_all(other_remote.root);
    let no_login = stub(
        "viewer",
        "git@github.com:Example/Repo.git",
        "#!/bin/sh\necho '{\"id\":1}'\n",
    );
    let gh = no_login.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    assert_eq!(run(&describe_request(&no_login, &command)).code, "none");
    let _ = std::fs::remove_dir_all(no_login.root);
}

#[cfg(unix)]
fn locator_script(repository: &str, extra: &str) -> String {
    format!(
        "#!/bin/sh\necho '{{\"data\":{{\"viewer\":{{\"login\":\"octocat\"}},\"node\":{{\"__typename\":\"PullRequestReviewThread\",\"id\":\"THREAD_1\",\"pullRequest\":{{\"number\":3,\"repository\":{{\"nameWithOwner\":\"{repository}\"}}}}}}}}}}{extra}'\n"
    )
}

#[cfg(unix)]
#[test]
fn review_thread_commands_locate_the_repository_through_gh() {
    let query =
        "'mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}'";
    let matching = stub(
        "thread",
        "git@github.com:Example/Repo.git",
        &locator_script("Example/Repo", ""),
    );
    let gh = matching.root.join("bin/gh");
    let command = format!(
        "{} api graphql -f query={query} -f threadId=THREAD_1",
        gh.display()
    );
    let result = run(&describe_request(&matching, &command));
    assert_eq!(result.code, "ok");
    assert_eq!(
        result.record.unwrap()["operation_kind"],
        "resolve-review-thread"
    );
    let _ = std::fs::remove_dir_all(matching.root);
    let foreign = stub(
        "thread-foreign",
        "git@github.com:Example/Repo.git",
        &locator_script("Other/Repo", ""),
    );
    let gh = foreign.root.join("bin/gh");
    let command = format!(
        "{} api graphql -f query={query} -f threadId=THREAD_1",
        gh.display()
    );
    assert_eq!(run(&describe_request(&foreign, &command)).code, "none");
    let _ = std::fs::remove_dir_all(foreign.root);
}

#[test]
fn locator_payloads_must_be_exact() {
    let good = json!({"data": {"viewer": {"login": "v"}, "node": {"__typename": "PullRequestReviewThread", "id": "T", "pullRequest": {"number": 1, "repository": {"nameWithOwner": "A/B"}}}}});
    assert_eq!(
        review_thread_location(&good, "T", "a/b"),
        Some(("a/b".to_owned(), "v".to_owned()))
    );
    assert_eq!(review_thread_location(&good, "U", "a/b"), None);
    assert_eq!(review_thread_location(&good, "T", "a/c"), None);
    let mut extra = good.clone();
    extra["data"]["node"]["extra"] = json!(1);
    assert_eq!(review_thread_location(&extra, "T", "a/b"), None);
    let mut float = good.clone();
    float["data"]["node"]["pullRequest"]["number"] = json!(1.5);
    assert_eq!(review_thread_location(&float, "T", "a/b"), None);
    assert_eq!(viewer_from_user_payload(&json!({"login": ""})), None);
    assert_eq!(viewer_from_user_payload(&json!({})), None);
    assert_eq!(viewer_from_user_payload(&json!([])), None);
}

#[test]
fn remotes_parse_like_the_retired_python() {
    for (remote, expected) in [
        ("https://github.com/Own/Repo.git", Some("own/repo")),
        ("https://github.com/Own/Repo/", Some("own/repo")),
        ("git@github.com:Own/Repo.git", Some("own/repo")),
        ("ssh://git@github.com/Own/Repo", Some("own/repo")),
        ("  https://github.com/Own/Repo\n", Some("own/repo")),
        ("https://github.com/Own/Repo/extra", None),
        ("https://gitlab.com/Own/Repo", None),
        ("http://github.com/Own/Repo", None),
    ] {
        assert_eq!(
            repository_from_remote(remote).as_deref(),
            expected,
            "{remote}"
        );
    }
}

#[test]
fn malformed_requests_are_rejected() {
    let mut request = GithubWorkflowPrepareRequestV1 {
        schema: "wrong".to_owned(),
        request_id: String::new(),
        mode: "describe".to_owned(),
        command_text: "x".to_owned(),
        workspace: None,
        config_path: None,
        configuration: None,
        sandbox: None,
        environment: None,
        policy_version: None,
        record: None,
        approval_request: None,
        operation: None,
        session: None,
    };
    let code = |request: &GithubWorkflowPrepareRequestV1| {
        serde_json::from_slice::<GithubWorkflowPrepareResultV1>(
            &evaluate_github_workflow_prepare_request(request).unwrap(),
        )
        .unwrap()
        .code
    };
    assert_eq!(
        code(&request),
        "native_github_workflow_prepare_schema_mismatch"
    );
    request.schema = GITHUB_WORKFLOW_PREPARE_REQUEST_SCHEMA.to_owned();
    assert_eq!(code(&request), "native_github_workflow_prepare_invalid");
    request.mode = "other".to_owned();
    assert_eq!(
        code(&request),
        "native_github_workflow_prepare_mode_invalid"
    );
    request.mode = "verify".to_owned();
    assert_eq!(code(&request), "native_github_workflow_prepare_invalid");
    request.command_text = "x".repeat(GITHUB_WORKFLOW_PREPARE_MAX_BYTES);
    assert!(evaluate_github_workflow_prepare_request(&request).is_err());
}

#[cfg(unix)]
fn launch_digest(
    stub: &Stub,
    command: &str,
    mutate: impl FnOnce(&mut GithubWorkflowPrepareRequestV1),
) -> String {
    let mut request = describe_request(stub, command);
    mutate(&mut request);
    let result = run(&request);
    assert_eq!(result.code, "ok");
    GitHubWorkflowApprovalRecord::decode(&result.record.unwrap())
        .unwrap()
        .binding
        .launch_sha256
}

#[cfg(unix)]
#[test]
fn launch_digest_tracks_every_environment_key_the_retired_python_bound() {
    let stub = stub("env-drift", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    let baseline = launch_digest(&stub, &command, |_| {});
    assert_eq!(
        baseline,
        launch_digest(&stub, &command, |_| {}),
        "digest is deterministic"
    );
    for key in [
        "HTTP_PROXY",
        "SSL_CERT_FILE",
        "GH_TOKEN",
        "GH_CONFIG_DIR",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
    ] {
        let drifted = launch_digest(&stub, &command, |request| {
            request
                .environment
                .as_mut()
                .unwrap()
                .insert(key.to_owned(), "changed".to_owned());
        });
        assert_ne!(
            baseline, drifted,
            "{key} drift must change the launch binding"
        );
    }
    let path_drift = launch_digest(&stub, &command, |request| {
        let environment = request.environment.as_mut().unwrap();
        let path = environment["PATH"].clone();
        environment.insert("PATH".to_owned(), format!("{path}:/usr/bin"));
    });
    assert_ne!(
        baseline, path_drift,
        "PATH drift must change the launch binding"
    );
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
#[test]
fn symlinked_and_oversized_gh_are_not_bindable() {
    let stub = stub("symlink", "git@github.com:Example/Repo.git", VIEWER_GH);
    let real = stub.root.join("bin/gh");
    let link_dir = stub.root.join("linkbin");
    std::fs::create_dir_all(&link_dir).unwrap();
    std::os::unix::fs::symlink(&real, link_dir.join("gh")).unwrap();
    std::fs::copy(stub.root.join("bin/git"), link_dir.join("git")).unwrap();
    let link = link_dir.join("gh");
    let mut request = describe_request(
        &stub,
        &format!("{} issue lock 17 --repo example/repo", link.display()),
    );
    request
        .environment
        .as_mut()
        .unwrap()
        .insert("PATH".to_owned(), link_dir.to_str().unwrap().to_owned());
    assert_eq!(run(&request).code, "none");
    let _ = std::fs::remove_dir_all(stub.root);

    let flood = "#!/bin/sh\nhead -c 70000 /dev/zero | tr '\\0' 'a'\n";
    let noisy = self::stub("oversized", "git@github.com:Example/Repo.git", flood);
    let gh = noisy.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    assert_eq!(run(&describe_request(&noisy, &command)).code, "none");
    let _ = std::fs::remove_dir_all(noisy.root);
}

#[cfg(unix)]
#[test]
fn persisted_verification_tracks_executable_bytes() {
    let stub = stub("drift", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let command = format!("{} issue lock 17 --repo example/repo", gh.display());
    let described = run(&describe_request(&stub, &command));
    let record = described.record.unwrap();
    let verify = |expected: bool| {
        let mut request = describe_request(&stub, &command);
        request.mode = "verify".to_owned();
        request.record = Some(record.clone());
        assert_eq!(run(&request).verified, Some(expected));
    };
    verify(true);
    write_executable(&gh, &format!("{VIEWER_GH}# drift\n"), 0o755);
    verify(false);
    write_executable(&gh, VIEWER_GH, 0o755);
    verify(true);
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
#[test]
fn non_canonical_launch_forms_decline() {
    let stub = stub("forms", "git@github.com:Example/Repo.git", VIEWER_GH);
    let gh = stub.root.join("bin/gh");
    let tail = "issue lock 17 --repo example/repo";
    let bin = stub.root.join("bin");
    for command in [
        format!("gh {tail}"),
        format!("./gh {tail}"),
        format!("{}/../bin/gh {tail}", bin.display()),
        format!("command {} {tail}", gh.display()),
        format!("{} {tail} &", gh.display()),
        format!("{} {tail}; echo done", gh.display()),
    ] {
        let result = run(&describe_request(&stub, &command));
        assert_eq!(result.code, "none", "{command}");
        assert!(result.record.is_none(), "{command}");
    }
    let _ = std::fs::remove_dir_all(stub.root);
}

#[cfg(unix)]
#[test]
fn bounded_runs_stop_waiting_for_descendants_that_keep_stdout_open() {
    let root = temp_dir("lingering");
    let script = root.join("lingering.sh");
    write_executable(&script, "#!/bin/sh\nsleep 5 &\necho '{}'\n", 0o755);
    let arguments = vec![script.to_str().unwrap().to_owned()];
    let started = Instant::now();
    let output = run_bounded(
        &arguments,
        &root,
        &BTreeMap::new(),
        Instant::now() + std::time::Duration::from_millis(400),
    );
    assert!(output.is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn bounded_runs_stop_at_the_shared_request_deadline() {
    let root = temp_dir("expired");
    let script = root.join("quick.sh");
    write_executable(&script, "#!/bin/sh\nsleep 3\n", 0o755);
    let arguments = vec![script.to_str().unwrap().to_owned()];
    let started = Instant::now();
    let deadline = started + std::time::Duration::from_millis(300);
    assert!(run_bounded(&arguments, &root, &BTreeMap::new(), deadline).is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(root);
}
