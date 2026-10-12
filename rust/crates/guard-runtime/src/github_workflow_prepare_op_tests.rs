//! Parity vectors recorded from the retired Python implementation
//! (`github_workflow_operations.py`, `github_workflow_authorization.py`,
//! `github_workflow_context.py` digests, and `_persisted_command_matches_record`),
//! plus end-to-end `describe` runs against stub `git`/`gh` executables.

use super::*;
use crate::store_vectors_support_tests::gunzip_json;
use guard_command::command_model::CanonicalCommand;
use guard_command::github_workflow_operations::GitHubWorkflowOperation;
use std::path::PathBuf;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/github_workflow_vectors.json.gz");

fn vectors() -> Value {
    gunzip_json(VECTORS)
}

fn parse_plain(text: &str) -> Option<CanonicalCommand> {
    parse(text, None, None)
}

fn temp_dir(label: &str) -> PathBuf {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("ghwf-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn operations_match_the_retired_python() {
    let vectors = vectors();
    let cases = vectors["operations"].as_array().unwrap();
    assert!(cases.len() > 400);
    for (index, case) in cases.iter().enumerate() {
        let text = case["command"].as_str().unwrap();
        let repository = case["repository"].as_str();
        let executable = case["expected_executable"].as_str().unwrap();
        let actual = parse_plain(text)
            .and_then(|command| parse_github_workflow_operation(&command, repository, executable))
            .map(|operation| serde_json::to_value(operation).unwrap());
        let expected = (!case["expected"].is_null()).then(|| case["expected"].clone());
        assert_eq!(
            actual, expected,
            "case {index}: {text:?} repo={repository:?}"
        );
    }
}

fn context_from(value: &Value) -> GitHubWorkflowBindingContext {
    let text = |key: &str| value[key].as_str().unwrap().to_owned();
    GitHubWorkflowBindingContext {
        repository_sha256: text("repository_sha256"),
        workspace_sha256: text("workspace_sha256"),
        executable_sha256: text("executable_sha256"),
        cwd_sha256: text("cwd_sha256"),
        environment_sha256: text("environment_sha256"),
        configuration_sha256: text("configuration_sha256"),
        manifest_sha256: text("manifest_sha256"),
        lockfile_sha256: text("lockfile_sha256"),
        sandbox_sha256: text("sandbox_sha256"),
        policy_id: text("policy_id"),
        policy_version: text("policy_version"),
        effect_id: text("effect_id"),
        effect_version: text("effect_version"),
        decision_id: text("decision_id"),
        decision_version: text("decision_version"),
        rules: value["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| WorkflowCapabilityRuleBinding {
                rule_id: rule["rule_id"].as_str().unwrap().to_owned(),
                rule_version: rule["rule_version"].as_str().unwrap().to_owned(),
            })
            .collect(),
    }
}

#[test]
fn records_match_the_retired_python() {
    let vectors = vectors();
    let cases = vectors["bindings"].as_array().unwrap();
    assert_eq!(cases.len(), 100);
    for (index, case) in cases.iter().enumerate() {
        let operation: GitHubWorkflowOperation =
            serde_json::from_value(case["operation"].clone()).unwrap();
        let actual = approval_record_from_operation(&operation, &context_from(&case["context"]));
        match (&case["expected"]["record"], &case["expected"]["error"]) {
            (record, Value::Null) => {
                assert_eq!(actual.unwrap().to_value(), *record, "case {index}");
            }
            (_, error) => {
                assert_eq!(actual.err().as_deref(), error.as_str(), "case {index}");
            }
        }
    }
}

#[test]
fn framed_digests_match_the_retired_python() {
    let vectors = vectors();
    for case in vectors["digests"].as_array().unwrap() {
        let purpose = case["purpose"].as_str().unwrap();
        let actual = framed_digest(purpose, &case["payload"]);
        assert_eq!(actual.as_deref(), case["expected"].as_str(), "{purpose}");
    }
}

#[cfg(unix)]
#[test]
fn workspace_file_digests_match_the_retired_python() {
    let vectors = vectors();
    let root = temp_dir("files");
    for case in vectors["workspace_files"].as_array().unwrap() {
        for child in std::fs::read_dir(&root).unwrap() {
            let path = child.unwrap().path();
            if path.is_dir() && !path.is_symlink() {
                std::fs::remove_dir_all(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
        }
        for (name, content) in case["files"].as_object().unwrap() {
            let path = root.join(name);
            match content {
                Value::Null => std::fs::create_dir(&path).unwrap(),
                Value::Object(link) => {
                    std::os::unix::fs::symlink(link["symlink"].as_str().unwrap(), &path).unwrap();
                }
                text => std::fs::write(&path, text.as_str().unwrap()).unwrap(),
            }
        }
        let names: Vec<&str> = case["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        let actual = workspace_file_entries(&root, &names)
            .and_then(|entries| workspace_files_digest(&entries));
        assert_eq!(
            actual.as_deref(),
            case["expected"]["digest"].as_str(),
            "{}",
            case["name"]
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
fn write_executable(path: &Path, content: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn persisted_verification_matches_the_retired_python() {
    let vectors = vectors();
    let root = temp_dir("persisted");
    let contents = &vectors["persisted_executables"];
    let primary = root.join("gh");
    let other = root.join("gh-other");
    let noexec = root.join("gh-noexec");
    let link = root.join("gh-link");
    write_executable(&primary, contents["primary"].as_str().unwrap(), 0o755);
    write_executable(&other, contents["other"].as_str().unwrap(), 0o755);
    write_executable(&noexec, contents["noexec"].as_str().unwrap(), 0o644);
    std::os::unix::fs::symlink(&primary, &link).unwrap();
    let path_for = |name: &str| match name {
        "link" => &link,
        "other" => &other,
        "noexec" => &noexec,
        _ => &primary,
    };
    for case in vectors["persisted"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let fill = |template: &str, executable: &str| {
            template.replace("{exe}", path_for(executable).to_str().unwrap())
        };
        let record_exe = case["record_executable"].as_str().unwrap();
        let record_text = fill(
            case["record_command_template"].as_str().unwrap(),
            record_exe,
        );
        let record_command = parse_plain(&record_text).unwrap();
        let operation = parse_github_workflow_operation(
            &record_command,
            Some("example/repo"),
            path_for(record_exe).to_str().unwrap(),
        )
        .unwrap_or_else(|| panic!("{name}: record command must parse"));
        let mut context = vectors_context(case["context_executable_sha256"].as_str().unwrap());
        context.executable_sha256 = case["context_executable_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let record = approval_record_from_operation(&operation, &context).unwrap();
        let mut value = record.to_value();
        if let Some(mutation) = case["mutation"].as_object() {
            for (key, replacement) in mutation {
                match key.split_once('.') {
                    Some((outer, inner)) => value[outer][inner] = replacement.clone(),
                    None => value[key] = replacement.clone(),
                }
            }
        }
        let executable = case["executable"].as_str().unwrap_or("primary");
        let text = fill(case["command_template"].as_str().unwrap(), executable);
        let actual = GitHubWorkflowApprovalRecord::decode(&value)
            .is_ok_and(|decoded| persisted_matches(&text, &decoded));
        assert_eq!(actual, case["expected"].as_bool().unwrap(), "{name}");
    }
    let _ = std::fs::remove_dir_all(root);
}

fn label_sha(label: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(label.as_bytes()))
}

fn vectors_context(executable_sha256: &str) -> GitHubWorkflowBindingContext {
    GitHubWorkflowBindingContext {
        repository_sha256: github_repository_sha256("example/repo").unwrap(),
        workspace_sha256: label_sha("workspace"),
        executable_sha256: executable_sha256.to_owned(),
        cwd_sha256: label_sha("cwd"),
        environment_sha256: label_sha("env"),
        configuration_sha256: label_sha("cfg"),
        manifest_sha256: label_sha("manifest"),
        lockfile_sha256: label_sha("lock"),
        sandbox_sha256: label_sha("sandbox"),
        policy_id: "guard.command-policy".to_owned(),
        policy_version: "policy.v1@abc".to_owned(),
        effect_id: "github.maintain-remote".to_owned(),
        effect_version: "effect.v1".to_owned(),
        decision_id: "github.workflow-authorized".to_owned(),
        decision_version: "decision.v1".to_owned(),
        rules: vec![WorkflowCapabilityRuleBinding {
            rule_id: "github.maintain-remote".to_owned(),
            rule_version: "rule.v1".to_owned(),
        }],
    }
}

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
