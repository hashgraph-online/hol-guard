use serde_json::{json, Value};

use super::{evaluate, QUERIES};
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};

/// A host with no resident services: every trust probe fails closed.
struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
}

fn ask(query: &str, input: &Value) -> Result<Value, &'static str> {
    let host = Host;
    let ctx = Ctx::new(&host, "/work", "/home/user");
    evaluate(query, input, &ctx, None)
}

/// `input` with a neutral native evaluation of the command `identity` names.
fn with_evaluation(input: &Value, identity: &str) -> Value {
    let mut input = input.clone();
    input["evaluation"] = json!({
        "security_identity": identity,
        "minimum_action": "monitor",
        "match_default_modes": [],
        "reason_codes": [],
        "explicitly_enabled_permission_ids": [],
        "controlling_action_class": null,
        "controlling_reason": null,
    });
    input
}

#[test]
fn unknown_queries_and_non_object_inputs_are_rejected() {
    assert_eq!(
        ask("verdict", &json!({})),
        Err("native_sensitive_request_query_unknown")
    );
    assert_eq!(
        ask("classify_path", &json!([])),
        Err("native_sensitive_request_input_invalid")
    );
    assert_eq!(
        ask("classify_path", &json!({"path": "x", "cwd": 3})),
        Err("native_sensitive_request_input_invalid")
    );
}

#[test]
fn every_listed_query_is_answered() {
    for query in QUERIES {
        assert_ne!(
            ask(query, &json!({})),
            Err("native_sensitive_request_query_unknown"),
            "{query}"
        );
    }
}

#[test]
fn ssh_private_key_path_is_classified() {
    let found = ask(
        "classify_path",
        &json!({"path": "~/.ssh/id_rsa", "cwd": "/work", "home_dir": "/home/user"}),
    )
    .expect("classified");
    assert!(found.is_object(), "{found}");
    assert!(found["family"].is_string(), "{found}");
    assert_eq!(found["requested_path"], json!("~/.ssh/id_rsa"));
}

#[test]
fn tool_action_wire_keeps_substitution_and_heredoc_text() {
    use std::path::Path;

    let command = crate::command_model::parse_shell_command(
        "cat $(echo ~/.ssh/id_rsa); sh <<'EOF'\nsecret\nEOF",
        None,
        Some(Path::new("/home/user")),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    assert!(command
        .embedded_commands
        .iter()
        .any(|item| { item.kind == "substitution" && item.text.contains("echo ~/.ssh/id_rsa") }));
    assert!(command
        .embedded_commands
        .iter()
        .any(|item| item.kind == "heredoc" && item.text.contains("secret")));
    let mut found = crate::sfrs_dispatcher_request::ToolActionRequestMatch::new(
        "Bash",
        "bash",
        &command.raw_text,
        "file_read",
        "ssh key",
    );
    found.canonical_command = Some(command.clone());
    let wire = super::tool_action_wire(&found).expect("wire");
    let embedded = wire["canonical_command"]["embedded_commands"]
        .as_array()
        .expect("embedded");
    assert_eq!(embedded.len(), command.embedded_commands.len());
    for (slot, item) in embedded.iter().zip(&command.embedded_commands) {
        assert_eq!(slot["text"], json!(item.text), "{}", item.kind);
    }
    assert_eq!(
        wire["canonical_command"]["raw_text"],
        json!(command.raw_text)
    );
}

#[test]
fn ordinary_source_path_is_not_sensitive() {
    let found = ask(
        "classify_path",
        &json!({"path": "src/main.rs", "cwd": "/work", "home_dir": "/home/user"}),
    );
    assert_eq!(found, Ok(Value::Null));
}

#[test]
fn canonical_claim_must_match_the_resident_parse() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "cat ~/.ssh/id_rsa"},
        "cwd": "/work",
        "home_dir": "/home/user",
        "canonical": {"raw_text": "cat ~/.ssh/id_rsa", "security_identity": "forged"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_canonical_unbound")
    );
}

#[test]
fn native_evaluation_claim_without_redirects_binds() {
    use std::path::Path;

    let text = "echo hi 2> /dev/null; sh -c 'echo $(date)'";
    let (cwd, home) = (Path::new("/work"), Path::new("/home/user"));
    let mut native = crate::command_model::parse_shell_command(
        text,
        Some(cwd),
        Some(home),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    let full = native.security_identity();
    native.redirects.clear();
    native.embedded_commands.clear();
    let stripped = native.security_identity();
    assert_ne!(full, stripped);
    for identity in [full.clone(), stripped] {
        let input = json!({
            "tool_name": "Bash",
            "arguments": {"command": text},
            "cwd": "/work",
            "home_dir": "/home/user",
            "canonical": {"raw_text": text, "security_identity": identity},
        });
        let found = ask("tool_action", &with_evaluation(&input, &identity)).expect(&identity);
        assert!(
            found.get("error").is_none(),
            "{identity} evaluation: {found}"
        );
        let command = &found["match"]["canonical_command"];
        assert!(
            command["redirects"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{identity} dropped redirects: {found}"
        );
        assert_eq!(
            command["security_identity"].as_str(),
            Some(full.as_str()),
            "{identity} classified the stripped command: {found}"
        );
    }
}

#[test]
fn malformed_evaluation_is_rejected() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "ls"},
        "evaluation": {"security_identity": "x", "minimum_action": "maybe"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_input_invalid")
    );
}

#[test]
fn command_list_texts_require_a_list_and_flag() {
    assert_eq!(
        ask("command_list_candidate_texts", &json!({"values": "ls"})),
        Err("native_sensitive_request_input_invalid")
    );
    let texts = ask(
        "command_list_candidate_texts",
        &json!({"values": ["cat", "README.md"], "preserve_items": false}),
    )
    .expect("texts");
    assert!(texts.is_array(), "{texts}");
}

#[test]
fn canonical_claim_parse_settings_must_be_known() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "ls"},
        "canonical": {"raw_text": "ls", "security_identity": "x", "dialect": "fish"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_input_invalid")
    );
}

#[test]
fn reduced_benign_evaluation_does_not_hide_an_embedded_secret_read() {
    use std::path::Path;

    let text = "echo $(cat ~/.ssh/id_rsa)";
    let (cwd, home) = (Path::new("/work"), Path::new("/home/user"));
    let mut native = crate::command_model::parse_shell_command(
        text,
        Some(cwd),
        Some(home),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    let full = native.security_identity();
    native.embedded_commands.clear();
    native.redirects.clear();
    let reduced = native.security_identity();
    assert_ne!(full, reduced, "the embedded read must change the identity");
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": text},
        "cwd": "/work",
        "home_dir": "/home/user",
        "canonical": {"raw_text": text, "security_identity": reduced},
        "evaluation": {
            "security_identity": reduced,
            "minimum_action": "allow",
            "match_default_modes": ["disabled"],
            "reason_codes": ["native.explicit-benign"],
            "explicitly_enabled_permission_ids": [],
            "controlling_action_class": null,
            "controlling_reason": null,
        },
    });
    let found = ask("tool_action", &input).expect("classified");
    assert!(found.get("error").is_none(), "{found}");
    let matched = &found["match"];
    assert!(
        matched.is_object(),
        "a benign evaluation of the reduced command hid the full parse: {found}"
    );
    assert_eq!(
        matched["canonical_command"]["security_identity"].as_str(),
        Some(full.as_str()),
        "{found}"
    );
    let embedded = matched["canonical_command"]["embedded_commands"]
        .as_array()
        .expect("embedded");
    assert!(
        embedded.iter().any(|item| item["text"]
            .as_str()
            .is_some_and(|text| text.contains("id_rsa"))),
        "the embedded secret read was dropped: {found}"
    );
}

#[test]
fn uncertain_native_model_claim_binds_to_the_full_parse() {
    let text = "stripe products delete prod_123 2> --help";
    let request = crate::CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let model = crate::parse_command(&request).expect("model");
    let input = json!({
        "tool_name": "Shell",
        "arguments": {"command": text},
        "cwd": "/work",
        "home_dir": "/home/user",
        "canonical": {"raw_text": text, "security_identity": model.security_identity},
    });
    let found = ask("tool_action", &input).expect("bound");
    let evaluated = ask(
        "tool_action",
        &with_evaluation(&input, &model.security_identity),
    )
    .expect("bound with evaluation");
    assert!(
        evaluated.get("error").is_none(),
        "the evaluation of the claim did not apply: {evaluated}"
    );
    if let Some(command) = found["match"].get("canonical_command") {
        assert!(
            command["redirects"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "classified without the redirect: {found}"
        );
    }
}

/// The Windows host floor runs only on Windows builds, so its rule is
/// checked directly: a compound Python launch needs review, a lone one does
/// not.
#[test]
fn windows_floor_reviews_only_a_compound_python_launch() {
    use crate::sfrs_shell_classifier::{windows_interpreter_floor, ShellClassifyInputs};
    use std::path::Path;

    let host = Host;
    let ctx = Ctx::new(&host, "/work", "/home/user");
    let (cwd, home) = (Path::new("/work"), Path::new("/home/user"));
    let floor = |text: &str| {
        let command = crate::command_model::parse_shell_command(
            text,
            Some(cwd),
            Some(home),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        );
        let inputs = ShellClassifyInputs {
            tool_name: "Bash",
            normalized_tool_name: "bash",
            command_text: text,
            cwd: Some(cwd),
            home_dir: Some(home),
            canonical_command: None,
            raw_command_text: None,
            execution_context: None,
            raw_execution_context: None,
            native_evaluation: None,
            controls: None,
            ctx: &ctx,
        };
        windows_interpreter_floor(&inputs, &command)
    };
    let found = floor("cd /work && printf data | /usr/bin/python3 -c 'print(1)'")
        .expect("a compound Python launch is floored");
    assert_eq!(
        found.reason_code.as_deref(),
        Some("interpreter_host_binding_unverified")
    );
    assert_eq!(
        found.guard_default_action.as_deref(),
        Some("require-reapproval")
    );
    assert!(floor("/usr/bin/python3 -c 'print(1)'").is_none());
    assert!(floor("cd /work && ls -la").is_none());
}

/// [`Host`] whose resident secret classifier finds nothing.
struct SecretFreeHost;

impl InspectionHost for SecretFreeHost {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn secret_content_found(&self, _: &str, _: bool) -> bool {
        false
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
}

/// A recorded `eph_safe` vector that the ported check accepts.
const EPHEMERAL_BODY_WORKFLOW: &str = r#"f="$(mktemp)"
cat > "$f" <<'EOF'
body
EOF
if grep -nE 'password' "$f"
then
  echo "found"
  exit 1
else
  cat "$f"
fi
gh pr create --title "t" --body-file "$f""#;

fn benign_github_shell(host: &dyn InspectionHost, command: &str) -> Value {
    let ctx = Ctx::new(host, "/work", "/home/user");
    evaluate(
        "benign_github_shell",
        &json!({"command_text": command}),
        &ctx,
        None,
    )
    .expect("benign_github_shell answers")
}

#[test]
fn static_ephemeral_pr_body_is_benign_github_shell() {
    assert_eq!(
        benign_github_shell(&SecretFreeHost, EPHEMERAL_BODY_WORKFLOW),
        json!(true)
    );
}

#[test]
fn ephemeral_pr_body_with_secret_or_expansion_is_not_benign() {
    assert_eq!(
        benign_github_shell(&Host, EPHEMERAL_BODY_WORKFLOW),
        json!(false)
    );
    let unquoted = EPHEMERAL_BODY_WORKFLOW.replacen("<<'EOF'", "<<EOF", 1);
    assert_eq!(
        benign_github_shell(&SecretFreeHost, &unquoted),
        json!(false)
    );
    for command in ["ls", "gh run view 1 --log", ""] {
        assert_eq!(benign_github_shell(&SecretFreeHost, command), json!(false));
    }
}

#[test]
fn benign_github_shell_requires_command_text() {
    assert_eq!(
        ask("benign_github_shell", &json!({"command_text": 3})),
        Err("native_sensitive_request_input_invalid")
    );
}

/// The artifact queries answer the same question as the plain ones and name
/// the review in one reply. Both halves have to describe the same request:
/// asking twice would let the artifact point at a path the caller no longer
/// acts on.
#[test]
fn a_read_artifact_query_returns_the_match_and_its_artifact_together() {
    let reply = ask(
        "file_read_artifact",
        &json!({
            "tool_name": "Read",
            "arguments": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/work",
            "home_dir": "/home/user",
            "harness": "claude-code",
            "config_path": "/home/user/.claude/settings.json",
            "source_scope": "project",
        }),
    )
    .expect("answered");
    let plain = ask(
        "file_read",
        &json!({
            "tool_name": "Read",
            "arguments": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/work",
            "home_dir": "/home/user",
        }),
    )
    .expect("answered");

    assert_eq!(reply["match"], plain);
    let artifact = &reply["artifact"];
    assert_eq!(artifact["artifact_type"], json!("file_read_request"));
    assert_eq!(artifact["harness"], json!("claude-code"));
    assert_eq!(artifact["source_scope"], json!("project"));
    assert_eq!(
        artifact["config_path"],
        json!("/home/user/.claude/settings.json")
    );
    let artifact_id = artifact["artifact_id"].as_str().expect("id");
    assert!(
        artifact_id.starts_with("claude-code:project:file-read:"),
        "{artifact_id}"
    );
    assert_eq!(
        artifact["metadata"]["normalized_path"],
        plain["path_match"]["path"]
    );
}

/// No sensitive request is no artifact. The reply still carries both keys so
/// the caller reads one shape either way.
#[test]
fn an_ordinary_path_yields_no_read_artifact() {
    let reply = ask(
        "file_read_artifact",
        &json!({
            "tool_name": "Read",
            "arguments": {"file_path": "/work/src/main.rs"},
            "cwd": "/work",
            "home_dir": "/home/user",
            "harness": "claude-code",
            "config_path": "/home/user/.claude/settings.json",
            "source_scope": "project",
        }),
    )
    .expect("answered");

    assert_eq!(reply, json!({"match": null, "artifact": null}));
}

/// The naming describes the call site, so a reply cannot be built without it.
/// Guessing a harness or a scope would key the review under a name no saved
/// approval uses.
#[test]
fn an_artifact_query_without_naming_is_rejected() {
    for input in [
        json!({"tool_name": "Read", "arguments": {"file_path": "~/.ssh/id_rsa"}}),
        json!({
            "tool_name": "Read",
            "arguments": {"file_path": "~/.ssh/id_rsa"},
            "harness": "",
            "config_path": "/c",
            "source_scope": "project",
        }),
    ] {
        assert_eq!(
            ask("file_read_artifact", &input),
            Err("native_sensitive_request_input_invalid"),
            "{input}"
        );
    }
}

/// A write request is keyed by its action class as well as its path, so the
/// write artifact has to come from the write builder rather than the read one.
#[test]
fn a_write_artifact_query_names_the_action_class() {
    let reply = ask(
        "file_write_artifact",
        &json!({
            "tool_name": "Write",
            "arguments": {"file_path": "~/.ssh/id_rsa", "content": "x"},
            "cwd": "/work",
            "home_dir": "/home/user",
            "protected_paths": {},
            "harness": "claude-code",
            "config_path": "/home/user/.claude/settings.json",
            "source_scope": "project",
        }),
    )
    .expect("answered");

    // The path is one `classify_path` flags, so a missing match or artifact
    // is a regression rather than a case to skip.
    let artifact = &reply["artifact"];
    assert!(!reply["match"].is_null(), "expected a write match: {reply}");
    assert!(!artifact.is_null(), "expected a write artifact: {reply}");
    assert_eq!(artifact["artifact_type"], json!("tool_action_request"));
    assert_eq!(
        artifact["metadata"]["action_class"],
        reply["match"]["action_class"]
    );
    let artifact_id = artifact["artifact_id"].as_str().expect("id");
    assert!(
        artifact_id.starts_with("claude-code:project:file-write:"),
        "{artifact_id}"
    );
}

/// A review names the file, not its whole path. Windows paths split on `\`
/// there, the way `Path(...).name` read them; elsewhere `\` is part of a name.
#[test]
fn an_artifact_name_is_the_last_path_component() {
    use crate::sfrs_requests::artifact_file_name;

    assert_eq!(artifact_file_name("/home/user/.ssh/id_rsa"), "id_rsa");
    let windows_path = "C:\\Users\\dev\\.ssh\\id_rsa";
    assert_eq!(
        artifact_file_name(windows_path),
        if cfg!(windows) {
            "id_rsa"
        } else {
            windows_path
        }
    );
}
