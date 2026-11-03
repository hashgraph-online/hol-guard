use serde_json::{json, Value};

use super::{candidates, dispatch};

fn args(command_text: &str, cwd: &str) -> Value {
    json!({
        "command_text": command_text,
        "cwd": cwd,
        "home_dir": cwd,
        "user_home": cwd,
        "env": {},
        "budget_ms": 2000,
    })
}

fn refusal(command_text: &str) -> (String, String) {
    let answer = dispatch(&args(command_text, "/nonexistent-recognize-cwd")).expect("answer");
    assert_eq!(answer["identity"], Value::Null);
    let text = |key: &str| answer[key].as_str().expect(key).to_owned();
    (text("error_code"), text("message"))
}

#[test]
fn an_empty_paste_asks_for_a_command() {
    let (code, message) = refusal(" \t\n");
    assert_eq!(code, "missing_command");
    assert_eq!(message, "Paste a command or a path to the tool.");
}

#[test]
fn a_common_tool_is_refused_with_its_copy() {
    assert_eq!(
        refusal("rg pattern"),
        (
            "common_shell_utility".to_owned(),
            "rg is a common search tool, not a custom extension.".to_owned()
        )
    );
    assert_eq!(refusal("whoami").0, "common_shell_utility");
}

#[test]
fn guard_itself_is_reserved() {
    assert_eq!(refusal("hol-guard status").0, "reserved_tool");
}

#[test]
fn an_unknown_pipeline_is_called_compound() {
    let (code, _) = refusal("internal-deploy run | tee out");
    assert_eq!(code, "compound_command");
    let (code, message) = refusal("internal-deploy run");
    assert_eq!(code, "unrecognized_command");
    assert!(message.starts_with("Guard could not turn that into one tool. Paste a single command,"));
}

#[test]
fn a_missing_path_is_only_the_paste() {
    assert_eq!(
        candidates(
            "~/bin/tool --help",
            "/nonexistent-recognize-cwd",
            "/home/op"
        ),
        vec!["/home/op/bin/tool --help".to_owned()]
    );
}

#[cfg(unix)]
#[test]
fn a_file_is_launched_the_way_its_suffix_implies() {
    let root = std::env::temp_dir().join(format!("lcr-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    std::fs::write(root.join("Tool.PY"), "print(1)\n").unwrap();
    std::fs::write(root.join("my tool"), "#!/bin/sh\n").unwrap();
    let cwd = root.to_str().unwrap();
    let found = candidates("Tool.PY", cwd, "/home/op");
    let found_spaced = candidates("my tool", cwd, "/home/op");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        found,
        vec!["Tool.PY".to_owned(), format!("python3 {cwd}/Tool.PY")]
    );
    assert_eq!(
        found_spaced,
        vec!["my tool".to_owned(), format!("'{cwd}/my tool'")]
    );
}

#[test]
fn the_candidates_answer_carries_only_spellings() {
    let mut request = args("~/x", "/nonexistent-recognize-cwd");
    request["answer"] = json!("candidates");
    assert_eq!(
        dispatch(&request).expect("answer"),
        json!({"candidates": ["/nonexistent-recognize-cwd/x"]})
    );
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(dispatch(&json!([])).is_err());
    assert!(dispatch(&json!({})).is_err());
    let mut extra = args("x", "/");
    extra["shell"] = json!("bash");
    assert!(dispatch(&extra).is_err());
    let mut typed = args("x", "/");
    typed["budget_ms"] = json!("2000");
    assert!(dispatch(&typed).is_err());
    let mut mode = args("x", "/");
    mode["answer"] = json!("everything");
    assert!(dispatch(&mode).is_err());
}
