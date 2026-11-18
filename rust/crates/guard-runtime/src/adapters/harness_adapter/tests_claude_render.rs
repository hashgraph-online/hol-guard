//! What the Claude SessionStart hook prints and what the install screen shows
//! for the settings target, worded by the runtime.

use serde_json::{json, Map, Value};

use super::super::{dispatch, Home};
use super::{ask, settings};
use crate::harness_adapter::claude::session_start_output;
use crate::harness_adapter::claude_install_target_text;

fn target(home: &Home, workspace: Option<&std::path::Path>, env: Value) -> Value {
    let mut context = home.context(env);
    context["workspace"] = json!(workspace);
    dispatch(&json!({"harness": "claude-code", "op": "install_target", "context": context}))
        .unwrap()
}

#[test]
fn session_start_answers_the_exact_hook_output_to_print() {
    let home = Home::new();
    let mut fields = Map::new();
    fields.insert("argv".into(), json!(["/g", "/h", "/w"]));
    let answer = ask(&home, "session_start", &fields);
    let context = answer["context"].as_str().unwrap();
    assert_eq!(
        answer["output"],
        json!(format!(
            "{{\"hookSpecificOutput\":{{\"hookEventName\":\"SessionStart\",\"additionalContext\":\"{context}\"}}}}"
        ))
    );
    let parsed: Value = serde_json::from_str(answer["output"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["additionalContext"],
        json!(context)
    );
}

#[test]
fn session_start_output_escapes_like_python_json() {
    let output = session_start_output("a\"b\\c\n\u{1}\u{7f}\u{e9}\u{1f600}");
    assert_eq!(
        output,
        "{\"hookSpecificOutput\":{\"hookEventName\":\"SessionStart\",\"additionalContext\":\"a\\\"b\\\\c\\n\\u0001\\u007f\\u00e9\\ud83d\\ude00\"}}"
    );
}

#[test]
fn install_target_answers_the_panel_text_and_border_to_show() {
    let home = Home::new();
    let workspace = home.root.join("project");
    let answer = target(&home, Some(&workspace), json!({"PATH": ""}));
    assert_eq!(answer["border"], "cyan");
    let text = answer["text"].as_str().unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        format!("Writes: {} (user settings)", settings(&home).display())
    );
    assert!(lines[1].starts_with("--workspace does not install into "));
    assert_eq!(lines[2], "Claude Code reads, highest precedence first:");
    assert!(lines[3].starts_with("  - managed: "));
    assert!(lines.iter().any(|line| line.starts_with("  * user: ")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("Claude Code runs the hooks from every")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("Headless `claude -p` runs")));
    let undo = lines.iter().find(|line| line.starts_with("Undo")).unwrap();
    assert!(undo.starts_with(&format!(
        "{}: {}. Removes only Guard's hook entries",
        if cfg!(windows) {
            "Undo (PowerShell)"
        } else {
            "Undo"
        },
        answer["rollback"]["command_text"].as_str().unwrap()
    )));
    assert!(!lines.iter().any(|line| line.starts_with("Warning: ")));
}

#[test]
fn a_hook_override_turns_the_border_red_and_adds_a_warning_line() {
    let target = json!({
        "scope": "user",
        "settings_path": "/h/.claude/settings.json",
        "workspace_note": "",
        "hook_overrides": [{"message": "disableAllHooks is set in /p/.claude/settings.json"}],
    });
    assert_eq!(claude_install_target_text::border(&target), "red");
    assert_eq!(
        claude_install_target_text::lines(&target),
        "Writes: /h/.claude/settings.json (user settings)\n\
         Warning: disableAllHooks is set in /p/.claude/settings.json"
    );
    let quiet = json!({"hook_overrides": []});
    assert_eq!(claude_install_target_text::border(&quiet), "cyan");
    assert_eq!(
        claude_install_target_text::lines(&quiet),
        "Writes: None (None settings)"
    );
}

#[test]
fn a_powershell_undo_is_labelled_and_its_effect_follows_on_one_line() {
    let target = json!({
        "rollback": {"command_text": "hol-guard uninstall", "shell": "powershell", "effect": "Removes it."},
        "precedence": [{"scope": "user", "path": "/u", "guard_writes": true}, "not a layer"],
    });
    let text = claude_install_target_text::lines(&target);
    assert_eq!(
        text.lines().skip(1).collect::<Vec<_>>(),
        [
            "Claude Code reads, highest precedence first:",
            "  * user: /u",
            "Undo (PowerShell): hol-guard uninstall. Removes it.",
        ]
    );
    let bare = json!({"rollback": {"command_text": "undo", "shell": "sh"}});
    assert!(claude_install_target_text::lines(&bare).ends_with("Undo: undo."));
}
