//! What `hol-guard update` asks the native runtime for: the old bounded hook
//! clients, Grok hook currentness and the OpenCode refresh.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::dispatch;
use super::{after, caller, shim, Home};

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn script(home: &Home, harness: &str) -> PathBuf {
    home.guard()
        .join("managed")
        .join("bounded-hooks")
        .join(format!("{harness}.py"))
}

fn listed(home: &Home) -> Vec<(String, String)> {
    let answer = home.ask("zcode", "bounded_hook_scripts", json!({}));
    answer["scripts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["harness"].as_str().unwrap().to_owned(),
                item["display_name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn bounded_scripts_lists_each_old_client_in_the_update_order() {
    let home = Home::new();
    assert!(listed(&home).is_empty());
    write(&script(&home, "muse"), "# old\n");
    write(&script(&home, "zcode"), "# old\n");
    write(&script(&home, "openclaw"), "# old\n");
    // Grok and unknown names are not bounded clients.
    write(&script(&home, "grok"), "# old\n");
    assert_eq!(
        listed(&home),
        [
            ("zcode".to_owned(), "ZCode".to_owned()),
            ("openclaw".to_owned(), "OpenClaw".to_owned()),
            ("muse".to_owned(), "Muse".to_owned()),
        ]
    );
}

#[test]
fn bounded_scripts_skips_a_directory_where_the_client_would_be() {
    let home = Home::new();
    fs::create_dir_all(script(&home, "devin")).unwrap();
    assert!(listed(&home).is_empty());
}

#[cfg(unix)]
#[test]
fn bounded_scripts_skips_a_symlinked_client() {
    let home = Home::new();
    let target = home.root.join("elsewhere.py");
    write(&target, "# not ours\n");
    fs::create_dir_all(script(&home, "kimi").parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, script(&home, "kimi")).unwrap();
    write(&script(&home, "hermes"), "# old\n");
    assert_eq!(listed(&home), [("hermes".to_owned(), "Hermes".to_owned())]);
}

#[cfg(unix)]
#[test]
fn bounded_scripts_skips_a_client_below_a_symlinked_directory() {
    let home = Home::new();
    let real = home.root.join("real-hooks");
    write(&real.join("copilot.py"), "# not ours\n");
    fs::create_dir_all(home.guard().join("managed")).unwrap();
    std::os::unix::fs::symlink(&real, home.guard().join("managed").join("bounded-hooks")).unwrap();
    assert!(listed(&home).is_empty());
}

#[test]
fn remove_bounded_script_deletes_only_the_named_client() {
    let home = Home::new();
    write(&script(&home, "devin"), "# old\n");
    write(&script(&home, "kimi"), "# old\n");
    let answer = home.ask(
        "zcode",
        "remove_bounded_hook_script",
        json!({"harness": "devin"}),
    );
    assert_eq!(answer, json!({"removed": true}));
    assert!(!script(&home, "devin").exists());
    assert!(script(&home, "kimi").exists());
}

#[test]
fn remove_bounded_script_is_quiet_when_the_client_is_gone() {
    let home = Home::new();
    let answer = home.ask(
        "zcode",
        "remove_bounded_hook_script",
        json!({"harness": "devin"}),
    );
    assert_eq!(answer, json!({"removed": true}));
}

#[test]
fn remove_bounded_script_reports_what_it_cannot_remove() {
    let home = Home::new();
    fs::create_dir_all(script(&home, "muse")).unwrap();
    let answer = home.ask(
        "zcode",
        "remove_bounded_hook_script",
        json!({"harness": "muse"}),
    );
    let message = answer["os_error"].as_str().unwrap();
    assert!(message.contains("muse.py"), "{answer}");
    assert!(message.starts_with('['), "{answer}");
}

#[test]
fn remove_bounded_script_refuses_a_harness_with_no_old_client() {
    let home = Home::new();
    write(&script(&home, "grok"), "# not ours\n");
    let request = json!({
        "harness": "grok",
        "op": "remove_bounded_hook_script",
        "context": home.context(json!({"PATH": ""})),
    });
    assert!(dispatch(&request).is_err());
    assert!(script(&home, "grok").exists());
}

/// A Grok install with both hook files written, and the hook files' paths.
fn grok_installed(home: &Home) -> (PathBuf, PathBuf) {
    let spec = home.ask("grok", "hook_spec", json!({}));
    let installed = home.ask(
        "grok",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": spec["hook_argv"]}),
    );
    let mut pretool = None;
    let mut prompt = None;
    for file in installed["files"].as_array().unwrap() {
        if file["after"].is_null() {
            continue;
        }
        let path = PathBuf::from(file["path"].as_str().unwrap());
        write(&path, &after(file));
        if path.ends_with("hol-guard-pretooluse.json") {
            pretool = Some(path);
        } else if path.ends_with("hol-guard-prompt.json") {
            prompt = Some(path);
        }
    }
    (pretool.unwrap(), prompt.unwrap())
}

fn grok_current(home: &Home) -> Value {
    home.ask("grok", "hooks_current", json!({}))["current"].clone()
}

fn edit(path: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(path).unwrap();
    assert!(text.contains(from), "{from} missing from {text}");
    fs::write(path, text.replace(from, to)).unwrap();
}

#[test]
fn grok_hooks_are_current_right_after_an_install() {
    let home = Home::new();
    assert_eq!(grok_current(&home), json!(false));
    grok_installed(&home);
    assert_eq!(grok_current(&home), json!(true));
}

#[test]
fn grok_hooks_with_another_timeout_are_not_current() {
    let home = Home::new();
    let (pretool, _) = grok_installed(&home);
    edit(&pretool, "\"timeout\": 90", "\"timeout\": 30");
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_hooks_with_a_float_timeout_are_not_current() {
    let home = Home::new();
    let (pretool, _) = grok_installed(&home);
    edit(&pretool, "\"timeout\": 90", "\"timeout\": 90.0");
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_hooks_naming_another_command_are_not_current() {
    let home = Home::new();
    let (pretool, _) = grok_installed(&home);
    edit(&pretool, "/py", "/old-python");
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_hooks_missing_the_prompt_file_are_not_current() {
    let home = Home::new();
    let (_, prompt) = grok_installed(&home);
    fs::remove_file(&prompt).unwrap();
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_hooks_missing_the_pretool_file_are_not_current() {
    let home = Home::new();
    let (pretool, _) = grok_installed(&home);
    fs::remove_file(&pretool).unwrap();
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_hooks_in_unparseable_files_are_not_current() {
    let home = Home::new();
    let (pretool, prompt) = grok_installed(&home);
    fs::write(&prompt, "{oops").unwrap();
    assert_eq!(grok_current(&home), json!(false));
    fs::write(&pretool, "{oops").unwrap();
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_prompt_hooks_that_lost_an_event_are_not_current() {
    let home = Home::new();
    let (_, prompt) = grok_installed(&home);
    fs::write(&prompt, "{\"hooks\": {}}").unwrap();
    assert_eq!(grok_current(&home), json!(false));
    fs::write(&prompt, "[]").unwrap();
    assert_eq!(grok_current(&home), json!(false));
}

#[test]
fn grok_prompt_hooks_keep_the_users_own_groups() {
    let home = Home::new();
    let (_, prompt) = grok_installed(&home);
    let mut payload: Value = serde_json::from_str(&fs::read_to_string(&prompt).unwrap()).unwrap();
    let events = payload["hooks"].as_object_mut().unwrap();
    for groups in events.values_mut() {
        groups.as_array_mut().unwrap().insert(
            0,
            json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}),
        );
    }
    events.insert("Other".to_owned(), json!([]));
    fs::write(&prompt, serde_json::to_string(&payload).unwrap()).unwrap();
    assert_eq!(grok_current(&home), json!(true));
}

#[test]
fn grok_hooks_in_a_file_that_is_not_utf8_are_a_refusal() {
    let home = Home::new();
    let (pretool, _) = grok_installed(&home);
    fs::write(&pretool, [0x7b, 0xff, 0x7d]).unwrap();
    let answer = home.ask("grok", "hooks_current", json!({}));
    assert!(
        answer["refusal"].as_str().unwrap().contains("utf-8"),
        "{answer}"
    );
}

pub(super) fn plugin() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../testdata/opencode/plugin_render_vectors.json"
    ))
    .unwrap();
    let mut args = vectors["cases"][0]["args"].clone();
    args.as_object_mut().unwrap().remove("native_bridge_argv");
    args
}

fn opencode_refresh(home: &Home) -> Value {
    home.ask("opencode", "update_refresh", json!({"plugin": plugin()}))
}

pub(super) fn plugin_paths(home: &Home) -> Vec<PathBuf> {
    let plan = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}));
    plan["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| PathBuf::from(path.as_str().unwrap()))
        .collect()
}

#[test]
fn opencode_update_rewrites_a_stale_plugin_in_both_places() {
    let home = Home::new();
    let paths = plugin_paths(&home);
    assert_eq!(paths.len(), 2);
    for path in &paths {
        write(path, "// stale\n");
    }
    let answer = opencode_refresh(&home);
    assert_eq!(
        answer["note"],
        "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."
    );
    let source = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}))["source"]
        .as_str()
        .unwrap()
        .to_owned();
    for path in &paths {
        assert_eq!(fs::read_to_string(path).unwrap(), source);
    }
    // The second run finds both copies current and has nothing to say.
    assert_eq!(opencode_refresh(&home)["note"], Value::Null);
}

#[test]
fn opencode_update_creates_a_missing_plugin() {
    let home = Home::new();
    let answer = opencode_refresh(&home);
    assert!(answer["note"]
        .as_str()
        .unwrap()
        .starts_with("Refreshed the OpenCode pretool plugin"));
    for path in plugin_paths(&home) {
        assert!(path.is_file(), "{}", path.display());
    }
}

#[test]
fn opencode_update_reports_a_config_it_could_not_refresh_before_the_plugin() {
    let home = Home::new();
    write(&home.home().join(".config/opencode/opencode.json"), "{oops");
    let answer = opencode_refresh(&home);
    let note = answer["note"].as_str().unwrap();
    assert!(
        note.starts_with("Could not refresh OpenCode MCP companion launchers in every config: "),
        "{note}"
    );
    assert!(
        note.ends_with(
            " Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."
        ),
        "{note}"
    );
}

#[test]
fn opencode_update_keeps_a_config_warning_when_the_plugin_is_current() {
    let home = Home::new();
    for path in plugin_paths(&home) {
        let plan = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}));
        write(&path, plan["source"].as_str().unwrap());
    }
    write(&home.home().join(".config/opencode/opencode.json"), "{oops");
    let answer = opencode_refresh(&home);
    let note = answer["note"].as_str().unwrap();
    assert!(note.starts_with("Could not refresh OpenCode MCP companion launchers"));
    assert!(!note.contains("pretool plugin"), "{note}");
}

#[test]
fn opencode_update_without_a_native_runtime_says_it_could_not_inspect_the_plugin() {
    let home = Home::new();
    let mut stamp = caller(false);
    stamp["native_runtime"] = Value::Null;
    let answer = home.ask(
        "opencode",
        "update_refresh",
        json!({"plugin": plugin(), "caller": stamp}),
    );
    let note = answer["note"].as_str().unwrap();
    assert!(
        note.starts_with("Could not inspect OpenCode pretool plugin during update: "),
        "{note}"
    );
    assert!(note.contains("hol-guard repair"), "{note}");
    for path in plugin_paths(&home) {
        assert!(!path.exists());
    }
}

#[cfg(unix)]
#[test]
fn opencode_update_says_when_it_cannot_write_the_plugin() {
    let home = Home::new();
    use std::os::unix::fs::PermissionsExt;

    let paths = plugin_paths(&home);
    // A stale plugin the update can read but not overwrite.
    write(&paths[0], "// stale plugin\n");
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o444)).unwrap();
    let answer = opencode_refresh(&home);
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o644)).unwrap();
    let note = answer["note"].as_str().unwrap();
    assert!(
        note.starts_with("Could not refresh OpenCode pretool plugin during update: ["),
        "{note}"
    );
}
