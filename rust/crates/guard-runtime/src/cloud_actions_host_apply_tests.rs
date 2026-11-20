//! Tests for the settings-file ops: where each AI tool keeps its file, the
//! bounded read behind the preview, and the compare-and-swap write.
//!
//! The write, restore and interrupted-write cases live in the submodules.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::restoring::Restored;
use super::*;

#[path = "cloud_actions_host_apply_recovery_tests.rs"]
mod recovery;
#[path = "cloud_actions_host_apply_restore_tests.rs"]
mod restore;
#[path = "cloud_actions_host_apply_write_tests.rs"]
mod writing;

const URL: &str = "https://hol.org/api/guard/gateway/mcp";
const COMMAND: &str = "/opt/hol-guard/python";
const SERVER: &str = "hol-guard-cloud";
const TOOLS: [&str; 3] = ["claude-code", "codex", "cursor"];

const CODEX_SETTINGS: &str = "# Hand-written; keep this comment.\nmodel = \"gpt-5\"\n\n[mcp_servers.docs]\ncommand = \"docs-mcp\"\nargs = [\"--stdio\"]\n";

const JSON_SETTINGS: &str = "{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"docs\": {\n      \"command\": \"docs-mcp\",\n      \"args\": [\n        \"--stdio\"\n      ]\n    }\n  }\n}\n";

type ReadFn<'a> = Box<dyn Fn(&Path) -> Result<Option<Vec<u8>>, Failure> + 'a>;
type TemporaryFn<'a> = Box<dyn Fn(&Path, &[u8], u32) -> Result<PathBuf, Failure> + 'a>;
type MoveFn<'a> = Box<dyn Fn(&Path, &Path) -> Result<(), Failure> + 'a>;
type MovedFn<'a> = Box<dyn Fn(&Path, &Path, bool) -> Option<bool> + 'a>;

/// `Ops` that do the real work until a test swaps one step for a fault.
struct Rig<'a> {
    read: ReadFn<'a>,
    temporary: TemporaryFn<'a>,
    replace: MoveFn<'a>,
    link: MoveFn<'a>,
    moved: MovedFn<'a>,
}

impl Rig<'_> {
    fn new() -> Self {
        Self {
            read: Box::new(|path| Real.read(path)),
            temporary: Box::new(|path, payload, mode| Real.write_temporary(path, payload, mode)),
            replace: Box::new(|from, to| Real.replace(from, to)),
            link: Box::new(|from, to| Real.link(from, to)),
            moved: Box::new(|temporary, path, create| Real.moved(temporary, path, create)),
        }
    }
}

impl Ops for Rig<'_> {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, Failure> {
        (self.read)(path)
    }

    fn write_temporary(&self, path: &Path, payload: &[u8], mode: u32) -> Result<PathBuf, Failure> {
        (self.temporary)(path, payload, mode)
    }

    fn replace(&self, from: &Path, to: &Path) -> Result<(), Failure> {
        (self.replace)(from, to)
    }

    fn link(&self, from: &Path, to: &Path) -> Result<(), Failure> {
        (self.link)(from, to)
    }

    fn moved(&self, temporary: &Path, path: &Path, create: bool) -> Option<bool> {
        (self.moved)(temporary, path, create)
    }
}

fn denied() -> Failure {
    Failure::Io(io::Error::from_raw_os_error(13))
}

fn entry(tool: &str, guard_home: &str) -> Value {
    json!({
        "command": COMMAND,
        "args": ["-m", "codex_plugin_scanner.cli", "guard", "cloud-actions", "bridge", tool, "--guard-home", guard_home],
    })
}

fn settings_file(home: &Path, tool: &str) -> PathBuf {
    match tool {
        "claude-code" => home.join(".claude.json"),
        "codex" => home.join(".codex").join("config.toml"),
        _ => home.join(".cursor").join("mcp.json"),
    }
}

fn seed(home: &Path, tool: &str) -> PathBuf {
    let path = settings_file(home, tool);
    fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    let text = if tool == "codex" {
        CODEX_SETTINGS
    } else {
        JSON_SETTINGS
    };
    fs::write(&path, text).expect("seed");
    set_mode_bits(&path, 0o640);
    path
}

#[cfg(unix)]
fn set_mode_bits(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[cfg(not(unix))]
fn set_mode_bits(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn mode_bits(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o7777
}

/// What a preview reads, and what `apply` is then asked to write.
struct Preview {
    action: String,
    entry: Value,
    before_sha256: Option<String>,
    after: Vec<u8>,
}

fn preview(tool: &str, path: &Path, guard_home: &str) -> Preview {
    let entry = entry(tool, guard_home);
    let answer = plan_file_answer(PlanFileRequest {
        op: "plan_file".to_owned(),
        ai_tool: tool.to_owned(),
        path: path.to_string_lossy().into_owned(),
        entry: entry.clone(),
        url: URL.to_owned(),
    })
    .expect("plan");
    Preview {
        action: answer["action"].as_str().expect("action").to_owned(),
        entry,
        before_sha256: answer["before_sha256"].as_str().map(str::to_owned),
        after: answer["after"]
            .as_str()
            .map(|after| after.as_bytes().to_vec())
            .unwrap_or_default(),
    }
}

fn apply_with(
    ops: &dyn Ops,
    preview: &Preview,
    tool: &str,
    path: &Path,
    guard_home: &Path,
) -> Result<(), WriteError> {
    apply(
        ops,
        &ApplyPlan {
            ai_tool: tool,
            path,
            guard_home,
            entry: preview.entry.as_object().expect("entry"),
            replaced_entry: preview.action == "update",
            before_sha256: preview.before_sha256.as_deref(),
            after: &preview.after,
        },
    )
}

/// Preview and apply in one go with the real file steps.
fn configure(tool: &str, path: &Path, guard_home: &Path, address: &str) -> Preview {
    let preview = preview(tool, path, address);
    apply_with(&Real, &preview, tool, path, guard_home).expect("applied");
    preview
}

fn restore_with(ops: &dyn Ops, tool: &str, path: &Path, guard_home: &Path) -> Option<Restored> {
    restore(ops, tool, path, guard_home).expect("restored")
}

fn kept_records(guard_home: &Path, tool: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(backups_dir(guard_home, tool)) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    found.sort();
    found
}

fn kept_files(guard_home: &Path, tool: &str) -> usize {
    fs::read_dir(backups_dir(guard_home, tool)).map_or(0, Iterator::count)
}

fn strays(directory: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(directory)
        .expect("folder")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".guard-tmp"))
        .collect();
    found.sort();
    found
}

fn edit_json(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut document: Value = serde_json::from_slice(&fs::read(path).expect("read")).expect("json");
    edit(&mut document);
    let mut text = serde_json::to_string_pretty(&document).expect("render");
    text.push('\n');
    fs::write(path, text).expect("write");
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read")).expect("json")
}

fn settings_path_for(tool: &str, home: &Path, environ: Option<&[(&str, String)]>) -> Option<Value> {
    settings_path_answer(SettingsPathRequest {
        op: "settings_path".to_owned(),
        ai_tool: tool.to_owned(),
        home: home.to_string_lossy().into_owned(),
        environ: environ.map(|pairs| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect()
        }),
    })
}

#[test]
fn settings_path_follows_the_ai_tool_home_unless_home_is_given() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    let environ = [
        (
            "CODEX_HOME",
            home.join("codex-home").to_string_lossy().into_owned(),
        ),
        (
            "CLAUDE_CONFIG_DIR",
            home.join("claude-home").to_string_lossy().into_owned(),
        ),
    ];
    let path = |tool: &str, environ: Option<&[(&str, String)]>| {
        settings_path_for(tool, home, environ).expect("path")["path"]
            .as_str()
            .expect("text")
            .to_owned()
    };

    assert_eq!(
        path("codex", Some(&environ)),
        home.join("codex-home")
            .join("config.toml")
            .to_string_lossy()
    );
    assert_eq!(
        path("claude-code", Some(&environ)),
        home.join("claude-home")
            .join(".claude.json")
            .to_string_lossy()
    );
    assert_eq!(
        path("cursor", Some(&environ)),
        home.join(".cursor").join("mcp.json").to_string_lossy()
    );
    assert_eq!(
        path("codex", None),
        home.join(".codex").join("config.toml").to_string_lossy()
    );
    assert_eq!(
        path("claude-code", None),
        home.join(".claude.json").to_string_lossy()
    );
    assert!(settings_path_for("windsurf", home, Some(&environ)).is_none());
}

#[test]
fn a_blank_home_variable_is_ignored_and_a_tilde_follows_the_given_home() {
    let home = tempfile::tempdir().expect("home");
    let home = home.path();
    let blank = [("CODEX_HOME", "  \u{1c}".to_owned())];
    let tilde = [("CODEX_HOME", "~/elsewhere".to_owned())];

    assert_eq!(
        settings_path_for("codex", home, Some(&blank)).expect("path")["path"],
        json!(home.join(".codex").join("config.toml").to_string_lossy())
    );
    assert_eq!(
        settings_path_for("codex", home, Some(&tilde)).expect("path")["path"],
        json!(home.join("elsewhere").join("config.toml").to_string_lossy())
    );
}

#[test]
fn the_preview_reads_the_file_and_never_writes() {
    let home = tempfile::tempdir().expect("home");
    let path = seed(home.path(), "codex");
    let before = fs::read(&path).expect("read");

    let plan = preview("codex", &path, "/guard-home");

    assert_eq!(plan.action, "add");
    assert_eq!(plan.before_sha256, Some(sha256_hex(&before)));
    assert_ne!(plan.after, before);
    assert_eq!(fs::read(&path).expect("read"), before);
}

#[test]
fn a_missing_settings_file_previews_a_created_one() {
    let home = tempfile::tempdir().expect("home");
    let path = settings_file(home.path(), "cursor");

    let plan = preview("cursor", &path, "/guard-home");

    assert_eq!(plan.action, "create_file");
    assert_eq!(plan.before_sha256, None);
    assert!(!path.exists());
}

fn unreadable_problem(path: &Path) -> Value {
    let answer = plan_file_answer(PlanFileRequest {
        op: "plan_file".to_owned(),
        ai_tool: "cursor".to_owned(),
        path: path.to_string_lossy().into_owned(),
        entry: entry("cursor", "/guard-home"),
        url: URL.to_owned(),
    })
    .expect("plan");
    assert_eq!(answer["action"], "unreadable");
    assert_eq!(answer["after"], Value::Null);
    assert_eq!(answer["before_sha256"], Value::Null);
    answer["problem"].clone()
}

#[test]
fn a_settings_path_that_is_a_folder_is_unreadable() {
    let home = tempfile::tempdir().expect("home");
    let path = settings_file(home.path(), "cursor");
    fs::create_dir_all(&path).expect("folder");

    assert_eq!(
        unreadable_problem(&path),
        json!(format!("{} is not a file.", path.display()))
    );
}

#[test]
fn a_file_that_is_not_utf8_text_is_unreadable() {
    let home = tempfile::tempdir().expect("home");
    let path = settings_file(home.path(), "cursor");
    fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    fs::write(&path, [0xff, 0xfe, 0x00]).expect("write");

    assert_eq!(
        unreadable_problem(&path),
        json!("The settings file is not UTF-8 text.")
    );
}

#[test]
fn a_file_over_the_size_limit_is_unreadable() {
    let home = tempfile::tempdir().expect("home");
    let path = settings_file(home.path(), "cursor");
    fs::create_dir_all(path.parent().expect("parent")).expect("folder");
    let file = fs::File::create(&path).expect("create");
    file.set_len(files::MAX_SETTINGS_BYTES + 1).expect("grow");

    assert_eq!(
        unreadable_problem(&path),
        json!(format!("{} is too large to change safely.", path.display()))
    );
}

#[test]
fn a_relative_path_is_not_a_request_the_op_answers() {
    let answer = plan_file_answer(PlanFileRequest {
        op: "plan_file".to_owned(),
        ai_tool: "cursor".to_owned(),
        path: ".cursor/mcp.json".to_owned(),
        entry: entry("cursor", "/guard-home"),
        url: URL.to_owned(),
    });

    assert!(answer.is_none());
    assert!(answer_op("apply", &json!({"ai_tool": "cursor"})).is_none());
}

fn answer_op(op: &str, fields: &Value) -> Option<Value> {
    let mut request = fields.clone();
    request["op"] = json!(op);
    answer(op, request)
}

#[test]
fn the_ops_answer_through_one_entry_point() {
    let home = tempfile::tempdir().expect("home");
    let guard_home = home.path().join("guard");
    let path = seed(home.path(), "codex");
    let plan = preview("codex", &path, "/guard-home");

    let applied = answer_op(
        "apply",
        &json!({
            "ai_tool": "codex",
            "path": path.to_string_lossy(),
            "guard_home": guard_home.to_string_lossy(),
            "entry": plan.entry,
            "action": plan.action,
            "before_sha256": plan.before_sha256,
            "after": String::from_utf8(plan.after.clone()).expect("text"),
        }),
    );

    assert_eq!(applied, Some(json!({"ok": true})));
    assert_eq!(fs::read(&path).expect("read"), plan.after);
    let restored = answer_op(
        "restore",
        &json!({
            "ai_tool": "codex",
            "path": path.to_string_lossy(),
            "guard_home": guard_home.to_string_lossy(),
        }),
    );
    assert_eq!(
        restored,
        Some(json!({"restored": {"removed_file": false, "scope": "file", "entry_removed": true}}))
    );
    assert_eq!(fs::read_to_string(&path).expect("read"), CODEX_SETTINGS);
    assert!(answer_op("unknown", &json!({})).is_none());
    assert!(answer_op("apply", &json!({"ai_tool": "codex", "extra": 1})).is_none());
}
