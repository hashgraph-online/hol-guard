use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::dispatch;
use super::{check_limit, config_path, record_text, records};

const SIZE: i64 = 100_000;
const KEY: &str = "model_auto_compact_token_limit";
const USER_CONFIG: &str = "# my Codex settings
model = \"gpt-6-luna\"  # keep this

[features]
hooks = true

[projects.\"/work/app\"]
trust_level = \"trusted\"
";

struct Homes {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Homes {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        Self { _dir: dir, root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn guard(&self) -> PathBuf {
        self.root.join("guard")
    }

    fn config(&self) -> PathBuf {
        config_path(&self.home(), None)
    }

    fn write_config(&self, text: &str) -> PathBuf {
        let path = self.config();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        path
    }

    fn ask(&self, action: &str, codex_home: Option<&Path>, limit: Value) -> Result<Value, Value> {
        let answer = dispatch(&json!({
            "op": "publication_lean_sessions",
            "home": self.guard().to_string_lossy(),
            "home_dir": self.home().to_string_lossy(),
            "codex_home": codex_home.map(|path| path.to_string_lossy().into_owned()),
            "action": action,
            "limit": limit,
        }))
        .unwrap();
        match answer.get("error") {
            Some(error) => Err(error.clone()),
            None => Ok(answer["value"].clone()),
        }
    }

    fn enable(&self, codex_home: Option<&Path>, limit: i64) -> Result<Value, Value> {
        self.ask("enable", codex_home, json!(limit))
    }

    fn disable(&self, codex_home: Option<&Path>) -> Result<Value, Value> {
        self.ask("disable", codex_home, Value::Null)
    }

    fn status(&self, codex_home: Option<&Path>) -> Value {
        self.ask("status", codex_home, Value::Null).unwrap()
    }

    fn recorded(&self, path: &Path) -> Option<Value> {
        records(&self.guard())
            .get(&path.to_string_lossy().into_owned())
            .cloned()
    }

    fn record(&self, path: &Path, value: i64) {
        let mut configs = Map::new();
        configs.insert(path.to_string_lossy().into_owned(), json!(value));
        fs::create_dir_all(self.guard()).unwrap();
        fs::write(
            self.guard().join("codex-lean-sessions.json"),
            record_text(&configs),
        )
        .unwrap();
    }
}

fn parsed(path: &Path) -> toml::Table {
    fs::read_to_string(path).unwrap().parse().unwrap()
}

fn limit_in(path: &Path) -> Option<i64> {
    parsed(path).get(KEY).and_then(toml::Value::as_integer)
}

#[test]
fn on_adds_the_limit_and_keeps_the_users_file() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    let state = homes.enable(None, SIZE).unwrap();
    assert_eq!(state["state"], json!("on"));
    assert_eq!(state["limit"], json!(SIZE));
    assert_eq!(state["schema"], json!("guard-codex-lean-sessions.v1"));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("# my Codex settings"));
    assert!(text.contains("model = \"gpt-6-luna\"  # keep this"));
    assert_eq!(limit_in(&path), Some(SIZE));
    let table = parsed(&path);
    assert_eq!(table["features"]["hooks"].as_bool(), Some(true));
    assert_eq!(
        table["projects"]["/work/app"]["trust_level"].as_str(),
        Some("trusted")
    );
    assert_eq!(homes.status(None)["state"], json!("on"));
}

#[test]
fn off_removes_only_what_guard_wrote() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    homes.enable(None, SIZE).unwrap();
    assert_eq!(homes.disable(None).unwrap()["state"], json!("off"));
    assert_eq!(parsed(&path), USER_CONFIG.parse::<toml::Table>().unwrap());
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("# my Codex settings"));
    assert!(!homes.guard().join("codex-lean-sessions.json").exists());
}

#[test]
fn on_without_a_config_creates_one() {
    let homes = Homes::new();
    assert_eq!(homes.status(None)["state"], json!("off"));
    assert_eq!(homes.status(None)["limit"], Value::Null);
    homes.enable(None, SIZE).unwrap();
    let table = parsed(&homes.config());
    assert_eq!(table.len(), 1);
    assert_eq!(limit_in(&homes.config()), Some(SIZE));
}

#[test]
fn a_limit_the_user_set_is_never_changed() {
    let homes = Homes::new();
    let path = homes.write_config(&format!("{KEY} = 80000\n{USER_CONFIG}"));
    let before = fs::read(&path).unwrap();
    assert_eq!(homes.enable(None, SIZE).unwrap()["state"], json!("yours"));
    assert_eq!(homes.disable(None).unwrap()["state"], json!("yours"));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn off_leaves_a_limit_the_user_changed_after_guard_set_it() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    homes.enable(None, SIZE).unwrap();
    let changed = fs::read_to_string(&path)
        .unwrap()
        .replace(&SIZE.to_string(), "45000");
    fs::write(&path, changed).unwrap();
    let state = homes.disable(None).unwrap();
    assert_eq!(state["state"], json!("yours"));
    assert_eq!(state["limit"], json!(45000));
    assert_eq!(limit_in(&path), Some(45000));
    assert_eq!(homes.status(None)["state"], json!("yours"));
}

#[test]
fn a_config_guard_cannot_read_is_left_alone() {
    let homes = Homes::new();
    let path = homes.write_config("model = \n[broken\n");
    let before = fs::read(&path).unwrap();
    let answer = homes.enable(None, SIZE).unwrap();
    assert_eq!(answer, json!({"error": "codex_config_unreadable"}));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(homes.recorded(&path), None);
}

#[test]
fn a_config_that_is_not_a_file_is_refused() {
    let homes = Homes::new();
    fs::create_dir_all(homes.config()).unwrap();
    assert_eq!(
        homes.enable(None, SIZE).unwrap(),
        json!({"error": "codex_config_not_regular_file"})
    );
}

#[test]
fn codex_home_from_the_environment_is_the_config_changed() {
    let homes = Homes::new();
    let codex_home = homes.root.join("codex-home");
    let state = homes.enable(Some(&codex_home), SIZE).unwrap();
    let path = codex_home.join("config.toml");
    assert_eq!(state["config_path"], json!(path.to_string_lossy()));
    assert_eq!(limit_in(&path), Some(SIZE));
    assert!(!homes.config().exists());
    assert_eq!(
        homes.disable(Some(&codex_home)).unwrap()["state"],
        json!("off")
    );
}

#[test]
fn guards_value_in_one_codex_home_is_not_claimed_in_another() {
    let homes = Homes::new();
    let codex_home = homes.root.join("codex-home");
    homes.enable(Some(&codex_home), SIZE).unwrap();
    let path = homes.write_config(&format!("{KEY} = {SIZE}\n"));
    assert_eq!(homes.status(None)["state"], json!("yours"));
    assert_eq!(homes.disable(None).unwrap()["state"], json!("yours"));
    assert_eq!(limit_in(&path), Some(SIZE));
    assert_eq!(homes.status(Some(&codex_home))["state"], json!("on"));
    assert_eq!(
        homes.disable(Some(&codex_home)).unwrap()["state"],
        json!("off")
    );
}

#[cfg(unix)]
#[test]
fn a_failed_config_write_leaves_no_ownership_record() {
    use std::os::unix::fs::PermissionsExt;
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    let codex = path.parent().unwrap().to_path_buf();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o500)).unwrap();
    let failed = homes.enable(None, SIZE);
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err());
    assert_eq!(homes.recorded(&path), None);
    assert_eq!(fs::read_to_string(&path).unwrap(), USER_CONFIG);
}

#[cfg(unix)]
#[test]
fn a_failed_record_removal_puts_the_config_back() {
    use std::os::unix::fs::PermissionsExt;
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    homes.enable(None, SIZE).unwrap();
    let turned_on = fs::read_to_string(&path).unwrap();
    fs::set_permissions(homes.guard(), fs::Permissions::from_mode(0o500)).unwrap();
    let failed = homes.disable(None);
    fs::set_permissions(homes.guard(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), turned_on);
    assert_eq!(homes.status(None)["state"], json!("on"));
}

#[test]
fn limits_outside_the_range_are_refused_before_any_write() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    for (limit, code) in [
        (Value::Null, "codex_lean_limit_required"),
        (json!(9_999), "codex_lean_limit_invalid"),
        (json!(10_000_001), "codex_lean_limit_invalid"),
        (json!(true), "codex_lean_limit_invalid"),
        (json!("50000"), "codex_lean_limit_invalid"),
        (json!(50_000.0), "codex_lean_limit_invalid"),
    ] {
        let answer = homes.ask("enable", None, limit.clone()).unwrap();
        assert_eq!(answer, json!({ "error": code }), "{limit}");
        assert!(check_limit(Some(&limit)).is_err());
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), USER_CONFIG);
    assert_eq!(homes.recorded(&path), None);
    assert_eq!(homes.ask("check", None, json!(SIZE)).unwrap(), json!(SIZE));
}

#[test]
fn a_limit_an_earlier_guard_wrote_still_turns_off() {
    let homes = Homes::new();
    let path = homes.write_config(&format!("{KEY} = 30000\n{USER_CONFIG}"));
    homes.record(&path, 30_000);
    let status = homes.status(None);
    assert_eq!(status["state"], json!("on"));
    assert_eq!(status["limit"], json!(30_000));
    assert_eq!(homes.disable(None).unwrap()["state"], json!("off"));
    assert_eq!(parsed(&path), USER_CONFIG.parse::<toml::Table>().unwrap());
}

#[test]
fn on_with_a_new_size_replaces_the_size_guard_wrote() {
    let homes = Homes::new();
    let path = homes.write_config(&format!("{KEY} = 30000\n{USER_CONFIG}"));
    homes.record(&path, 30_000);
    assert_eq!(homes.enable(None, SIZE).unwrap()["limit"], json!(SIZE));
    assert_eq!(limit_in(&path), Some(SIZE));
    assert_eq!(homes.recorded(&path), Some(json!(SIZE)));
    assert_eq!(homes.status(None)["state"], json!("on"));
}

#[test]
fn on_with_a_new_size_leaves_a_size_the_user_set() {
    let homes = Homes::new();
    let path = homes.write_config(&format!("{KEY} = 50000\n{USER_CONFIG}"));
    let state = homes.enable(None, SIZE).unwrap();
    assert_eq!(state["state"], json!("yours"));
    assert_eq!(state["limit"], json!(50_000));
    assert_eq!(homes.recorded(&path), None);
}

#[test]
fn record_file_is_sorted_python_json_with_ascii_escapes() {
    let mut configs = Map::new();
    configs.insert("/b/é".to_owned(), json!(2));
    configs.insert("/a".to_owned(), json!(1));
    assert_eq!(
        record_text(&configs),
        "{\"configs\": {\"/a\": 1, \"/b/\\u00e9\": 2}}\n"
    );
}

#[test]
fn malformed_records_read_as_none() {
    let homes = Homes::new();
    fs::create_dir_all(homes.guard()).unwrap();
    let record = homes.guard().join("codex-lean-sessions.json");
    for text in ["not json", "[1]", "{\"configs\": []}"] {
        fs::write(&record, text).unwrap();
        assert!(records(&homes.guard()).is_empty(), "{text}");
    }
    fs::write(
        &record,
        "{\"configs\": {\"/a\": 1, \"/b\": true, \"/c\": 1.5}}",
    )
    .unwrap();
    let kept = records(&homes.guard());
    assert_eq!(kept.len(), 1);
    assert_eq!(kept["/a"], json!(1));
}

#[test]
fn codex_home_expands_the_users_home() {
    let home = Path::new("/u");
    assert_eq!(
        config_path(home, Some(" ~/c ")),
        PathBuf::from("/u/c/config.toml")
    );
    assert_eq!(
        config_path(home, Some("  ")),
        PathBuf::from("/u/.codex/config.toml")
    );
    assert_eq!(
        config_path(home, None),
        PathBuf::from("/u/.codex/config.toml")
    );
}
