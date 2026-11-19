use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::dispatch;
use super::super::publication_lean::config_path;
use super::{first_ask_due, recorded, Record, TEXT};

const KEY: &str = "developer_instructions";
const USER_CONFIG: &str = "# my Codex settings
model = \"gpt-6-luna\"  # keep this

[features]
hooks = true
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

    fn ask(&self, action: &str) -> Value {
        let answer = dispatch(&json!({
            "op": "publication_short_replies",
            "home": self.guard().to_string_lossy(),
            "home_dir": self.home().to_string_lossy(),
            "codex_home": Value::Null,
            "action": action,
        }))
        .unwrap();
        assert!(answer.get("error").is_none(), "{answer}");
        answer["value"].clone()
    }
}

fn instructions(path: &Path) -> Option<String> {
    let table: toml::Table = fs::read_to_string(path).unwrap().parse().unwrap();
    table
        .get(KEY)
        .and_then(|value| value.as_str().map(str::to_owned))
}

#[test]
fn turning_cigar_on_adds_short_replies_and_keeps_the_users_file() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);

    let state = homes.ask("ensure");

    assert_eq!(state["state"], "on");
    assert_eq!(state["schema"], "guard-codex-short-replies.v1");
    assert_eq!(instructions(&path).as_deref(), Some(TEXT));
    let text = fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("model = \"gpt-6-luna\"  # keep this"),
        "{text}"
    );
    assert!(text.contains("[features]\nhooks = true"), "{text}");
    assert_eq!(
        recorded(&homes.guard(), &path),
        Record::Wrote(TEXT.to_owned())
    );
    assert_eq!(homes.ask("status")["state"], "on");
    assert_eq!(homes.ask("ensure")["state"], "on");
}

#[test]
fn instructions_the_user_wrote_are_left_alone() {
    let homes = Homes::new();
    // A root key must come before the first table, or TOML reads it as part of that table.
    let mine = format!("{KEY} = \"Explain every step.\"\n{USER_CONFIG}");
    let path = homes.write_config(&mine);

    assert_eq!(homes.ask("ensure")["state"], "yours");
    assert_eq!(homes.ask("enable")["state"], "yours");
    assert_eq!(fs::read_to_string(&path).unwrap(), mine);

    assert_eq!(homes.ask("disable")["state"], "yours");
    assert_eq!(fs::read_to_string(&path).unwrap(), mine);
}

#[test]
fn turning_it_off_removes_only_guards_text_and_stays_off() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    homes.ask("ensure");

    let state = homes.ask("disable");

    assert_eq!(state["state"], "off");
    assert_eq!(instructions(&path), None);
    assert_eq!(fs::read_to_string(&path).unwrap(), USER_CONFIG);
    // Turning CIGAR on again does not bring it back.
    assert_eq!(homes.ask("ensure")["state"], "off");
    assert_eq!(instructions(&path), None);
    // Turning it on by hand does.
    assert_eq!(homes.ask("enable")["state"], "on");
    assert_eq!(instructions(&path).as_deref(), Some(TEXT));
}

#[test]
fn no_codex_folder_means_nothing_is_written() {
    let homes = Homes::new();

    assert_eq!(homes.ask("ensure")["state"], "not_set");
    assert!(!homes.config().exists());
    assert!(!homes.guard().join("codex-short-replies.json").exists());
}

#[test]
fn text_an_earlier_guard_wrote_is_updated() {
    let homes = Homes::new();
    let path = homes.write_config(&format!("{KEY} = \"Be brief.\"\n"));
    fs::create_dir_all(homes.guard()).unwrap();
    let key = serde_json::to_string(&path.to_string_lossy()).unwrap();
    fs::write(
        homes.guard().join("codex-short-replies.json"),
        format!("{{\"configs\": {{{key}: \"Be brief.\"}}}}\n"),
    )
    .unwrap();

    assert_eq!(homes.ask("ensure")["state"], "on");
    assert_eq!(instructions(&path).as_deref(), Some(TEXT));
}

#[test]
fn deleting_guards_line_by_hand_counts_as_turning_it_off() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    homes.ask("ensure");
    fs::write(&path, USER_CONFIG).unwrap();

    assert_eq!(homes.ask("ensure")["state"], "off");
    assert_eq!(fs::read_to_string(&path).unwrap(), USER_CONFIG);
    assert_eq!(recorded(&homes.guard(), &path), Record::Off);
}

#[test]
fn only_a_guard_home_in_the_home_folder_asks_and_only_once() {
    let homes = Homes::new();
    let path = homes.write_config(USER_CONFIG);
    fs::create_dir_all(homes.guard()).unwrap();
    // The Guard home sits in `root`, so `root` plays the user's home folder.
    assert!(first_ask_due(&homes.guard(), Some(&homes.root)));
    assert!(!first_ask_due(&homes.guard(), Some(&homes.home())));
    assert!(!first_ask_due(&homes.guard(), None));

    homes.ask("ensure");
    assert_eq!(
        recorded(&homes.guard(), &path),
        Record::Wrote(TEXT.to_owned())
    );
    assert!(!first_ask_due(&homes.guard(), Some(&homes.root)));
}

#[test]
fn guards_text_written_by_someone_else_is_not_claimed() {
    let homes = Homes::new();
    let config = format!("developer_instructions = {TEXT:?}\n");
    let path = homes.write_config(&config);
    assert_eq!(homes.ask("enable")["state"], "yours");
    assert_eq!(recorded(&homes.guard(), &path), Record::None);
    homes.ask("disable");
    assert_eq!(instructions(&path).as_deref(), Some(TEXT));
}

#[test]
fn an_unreadable_record_never_asks_again() {
    let homes = Homes::new();
    homes.write_config(USER_CONFIG);
    fs::create_dir_all(homes.guard()).unwrap();
    fs::write(homes.guard().join("codex-short-replies.json"), b"{not json").unwrap();
    assert!(!first_ask_due(&homes.guard(), Some(&homes.root)));
}
