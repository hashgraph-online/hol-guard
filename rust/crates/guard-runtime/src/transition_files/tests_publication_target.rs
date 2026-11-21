use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "publication-target-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(root.join("home/.codex")).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn ask(&self) -> Result<Value, String> {
        dispatch(&json!({
            "op": "publication_target",
            "home": self.0.join("guard").to_string_lossy(),
            "config": self.config().to_string_lossy(),
        }))
        .map_err(|error| format!("{error:?}"))
        .and_then(|answer| match answer.get("error") {
            Some(error) => Err(error.to_string()),
            None => Ok(answer["value"].clone()),
        })
    }

    fn config(&self) -> PathBuf {
        self.0.join("home/.codex/config.toml")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn an_absent_config_has_no_bytes_or_identity() {
    let home = Home::new();
    let answer = home.ask().unwrap();
    assert_eq!(answer["before"], Value::Null);
    assert_eq!(answer["identity"], Value::Null);
    assert_eq!(answer["key_present"], false);
}

#[test]
fn a_present_config_returns_its_bytes_and_identity() {
    let home = Home::new();
    fs::write(home.config(), b"model = \"fixture\"\n").unwrap();
    #[cfg(unix)]
    private(&home.config());
    let answer = home.ask().unwrap();
    assert_eq!(
        answer["before"],
        json!(STANDARD.encode(b"model = \"fixture\"\n"))
    );
    assert_eq!(answer["identity"].as_array().map(Vec::len), Some(5));
}

#[test]
fn non_utf8_config_and_pending_publication_are_refused() {
    let home = Home::new();
    fs::write(home.config(), [0xff, 0xfe]).unwrap();
    #[cfg(unix)]
    private(&home.config());
    assert!(home
        .ask()
        .is_err_and(|error| error.contains("not valid UTF-8")));
    fs::write(home.config(), b"").unwrap();
    let record = home
        .0
        .join("guard/managed/codex/pending-hook-publication.json");
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    fs::write(&record, b"{}").unwrap();
    assert!(home
        .ask()
        .is_err_and(|error| error.contains("codex_hook_publication_pending")));
}

#[test]
fn an_abort_before_any_record_leaves_the_config_alone() {
    let home = Home::new();
    fs::write(home.config(), b"model = \"fixture\"\n").unwrap();
    let answer = dispatch(&json!({
        "op": "publication_abort",
        "home": home.0.join("guard").to_string_lossy(),
        "config": home.config().to_string_lossy(),
        "prepared": false,
        "written": STANDARD.encode(b"other"),
    }))
    .unwrap();
    assert_eq!(answer["value"], json!({ "durable": false }));
    assert_eq!(fs::read(home.config()).unwrap(), b"model = \"fixture\"\n");
}
