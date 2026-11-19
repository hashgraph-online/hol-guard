use serde_json::json;

use super::*;

#[test]
fn an_index_keeps_its_object_entries() {
    let raw = br#"{"entries": [{"slug": "a"}, 3, "b", {"slug": "c"}]}"#;
    assert_eq!(
        entries_from(raw),
        Ok(vec![json!({"slug": "a"}), json!({"slug": "c"})])
    );
}

#[test]
fn an_index_that_is_not_json_or_not_shaped_is_told_apart() {
    assert_eq!(entries_from(b"not json"), Err(false));
    assert_eq!(entries_from(br#"{"entries": {}}"#), Err(true));
    assert_eq!(entries_from(br#"[]"#), Err(true));
}

#[test]
fn listings_match_the_installed_repositories_by_substring() {
    let index = vec![
        json!({"slug": "kept", "repository": "https://GitHub.com/Owner/Repo"}),
        json!({"slug": "other", "repository": "https://github.com/owner/else"}),
        json!({"slug": "unrepo"}),
    ];
    let repositories = json!(["https://github.com/owner/repo", 7]);
    assert_eq!(
        filter_installed(index, Some(&repositories)),
        vec![json!({"slug": "kept", "repository": "https://GitHub.com/Owner/Repo"})]
    );
}

#[test]
fn no_installed_repository_keeps_no_listing() {
    let index = vec![json!({"slug": "a", "repository": "https://github.com/o/r"})];
    assert!(filter_installed(index.clone(), Some(&json!([]))).is_empty());
    assert!(filter_installed(index, None).is_empty());
}

/// A HOL that never answers and reads no runtime-home overrides, so the
/// test sees only its temp home.
struct NoEnvHol;

impl Hol for NoEnvHol {
    fn index(&self, _index: Index) -> Result<Vec<Value>, String> {
        Err("offline".to_owned())
    }

    fn post_report(&self, _report: &Value) -> Result<i64, String> {
        Err("offline".to_owned())
    }

    fn configured_dir(&self, _name: &str) -> Option<String> {
        None
    }
}

#[test]
fn runtime_homes_name_only_directories_that_exist() {
    let home = tempfile::tempdir().expect("home");
    std::fs::create_dir(home.path().join(".gemini")).expect("gemini");
    std::fs::write(home.path().join(".cursor"), b"").expect("cursor file");
    let homes = runtime_homes(&NoEnvHol, home.path());
    assert_eq!(
        homes.get("gemini").and_then(Value::as_str),
        Some(home.path().join(".gemini").to_string_lossy().as_ref())
    );
    assert!(!homes.contains_key("cursor"));
}

#[test]
fn hol_reply_counts_accepted_entries() {
    assert_eq!(accepted_from(b""), Some(0));
    assert_eq!(accepted_from(br#"{"accepted": 3}"#), Some(3));
    assert_eq!(accepted_from(br#"{"accepted": "3"}"#), Some(0));
    assert_eq!(accepted_from(br#"[1]"#), Some(0));
    assert_eq!(accepted_from(b"<html>"), None);
}

#[test]
fn a_request_the_host_does_not_know_is_refused() {
    let answer = run_command(br#"{"command": "upload", "guardHome": "/nowhere"}"#);
    assert_eq!(answer["ok"], json!(false));
    assert_eq!(
        answer["error"],
        json!("The plugin telemetry request was not understood.")
    );
}

#[test]
fn status_on_and_off_round_trip_through_the_host() {
    let guard_home = tempfile::tempdir().expect("guard home");
    let home = guard_home.path().to_string_lossy().into_owned();
    let request = |command: &str| {
        run_command(
            json!({"command": command, "guardHome": home})
                .to_string()
                .as_bytes(),
        )
    };
    assert_eq!(
        request("status")["result"],
        json!({"enabled": false, "lastWeek": null})
    );
    assert_eq!(request("on")["result"], json!({"enabled": true}));
    assert_eq!(request("status")["result"]["enabled"], json!(true));
    assert_eq!(request("off")["result"], json!({"enabled": false}));
    assert_eq!(request("status")["result"]["enabled"], json!(false));
}
