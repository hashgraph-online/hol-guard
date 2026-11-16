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

#[test]
fn runtime_homes_name_only_directories_that_exist() {
    let home = tempfile::tempdir().expect("home");
    std::fs::create_dir(home.path().join(".gemini")).expect("gemini");
    std::fs::write(home.path().join(".cursor"), b"").expect("cursor file");
    let homes = runtime_homes(home.path());
    assert_eq!(
        homes.get("gemini").and_then(Value::as_str),
        Some(home.path().join(".gemini").to_string_lossy().as_ref())
    );
    assert!(!homes.contains_key("cursor"));
}
