//! Replays package.json script vectors recorded from the reference Python
//! (`scripts/record_package_json_script_vectors.py`).

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/package_json_script_vectors.json");
const ROOT_TOKEN: &str = "<ROOT>";

fn tree(name: &str, files: &Map<String, Value>) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-package-scripts-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create vector root");
    let root = fs::canonicalize(root).expect("resolve vector root");
    for (relative, content) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("file parent")).expect("create parent");
        fs::write(&path, content.as_str().expect("file content")).expect("write file");
    }
    root
}

fn under(root: &Path, relative: &str, fallback: Option<&str>) -> String {
    match (relative, fallback) {
        ("", None) => path_text(root),
        ("", Some(fallback)) => path_text(&root.join(fallback)),
        (relative, _) => path_text(&root.join(relative)),
    }
}

fn detokenize(value: Value, root: &Path) -> Value {
    let text = serde_json::to_string(&value).expect("serialize");
    let root_json = serde_json::to_string(&path_text(root)).expect("serialize root");
    serde_json::from_str(&text.replace(root_json.trim_matches('"'), ROOT_TOKEN))
        .expect("parse detokenized")
}

#[test]
fn package_json_scripts_match_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    assert!(vectors.len() >= 50);
    for vector in &vectors {
        let name = vector["name"].as_str().expect("name");
        let root = tree(name, vector["files"].as_object().expect("files"));
        let cwd = under(&root, vector["cwd"].as_str().expect("cwd"), None);
        let home = under(
            &root,
            vector["home"].as_str().expect("home"),
            Some("no-home"),
        );
        let command = vector["command"]
            .as_str()
            .expect("command")
            .replace(ROOT_TOKEN, &path_text(&root));
        let got = package_json_scripts(&command, &cwd, &home).expect("no native error");
        let got = got.map(|found| {
            assert_eq!(
                found.identity,
                local_cli_identity(&found.source).expect("identity"),
                "{name}: identity is derived from the source"
            );
            let mut value = serde_json::to_value(&found).expect("serialize result");
            value.as_object_mut().expect("object").remove("identity");
            detokenize(value, &root)
        });
        assert_eq!(
            got.unwrap_or(Value::Null),
            vector["expected"],
            "vector {name}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn command_ids_follow_python_rules() {
    assert_eq!(command_id_for_script("build:web"), "build.web");
    assert_eq!(command_id_for_script("a:b:c:d"), "a.b.c.d");
    assert_eq!(parent_command_id("a:b:c"), Some("a.b".to_owned()));
    assert_eq!(parent_command_id("build"), None);
    for name in ["root", "other", "a:b:c:d:e", "1abc", "x::y", "Build Web!"] {
        let command_id = command_id_for_script(name);
        assert!(command_id != "root" && command_id != "other", "{name}");
        assert!(is_command_part(&command_id), "{name} -> {command_id}");
    }
    assert!(is_command_part(&"a".repeat(41)));
    assert!(!is_command_part(&"a".repeat(42)));
    assert!(!is_command_part(""));
}
