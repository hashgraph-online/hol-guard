use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::run_command;

struct Fixture {
    _root: tempfile::TempDir,
    state_root: PathBuf,
    home: PathBuf,
    owner: u32,
}

fn setup() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().to_path_buf();
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    Fixture {
        state_root: base.join("state"),
        owner: owner_of(&home),
        home,
        _root: root,
    }
}

#[cfg(unix)]
fn owner_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    fs::metadata(path).unwrap().uid()
}

#[cfg(windows)]
fn owner_of(_path: &Path) -> u32 {
    0
}

fn install(name: &str, artifact: &Path) -> Value {
    json!({"active": true, "harness": name, "manifest": {"config_path": artifact}})
}

#[test]
fn the_command_answers_a_framed_request() {
    let fixture = setup();
    let artifact = fixture.home.join("config.json");
    fs::write(&artifact, "{}").unwrap();
    let run = |request: Value| {
        run_command(serde_json::to_vec(&request).unwrap().as_slice())
            .map(|response| serde_json::from_slice::<Value>(&response).unwrap())
    };
    let framed = |fields: Value| {
        let mut request = json!({
            "schema": "harness-coverage.v1",
            "state_root": fixture.state_root,
            "registry_owner_uid": fixture.owner,
        });
        request
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        request
    };

    assert_eq!(
        run(framed(
            json!({"op": "register", "home": fixture.home, "installs": [install("codex", &artifact)]})
        )),
        Ok(json!({"ok": true}))
    );
    assert_eq!(
        run(framed(
            json!({"op": "verify", "required_harnesses": ["codex"]})
        )),
        Ok(json!({
            "ok": true,
            "state": "healthy",
            "reason_code": "harness_coverage_healthy",
            "coverage": {"required": 1, "protected": 1, "degraded": 0, "missing": 0},
        }))
    );
    assert_eq!(
        run(framed(
            json!({"op": "register", "home": fixture.home, "installs": [
                {"active": true, "harness": "", "manifest": {}}
            ]})
        )),
        Ok(
            json!({"ok": false, "error_class": "value", "reason_code": "harness_coverage_registry_invalid"})
        )
    );
    assert_eq!(
        run(framed(json!({"op": "unregister", "home": fixture.home}))),
        Ok(json!({"ok": true}))
    );
    for refused in [
        json!({"op": "verify"}),
        json!({"op": "verify", "required_harnesses": [], "home": "x"}),
        json!({"op": "unregister", "home": "x", "installs": []}),
        json!({"op": "delete", "home": "x"}),
        json!({"op": "verify", "required_harnesses": [], "unexpected": 1}),
    ] {
        assert!(run(framed(refused)).is_err());
    }
    let mut wrong_schema = framed(json!({"op": "verify", "required_harnesses": []}));
    wrong_schema["schema"] = json!("other");
    assert!(run(wrong_schema).is_err());
}
