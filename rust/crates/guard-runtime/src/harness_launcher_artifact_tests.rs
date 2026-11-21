use serde_json::{json, Value};

use super::*;

const SHIM: &str = "python -m codex_plugin_scanner.cli guard run codex %*\r\n";

fn ask(fields: Value) -> KindResult {
    let mut fields = fields;
    fields["op"] = json!("launcher_artifact");
    answer(fields.as_object().unwrap())
}

#[test]
fn the_first_candidate_running_guard_is_the_artifact() {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(bin.join("guard-codex"), "#!/bin/sh\nexec codex \"$@\"\n").unwrap();
    std::fs::write(bin.join("guard-codex.cmd"), SHIM).unwrap();
    std::fs::write(bin.join("guard-old"), SHIM).unwrap();
    let guard_home = home.path().to_string_lossy().into_owned();

    let found =
        ask(json!({"harness": "codex", "guard_home": guard_home, "names": ["codex", "old"]}))
            .unwrap();
    let shim = bin.join("guard-codex.cmd").to_string_lossy().into_owned();
    assert_eq!(
        found,
        json!({"launcher_artifact": {
            "artifact_id": "codex:guard-launcher-shim",
            "name": "guard-codex.cmd",
            "harness": "codex",
            "artifact_type": "guard_launcher_shim",
            "source_scope": "guard",
            "config_path": shim,
            "command": shim,
            "metadata": {"shim_dir": bin.to_string_lossy()},
        }})
    );

    let legacy =
        ask(json!({"harness": "codex", "guard_home": guard_home, "names": ["old", "codex"]}))
            .unwrap();
    assert_eq!(legacy["launcher_artifact"]["name"], "guard-old");
    let none =
        ask(json!({"harness": "codex", "guard_home": guard_home, "names": ["absent"]})).unwrap();
    assert_eq!(none, json!({"launcher_artifact": null}));
}

#[test]
fn a_relative_guard_home_anchors_on_the_callers_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = cwd.path().join("home").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("guard-codex"), SHIM).unwrap();
    let cwd = cwd.path().to_string_lossy().into_owned();

    let found =
        ask(json!({"harness": "codex", "guard_home": "home", "names": ["codex"], "cwd": cwd}))
            .unwrap();
    let relative = Path::new("home").join("bin").join("guard-codex");
    assert_eq!(
        found["launcher_artifact"]["config_path"],
        json!(relative.to_string_lossy())
    );
    assert!(ask(json!({"harness": "codex", "guard_home": "home", "names": ["codex"]})).is_err());
}

#[test]
fn a_malformed_request_is_refused() {
    for request in [
        json!({"harness": "codex", "guard_home": "/g", "names": "codex"}),
        json!({"harness": "codex", "guard_home": "/g", "names": [1]}),
        json!({"harness": "codex", "names": []}),
        json!({"harness": 1, "guard_home": "/g", "names": []}),
        json!({"harness": "codex", "guard_home": "/g", "names": [], "cwd": 3}),
        json!({"harness": "codex", "guard_home": "/g", "names": [], "extra": true}),
    ] {
        assert!(ask(request).is_err());
    }
}
