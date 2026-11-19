//! `prepare_guard_shim` and `prepare_guard_shim_removal`: the launcher
//! sources an install writes and the files an uninstall deletes.

use std::fs;

use serde_json::{json, Value};

use super::{after, Home};

fn interpreter() -> Value {
    json!({
        "executable": "/opt/python/bin/python3",
        "frozen": false,
        "package_interpreter": "/opt/python/bin/python3",
        "python_flags": ["-I", "-P"],
        "import_root": "/opt/site",
        "launcher_env": [["HOL_GUARD_LAUNCHER", "1"]],
    })
}

fn launchers(answer: &Value) -> (String, String) {
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{answer}");
    (after(&files[0]), after(&files[1]))
}

#[test]
fn the_python_launcher_re_enters_guard_through_the_trusted_loader() {
    let home = Home::new();
    let answer = home.ask(
        "devin",
        "prepare_guard_shim",
        json!({"interpreter": interpreter()}),
    );
    let (posix, windows) = launchers(&answer);
    assert!(posix.starts_with("#!/opt/python/bin/python3\n"), "{posix}");
    // `repr` picks double quotes because the launcher source holds single quotes.
    assert!(
        posix.contains("'-c', \"import importlib.util, os, sys; "),
        "{posix}"
    );
    assert!(posix.contains("'guard', 'run', 'devin', '--guard-home', "));
    assert!(posix.contains("base_env = {'HOL_GUARD_LAUNCHER': '1'}"));
    assert!(posix.contains("os.execvpe(argv[0], argv, combined_env)"));
    // `exit /b` alone returns the hook's status; `%ERRORLEVEL%` could be inherited.
    assert!(windows.ends_with("exit /b\r\n"), "{windows:?}");
    assert!(!windows.contains("%ERRORLEVEL%"));
    assert_eq!(answer["files"][0]["after_mode"], 0o755);
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["shim_command"], "guard-devin");
    assert!(!home.guard().join("bin").exists());
}

#[cfg(unix)]
#[test]
fn a_desktop_core_launcher_is_run_directly_with_cmd_safe_arguments() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    // A desktop core under a temporary root is never baked into a launcher,
    // so it sits in the workspace's build directory instead.
    let durable = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&durable).unwrap();
    let durable = tempfile::TempDir::new_in(durable).unwrap();
    let data = fs::canonicalize(durable.path()).unwrap().join("data");
    let core = data.join("org.hol.guard.desktop").join("core");
    fs::create_dir_all(&core).unwrap();
    let desktop = core.join("current-hol-guard");
    fs::write(&desktop, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&desktop, fs::Permissions::from_mode(0o700)).unwrap();
    let workspace = home.root.join("100%").join("a&b");
    let mut request = json!({
        "harness": "omp",
        "op": "prepare_guard_shim",
        "interpreter": interpreter(),
        "context": home.context(json!({"PATH": "", "XDG_DATA_HOME": data})),
    });
    request["context"]["workspace"] = json!(workspace);
    let answer = super::dispatch(&request).unwrap();
    let (posix, windows) = launchers(&answer);
    assert!(posix.starts_with("#!/bin/sh\n# base_command = "), "{posix}");
    assert!(
        posix.contains(&desktop.to_string_lossy().into_owned()),
        "{posix}"
    );
    assert!(windows.contains("setlocal DisableDelayedExpansion"));
    assert!(windows.contains("run-shim"));
    let quoted = format!("\"{}\"", workspace.to_string_lossy().replace('%', "%%"));
    assert!(windows.contains(&quoted), "{windows}");
    assert!(windows.contains("\"omp\" \"--\" %*"), "{windows}");
}

#[test]
fn the_removal_plan_names_every_launcher_without_deleting_one() {
    let home = Home::new();
    let bin = home.guard().join("bin");
    fs::create_dir_all(&bin).unwrap();
    for name in [
        "guard-cursor-agent",
        "guard-cursor-agent.cmd",
        "guard-cursor",
    ] {
        fs::write(bin.join(name), name).unwrap();
    }
    let answer = home.ask(
        "cursor",
        "prepare_guard_shim_removal",
        json!({"launcher_name": "cursor-agent", "legacy_launcher_names": ["cursor"]}),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 3, "{answer}");
    assert!(files
        .iter()
        .all(|file| file["after"].is_null() && file["no_follow"] == true));
    assert!(bin.join("guard-cursor").exists());
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["removed_paths"].as_array().unwrap().len(), 3);
    assert_eq!(manifest["shim_command"], "guard-cursor-agent");
    assert_eq!(
        manifest["notes"],
        json!(["Removed the Guard launcher shim for cursor."])
    );
}
