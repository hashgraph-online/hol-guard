use std::collections::BTreeMap;

use serde_json::json;

use super::*;

/// Directories as a fake Windows reports them: `real` maps each path that
/// exists and is not a reparse point to its final path.
struct FakeDirectories {
    windows: Option<&'static str>,
    system: Option<&'static str>,
    profile: Option<&'static str>,
    roaming: Option<&'static str>,
    real_directories: BTreeMap<&'static str, &'static str>,
    real_files: BTreeMap<&'static str, &'static str>,
}

impl Default for FakeDirectories {
    fn default() -> Self {
        Self {
            windows: Some(r"C:\WINDOWS"),
            system: Some(r"C:\WINDOWS\system32"),
            profile: Some(r"C:\Users\guard"),
            roaming: Some(r"D:\Redirected\Roaming"),
            real_directories: BTreeMap::from([
                (r"C:\WINDOWS", r"C:\Windows"),
                (r"C:\WINDOWS\system32", r"C:\Windows\System32"),
                (r"C:\Users\guard", r"C:\Users\guard"),
                (
                    r"C:\Users\guard\AppData\Local\Temp",
                    r"C:\Users\guard\AppData\Local\Temp",
                ),
                (r"D:\Redirected\Roaming", r"D:\Redirected\Roaming"),
            ]),
            real_files: BTreeMap::from([
                (
                    r"C:\Windows\System32\cmd.exe",
                    r"C:\Windows\System32\cmd.exe",
                ),
                (
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ),
                (r"C:\Windows\System32\escape.exe", r"C:\Tools\escape.exe"),
                (
                    r"C:\Windows\System32\..\notepad.exe",
                    r"C:\Windows\notepad.exe",
                ),
            ]),
        }
    }
}

impl Directories for FakeDirectories {
    fn kernel_windows(&self) -> Option<String> {
        self.windows.map(str::to_owned)
    }

    fn kernel_system(&self) -> Option<String> {
        self.system.map(str::to_owned)
    }

    fn user_profile(&self) -> Option<String> {
        self.profile.map(str::to_owned)
    }

    fn roaming_appdata(&self) -> Option<String> {
        self.roaming.map(str::to_owned)
    }

    fn real_directory(&self, path: &str) -> Option<String> {
        self.real_directories
            .get(path)
            .map(|real| (*real).to_owned())
    }

    fn real_regular_file(&self, path: &str) -> Option<String> {
        self.real_files.get(path).map(|real| (*real).to_owned())
    }
}

fn paths(directories: &FakeDirectories, request: Value) -> Value {
    let mut request = request;
    request["schema"] = json!(SCHEMA);
    answer(&serde_json::from_value(request).unwrap(), directories).unwrap()["paths"].clone()
}

fn executable(directories: &FakeDirectories, parts: &[&str]) -> Value {
    paths(
        directories,
        json!({"op": "system_executable", "relative_parts": parts}),
    )
}

#[test]
fn system_directories_answer_the_resolved_pair() {
    let directories = FakeDirectories::default();
    assert_eq!(
        paths(&directories, json!({"op": "system_directories"})),
        json!([r"C:\Windows", r"C:\Windows\System32"])
    );
}

#[test]
fn system_directories_need_system32_directly_inside_windows() {
    for (windows, system) in [
        (r"C:\WINDOWS", r"C:\WINDOWS\SysWOW64"),
        (r"C:\WINDOWS", r"C:\Other\system32"),
        (r"C:\WINDOWS", r"C:\WINDOWS\nested\system32"),
        (r"WINDOWS", r"WINDOWS\system32"),
    ] {
        let directories = FakeDirectories {
            windows: Some(windows),
            system: Some(system),
            ..FakeDirectories::default()
        };
        assert_eq!(
            paths(&directories, json!({"op": "system_directories"})),
            Value::Null,
            "{system}"
        );
    }
    // System32 resolving somewhere else, a reparse point or a missing
    // directory answers nothing.
    let mut moved = FakeDirectories::default();
    moved
        .real_directories
        .insert(r"C:\WINDOWS\system32", r"E:\Elsewhere\System32");
    assert_eq!(
        paths(&moved, json!({"op": "system_directories"})),
        Value::Null
    );
    let mut reparse = FakeDirectories::default();
    reparse.real_directories.remove(r"C:\WINDOWS");
    assert_eq!(
        paths(&reparse, json!({"op": "system_directories"})),
        Value::Null
    );
    let unreported = FakeDirectories {
        system: None,
        ..FakeDirectories::default()
    };
    assert_eq!(
        paths(&unreported, json!({"op": "system_directories"})),
        Value::Null
    );
}

#[test]
fn system_executables_resolve_inside_system32() {
    let directories = FakeDirectories::default();
    assert_eq!(
        executable(&directories, &["cmd.exe"]),
        json!([r"C:\Windows\System32\cmd.exe"])
    );
    assert_eq!(
        executable(
            &directories,
            &["WindowsPowerShell", "v1.0", "powershell.exe"]
        ),
        json!([r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"])
    );
    for refused in [
        &["escape.exe"][..],
        &["..", "notepad.exe"],
        &["missing.exe"],
        &[],
        &[""],
        &[r"\cmd.exe"],
        &["/cmd.exe"],
        &[r"C:\Windows\System32\cmd.exe"],
        &["C:cmd.exe"],
        &["cmd.exe:stream"],
        &["cmd\0.exe"],
    ] {
        assert_eq!(
            executable(&directories, refused),
            Value::Null,
            "{refused:?}"
        );
    }
    let long = "a".repeat(MAX_PART_CHARS + 1);
    assert_eq!(executable(&directories, &[&long]), Value::Null);
}

#[test]
fn known_folders_answer_their_real_directories() {
    let directories = FakeDirectories::default();
    assert_eq!(
        paths(&directories, json!({"op": "user_profile"})),
        json!([r"C:\Users\guard"])
    );
    assert_eq!(
        paths(&directories, json!({"op": "roaming_appdata"})),
        json!([r"D:\Redirected\Roaming"])
    );
    assert_eq!(
        paths(&directories, json!({"op": "local_temp"})),
        json!([r"C:\Users\guard\AppData\Local\Temp"])
    );
    let unreported = FakeDirectories {
        profile: None,
        roaming: None,
        ..FakeDirectories::default()
    };
    for op in ["user_profile", "roaming_appdata", "local_temp"] {
        assert_eq!(paths(&unreported, json!({"op": op})), Value::Null, "{op}");
    }
    let mut no_temp = FakeDirectories::default();
    no_temp
        .real_directories
        .remove(r"C:\Users\guard\AppData\Local\Temp");
    assert_eq!(paths(&no_temp, json!({"op": "local_temp"})), Value::Null);
}

#[test]
fn requests_are_checked() {
    let directories = FakeDirectories::default();
    let ask = |request: Value| answer(&serde_json::from_value(request).unwrap(), &directories);
    assert!(ask(json!({"schema": SCHEMA, "op": "program_files"})).is_err());
    assert!(ask(json!({"schema": "other", "op": "user_profile"})).is_err());
    assert!(ask(json!({
        "schema": SCHEMA,
        "op": "user_profile",
        "relative_parts": ["cmd.exe"],
    }))
    .is_err());
    assert!(ask(json!({
        "schema": SCHEMA,
        "op": "system_executable",
        "relative_parts": vec!["a"; MAX_RELATIVE_PARTS + 1],
    }))
    .is_err());
    assert!(serde_json::from_value::<Request>(json!({
        "schema": SCHEMA,
        "op": "user_profile",
        "extra": true,
    }))
    .is_err());
    assert!(run_command(&b"{"[..]).is_err());
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&oversized[..]),
        Err("windows_trusted_directories_request_too_large".to_owned())
    );
}

#[test]
fn off_windows_nothing_is_read() {
    if cfg!(windows) {
        return;
    }
    for op in [
        "system_directories",
        "user_profile",
        "roaming_appdata",
        "local_temp",
    ] {
        let request: Request = serde_json::from_value(json!({"schema": SCHEMA, "op": op})).unwrap();
        assert_eq!(
            answer(&request, &SystemDirectories).unwrap(),
            json!({"paths": null})
        );
    }
}
