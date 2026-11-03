use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn base() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(directory.path()).expect("canonical tempdir");
    (directory, base)
}

fn write(path: &Path, text: &[u8]) -> PathBuf {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, text).expect("write");
    path.to_path_buf()
}

fn spelled(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn probe(path: &str) -> bool {
    let answer = dispatch(&json!({"op": "probe", "path": path})).expect("probe answer");
    answer["safe"].as_bool().expect("bool")
}

fn read(path: &Path, shebang_only: bool) -> Value {
    let request = json!({"op": "read", "path": spelled(path), "shebang_only": shebang_only});
    dispatch(&request).expect("read answer")["text"].clone()
}

fn imports(script: &Path, entries: &[&str]) -> Vec<String> {
    let request = json!({"op": "imports", "script": spelled(script), "imports": entries});
    let answer = dispatch(&request).expect("imports answer");
    serde_json::from_value(answer["paths"].clone()).expect("path list")
}

fn module(module: &str, script: &Path) -> Value {
    let request = json!({"op": "module", "module": module, "script": spelled(script)});
    dispatch(&request).expect("module answer")["text"].clone()
}

#[test]
fn only_absolute_regular_files_outside_kernel_file_systems_are_probed() {
    let (_directory, base) = base();
    let script = write(&base.join("tool.sh"), b"echo hi\n");
    assert!(probe(&spelled(&script)));
    assert!(!probe("tool.sh"));
    assert!(!probe(""));
    assert!(!probe(&spelled(&base)));
    assert!(!probe(&spelled(&base.join("missing"))));
    symlink("/dev/null", base.join("null")).expect("symlink");
    assert!(!probe(&spelled(&base.join("null"))));
    symlink(&script, base.join("alias")).expect("symlink");
    assert!(probe(&spelled(&base.join("alias"))));
}

#[test]
fn a_script_is_read_up_to_the_limit_and_blank_text_is_nothing() {
    let (_directory, base) = base();
    let script = write(&base.join("tool.py"), b"import sys\n");
    assert_eq!(read(&script, false), "import sys\n");
    let long = write(&base.join("long.py"), &[b'a'; 40 * 1024]);
    assert_eq!(read(&long, false).as_str().map(str::len), Some(32 * 1024));
    let blank = write(&base.join("blank.py"), b" \n\t\x1c\x1f\n");
    assert_eq!(read(&blank, false), Value::Null);
    let invalid = write(&base.join("bytes.py"), b"a\xffb");
    assert_eq!(read(&invalid, false), "a\u{fffd}b");
    assert_eq!(read(&base.join("missing.py"), false), Value::Null);
}

#[test]
fn a_program_run_directly_is_read_only_with_a_shebang_line() {
    let (_directory, base) = base();
    let program = write(&base.join("tool"), b"\xcf\xfa\xed\xfe binary");
    assert_eq!(read(&program, true), Value::Null);
    let script = write(&base.join("script"), b"#!/bin/sh\necho hi\n");
    assert_eq!(read(&script, true), "#!/bin/sh\necho hi\n");
}

#[test]
fn only_script_files_inside_the_scripts_folder_are_followed() {
    let (_directory, base) = base();
    let folder = base.join("tool");
    let script = write(&folder.join("main.mjs"), b"");
    let cli = write(&folder.join("cli.mjs"), b"");
    write(&folder.join("data.json"), b"{}");
    let outside = write(&base.join("outside.mjs"), b"");
    symlink(&outside, folder.join("escape.mjs")).expect("symlink");
    std::fs::create_dir(folder.join("pkg")).expect("mkdir");
    let entries = [
        "./cli",
        "./data.json",
        "./../outside.mjs",
        "./escape.mjs",
        "./pkg",
        "./main.mjs",
        "./missing.mjs",
        "cli.mjs",
        "./cli\0.mjs",
    ];
    assert_eq!(imports(&script, &entries), [spelled(&cli)]);
}

#[test]
fn a_python_import_may_name_a_package() {
    let (_directory, base) = base();
    let script = write(&base.join("main.py"), b"");
    let package = write(&base.join("server/__init__.py"), b"");
    assert_eq!(imports(&script, &["./server.py"]), [spelled(&package)]);
}

#[test]
fn at_most_a_few_imports_are_followed_once_each() {
    let (_directory, base) = base();
    let script = write(&base.join("main.py"), b"");
    let names: Vec<String> = (0..7).map(|index| format!("./m{index}.py")).collect();
    for name in &names {
        write(&base.join(&name[2..]), b"");
    }
    let mut entries: Vec<&str> = vec!["./m0.py", "./m0.py"];
    entries.extend(names.iter().map(String::as_str));
    let found = imports(&script, &entries);
    assert_eq!(found.len(), 4);
    assert_eq!(found[0], spelled(&base.join("m0.py")));
    assert_eq!(found[1], spelled(&base.join("m1.py")));
}

#[test]
fn a_script_reached_through_a_symlink_reads_beside_its_real_file() {
    let (_directory, base) = base();
    let script = write(&base.join("real/main.py"), b"");
    let cli = write(&base.join("real/cli.py"), b"");
    std::fs::create_dir(base.join("bin")).expect("mkdir");
    symlink(&script, base.join("bin/main.py")).expect("symlink");
    assert_eq!(
        imports(&base.join("bin/main.py"), &["./cli.py"]),
        [spelled(&cli)]
    );
    assert!(imports(&base.join("missing.py"), &["./cli.py"]).is_empty());
}

#[test]
fn a_module_swapped_for_a_symlink_after_it_was_checked_is_not_read() {
    let (_directory, base) = base();
    let folder = base.join("tool");
    let script = write(&folder.join("tool.mjs"), b"import './lib/cli.mjs';\n");
    let module_path = write(
        &folder.join("lib/cli.mjs"),
        b"switch (process.argv[2]) {}\n",
    );
    let outside = write(&base.join("outside/cli.mjs"), b"secret\n");
    let found = imports(&script, &["./lib/cli.mjs"]);
    assert_eq!(found, [spelled(&module_path)]);
    assert_eq!(module(&found[0], &script), "switch (process.argv[2]) {}\n");
    std::fs::remove_file(&module_path).expect("unlink");
    symlink(&outside, &module_path).expect("symlink");
    assert_eq!(module(&found[0], &script), Value::Null);
    std::fs::remove_file(&module_path).expect("unlink");
    std::fs::remove_dir(folder.join("lib")).expect("rmdir");
    symlink(base.join("outside"), folder.join("lib")).expect("symlink");
    assert_eq!(module(&found[0], &script), Value::Null);
}

#[test]
fn a_module_outside_the_folder_or_not_a_file_is_not_read() {
    let (_directory, base) = base();
    let script = write(&base.join("tool/main.py"), b"");
    let outside = write(&base.join("other.py"), b"print(1)\n");
    assert_eq!(module(&spelled(&outside), &script), Value::Null);
    std::fs::create_dir(base.join("tool/pkg")).expect("mkdir");
    assert_eq!(
        module(&spelled(&base.join("tool/pkg")), &script),
        Value::Null
    );
    let blank = write(&base.join("tool/blank.py"), b"\n\n");
    assert_eq!(module(&spelled(&blank), &script), Value::Null);
    assert_eq!(module("relative.py", &script), Value::Null);
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!([]),
        json!({"op": "probe"}),
        json!({"op": "probe", "path": 1}),
        json!({"op": "probe", "path": "/x", "extra": 1}),
        json!({"op": "read", "path": "/x"}),
        json!({"op": "read", "path": "/x", "shebang_only": "no"}),
        json!({"op": "imports", "script": "/x", "imports": "./a"}),
        json!({"op": "imports", "script": "/x", "imports": [1]}),
        json!({"op": "module", "module": "/x"}),
        json!({"op": "other", "path": "/x"}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
