use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

use super::super::dispatch;
use super::{answered, environment, settled};
use crate::hook_process_spawn::BoundedHookProcessResult;

fn ended(
    returncode: Option<i32>,
    timed_out: bool,
    overflow: bool,
    contained: bool,
) -> BoundedHookProcessResult {
    BoundedHookProcessResult {
        returncode,
        stdout: String::new(),
        stderr: "private path".into(),
        output_limit_exceeded: overflow,
        timed_out,
        containment_failed: !contained,
    }
}

#[test]
fn the_probe_sees_only_the_inherited_values_and_a_neutral_home() {
    let inherited = BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]);
    let environment = environment(inherited, Path::new("/guard/runtime/python-probe"));
    assert_eq!(
        environment,
        BTreeMap::from(
            [
                ("HOME", "/guard/runtime/python-probe"),
                ("LANG", "C.UTF-8"),
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("PYTHONIOENCODING", "utf-8"),
                ("PYTHONNOUSERSITE", "1"),
                ("PYTHONSAFEPATH", "1"),
                ("USERPROFILE", "/guard/runtime/python-probe"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
}

#[test]
fn how_the_probe_ended_has_a_reason_that_names_no_path() {
    for (result, reason) in [
        (
            ended(Some(1), true, false, true),
            "guard_hook_python_probe_timeout",
        ),
        (
            ended(Some(1), false, true, true),
            "guard_hook_python_probe_output_limit",
        ),
        (
            ended(Some(0), false, false, false),
            "guard_hook_python_probe_capture_incomplete",
        ),
        (
            ended(Some(1), false, false, true),
            "guard_hook_python_probe_rejected",
        ),
        (
            ended(None, false, false, true),
            "guard_hook_python_probe_rejected",
        ),
    ] {
        assert_eq!(settled(&result), Err(reason));
    }
    assert_eq!(settled(&ended(Some(0), false, false, true)), Ok(()));
}

#[test]
fn only_one_line_equal_to_the_record_is_accepted() {
    let record = json!({"schema": 2, "version": "1.0"});
    assert_eq!(
        answered("{\"schema\":2,\"version\":\"1.0\"}\n", &record),
        Ok(())
    );
    for (stdout, reason) in [
        ("noise\n{}\n", "guard_hook_python_probe_output_invalid"),
        ("", "guard_hook_python_probe_output_invalid"),
        ("\n", "guard_hook_python_probe_output_invalid"),
        ("{not json}\n", "guard_hook_python_probe_output_invalid"),
        (
            "{\"schema\":2,\"version\":\"1.0\u{FFFD}\"}\n",
            "guard_hook_python_probe_output_invalid",
        ),
        (
            "{\"schema\":2,\"version\":\"2.0\"}\n",
            "guard_hook_python_probe_identity_mismatch",
        ),
        ("[]\n", "guard_hook_python_probe_identity_mismatch"),
    ] {
        assert_eq!(answered(stdout, &record), Err(reason), "{stdout:?}");
    }
}

fn expected() -> Value {
    json!({
        "package_file": "/p/codex_plugin_scanner/__init__.py",
        "package_root": "/p",
        "cryptography_file": "/p/cryptography/__init__.py",
        "import_roots": ["/p"],
        "hol_distribution_root": null,
        "cryptography_distribution_root": "/p",
        "version": "1.0",
        "entry_point": "codex_plugin_scanner.cli:main",
    })
}

#[test]
fn a_malformed_attest_request_is_refused() {
    let request = |inherited: Value, expected: Value| {
        json!({
            "op": "attest",
            "python": "/usr/bin/python3",
            "cwd": "/guard/runtime/python-probe",
            "inherited": inherited,
            "expected": expected,
        })
    };
    let mut short = expected();
    short.as_object_mut().unwrap().remove("version");
    for args in [
        request(json!({"PYTHONPATH": "/x"}), expected()),
        request(json!({"LANG": 1}), expected()),
        request(json!({}), short),
        json!({"op": "attest", "python": "python3", "cwd": "/", "inherited": {}, "expected": expected()}),
        json!({"op": "attest", "python": "/usr/bin/python3", "cwd": "/", "inherited": {}}),
    ] {
        assert!(dispatch(&args).is_err(), "{args}");
    }
}

#[test]
fn an_interpreter_that_cannot_be_read_is_unavailable_before_anything_runs() {
    let home = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(home.path()).unwrap();
    let answer = dispatch(&json!({
        "op": "attest",
        "python": root.join("absent"),
        "cwd": root,
        "inherited": {},
        "expected": expected(),
    }))
    .unwrap();
    assert_eq!(
        answer,
        json!({"error": "guard_hook_python_interpreter_unavailable"})
    );
}
