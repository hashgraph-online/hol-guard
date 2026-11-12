use super::*;
use crate::contained_argv::{bun_test_invocation, bun_test_script_invocation, inline_eval};
use crate::restricted_pytest::contained_tests::{fixture, plant_runtime};
use crate::restricted_pytest::evaluate;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn a_sink_asks_about_a_planned_bun_run_as_the_caller_spelled_it() {
    let bun = "/opt/homebrew/bin/bun";
    for caller in [
        argv(&[bun, "-e", "console.log(1)"]),
        argv(&[bun, "--print", "1"]),
        argv(&[bun, "test"]),
        argv(&[bun, "calc.test.ts"]),
    ] {
        let planned = contained_command(Path::new(bun), &caller[1..]);
        assert_ne!(planned, caller);
        assert_eq!(planned_route_argv(&planned), caller);
    }
    // The resident routes the caller's spelling; the planned argv with the
    // flag in front is not a route it would grant, so a sink that asked about
    // it would refuse every contained Bun run.
    let eval = argv(&[bun, "-e", "1"]);
    assert!(inline_eval(&eval).unwrap());
    assert!(!inline_eval(&contained_command(Path::new(bun), &eval[1..])).unwrap_or(false));
    let test = argv(&[bun, "test"]);
    assert!(bun_test_invocation(&test));
    assert!(!bun_test_invocation(&contained_command(
        Path::new(bun),
        &test[1..]
    )));
    let file = argv(&[bun, "calc.test.ts"]);
    assert!(bun_test_script_invocation(&file));
    assert_eq!(
        planned_route_argv(&contained_command(Path::new(bun), &file[1..])),
        file
    );
}

#[test]
fn any_other_planned_argv_is_asked_about_unchanged() {
    for command in [
        argv(&["/usr/bin/node", "--no-env-file", "-e", "1"]),
        argv(&["/opt/homebrew/bin/bun", "-e", "--no-env-file"]),
        argv(&["/opt/homebrew/bin/bunx", "--no-env-file", "test"]),
        argv(&["/opt/homebrew/bin/bun"]),
        argv(&[]),
    ] {
        assert_eq!(planned_route_argv(&command), command);
    }
}

#[test]
fn bun_inline_eval_uses_the_node_eval_profile_with_an_installer_image() {
    let fixture = fixture("guard-bun-eval");
    let home = fixture.0.join("caller-home");
    let bun = home.join(".bun/bin/bun");
    let workspace = fixture.0.join("project");
    fs::create_dir_all(bun.parent().unwrap()).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    fs::write(&bun, b"\x7fELFnative-fixture").unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let mut launch = json!({"command":[bun,"-e","console.log(1)"],"workspace":workspace,
        "cwd":workspace,"home":home,"platform":"darwin","backend_executable":"/usr/bin/true",
        "search_path":""});
    let result = evaluate("prepare_inline", &launch);
    let plan = &result["value"];
    assert_eq!(plan["profile_version"], "node-eval-readonly-v1", "{plan}");
    // Bun's automatic `.env` load is off: the profile denies reading it, and
    // Bun 1.4 aborts the whole run when that load is refused.
    assert_eq!(
        plan["command"],
        json!([bun, "--no-env-file", "-e", "console.log(1)"])
    );
    assert_eq!(
        plan["denied_capabilities"],
        json!([
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "workspace-write",
            "workspace-credential-read",
            "unapproved-process-exec",
            "privileged-operation"
        ])
    );
    launch["command"] = json!([bun, "--print", "1"]);
    assert_eq!(
        evaluate("prepare_inline", &launch)["value"]["command"],
        json!([bun, "--no-env-file", "--print", "1"])
    );
    // `bun test` and the single test file Bun runs on its own take the Node
    // test profile with the same automatic `.env` load turned off.
    launch["command"] = json!([bun, "test"]);
    let plan = evaluate("prepare_node", &launch)["value"].clone();
    assert_eq!(plan["profile_version"], "node-test-readonly-v1", "{plan}");
    assert_eq!(plan["command"], json!([bun, "--no-env-file", "test"]));
    fs::write(workspace.join("calc.test.ts"), "").unwrap();
    launch["command"] = json!([bun, "calc.test.ts"]);
    assert_eq!(
        evaluate("prepare_node", &launch)["value"]["command"],
        json!([bun, "--no-env-file", "calc.test.ts"])
    );
    launch["command"] = json!([bun, "--print", "1"]);
    // Another home's installer, a repository copy, a writable or script image.
    let invalid = |launch: &Value| {
        assert_eq!(
            evaluate("prepare_inline", launch)["reason_code"],
            "inline_eval_invalid_command",
            "{launch}"
        );
    };
    let other = fixture.0.join("other-home");
    fs::create_dir(&other).unwrap();
    launch["home"] = json!(other);
    invalid(&launch);
    launch["home"] = json!(home);
    let local = workspace.join("bun");
    fs::copy(&bun, &local).unwrap();
    launch["command"] = json!([local, "-e", "1"]);
    invalid(&launch);
    launch["command"] = json!([bun, "-e", "1"]);
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o775)).unwrap();
    invalid(&launch);
    fs::write(&bun, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    invalid(&launch);
    launch["command"] = json!([bun, "run", "-e", "1"]);
    invalid(&launch);
}

#[test]
fn bun_installed_by_a_version_manager_runs_contained() {
    let fixture = fixture("guard-manager-bun");
    let home = fixture.0.join("caller-home");
    let workspace = fixture.0.join("project");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    let launch = |bun: &Path| {
        evaluate(
            "prepare_inline",
            &json!({"command":[bun,"-e","console.log(1)"],"workspace":workspace,"cwd":workspace,
                "home":home,"platform":"darwin","backend_executable":"/usr/bin/true",
                "search_path":""}),
        )
    };
    // Bun's own installer directory, and the managers that install Bun.
    for relative in [
        ".bun/bin/bun",
        ".asdf/installs/bun/1.1.30/bin/bun",
        ".local/share/mise/installs/bun/1.1.30/bin/bun",
    ] {
        let bun = home.join(relative);
        plant_runtime(&bun);
        assert_eq!(
            launch(&bun)["value"]["executable"],
            json!(bun),
            "{relative}"
        );
    }
    // Guard's own shim directory is still refused, so a shim can never answer
    // for Bun inside containment.
    let shim = home.join(".hol-guard/package-shims/bin/bun");
    plant_runtime(&shim);
    assert_eq!(
        launch(&shim)["reason_code"],
        json!("inline_eval_invalid_command")
    );
}
