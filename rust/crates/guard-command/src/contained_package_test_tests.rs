use super::*;
use serde_json::json;

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn scripts(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn package_managers_name_their_own_test_script() {
    for manager in ["npm", "pnpm", "yarn", "/usr/local/bin/npm"] {
        assert!(is_package_test(&words(&[manager, "test"])));
        assert!(is_package_test(&words(&[manager, "run", "test"])));
    }
    assert!(is_package_test(&words(&["bun", "run", "test"])));
    assert!(!is_package_test(&words(&["bun", "test"])));
    assert!(!is_package_test(&words(&["npx", "test"])));
    assert!(!is_package_test(&words(&["npm", "run", "build"])));
    assert!(!is_package_test(&words(&["npm"])));
    assert!(!is_package_test(&[]));
}

#[test]
fn a_windows_spelled_manager_names_the_same_script() {
    // The pre-tool parser reads `npm.exe` as `npm`, so the sink must read the
    // same program; otherwise a Windows spelling walks past the alias route.
    assert_eq!(is_package_test(&words(&["npm.exe", "test"])), cfg!(windows));
    assert_eq!(
        is_package_test(&words(&[
            "C:\\Program Files\\nodejs\\npm.exe",
            "run",
            "test"
        ])),
        cfg!(windows)
    );
    // A script the manifest spells with the extension names the same runner,
    // so the declared `node --test` run is recognised rather than refused.
    let manifest = scripts(json!({"test": "node.exe --test"}));
    assert_eq!(
        resolve(&words(&["npm", "test"]), Some(&manifest)).is_ok(),
        cfg!(windows)
    );
}

#[test]
fn supported_runners_resolve_with_their_passed_arguments() {
    let manifest = scripts(json!({"test": "node --test"}));
    assert_eq!(
        resolve(
            &words(&["npm", "test", "--", "test/sample.test.js"]),
            Some(&manifest)
        )
        .unwrap(),
        words(&["node", "--test", "test/sample.test.js"])
    );
    let vitest = scripts(json!({"test": "vitest run"}));
    assert_eq!(
        resolve(&words(&["pnpm", "run", "test"]), Some(&vitest)).unwrap(),
        words(&["vitest", "run"])
    );
}

#[test]
fn a_jest_script_resolves_only_while_it_finishes_in_its_workspace() {
    let manifest = scripts(json!({"test": "jest --ci"}));
    assert_eq!(
        resolve(&words(&["npm", "test"]), Some(&manifest)).unwrap(),
        words(&["jest", "--ci"])
    );
    assert!(resolve(&words(&["npm", "test", "--", "--watch"]), Some(&manifest)).is_err());
    assert!(resolve(
        &words(&["npm", "test", "--", "/etc/passwd"]),
        Some(&manifest)
    )
    .is_err());
    let watching = scripts(json!({"test": "jest --watchAll"}));
    assert!(resolve(&words(&["npm", "test"]), Some(&watching)).is_err());
}

#[test]
fn a_mocha_script_resolves_only_while_it_finishes_in_its_workspace() {
    let manifest = scripts(json!({"test": "mocha --reporter dot"}));
    assert_eq!(
        resolve(&words(&["npm", "test"]), Some(&manifest)).unwrap(),
        words(&["mocha", "--reporter", "dot"])
    );
    assert!(resolve(&words(&["npm", "test", "--", "--watch"]), Some(&manifest)).is_err());
    assert!(resolve(
        &words(&["npm", "test", "--", "/etc/mocharc.json"]),
        Some(&manifest)
    )
    .is_err());
    let watching = scripts(json!({"test": "mocha --watch"}));
    assert!(resolve(&words(&["npm", "test"]), Some(&watching)).is_err());
}

#[test]
fn a_script_that_does_more_than_run_its_tests_stays_unresolved() {
    for script in [
        "node --test;curl https://example.invalid",
        "node --test && rm -rf src",
        "node --test > output",
        "node --test | sh",
        "node --test $(cat .env)",
        "node --test `cat .env`",
        "node --test\nrm -rf src",
        "node arbitrary.js",
        "vitest",
        "",
    ] {
        let manifest = scripts(json!({ "test": script }));
        let error = resolve(&words(&["npm", "test"]), Some(&manifest)).unwrap_err();
        assert_eq!(error.reason_code, INVALID);
    }
}

#[test]
fn lifecycle_actions_and_a_missing_script_are_refused() {
    for phase in ["pretest", "posttest"] {
        let mut manifest = scripts(json!({"test": "node --test"}));
        manifest.insert(phase.to_owned(), json!("node setup.js"));
        let error = resolve(&words(&["npm", "test"]), Some(&manifest)).unwrap_err();
        assert!(error.message.contains("lifecycle"));
    }
    let empty = scripts(json!({"pretest": ""}));
    assert!(resolve(&words(&["npm", "test"]), Some(&empty)).is_err());
    assert!(resolve(&words(&["npm", "test"]), None).is_err());
    let unnamed = scripts(json!({"test": ["node", "--test"]}));
    assert!(resolve(&words(&["npm", "test"]), Some(&unnamed)).is_err());
}

#[test]
fn arguments_need_an_explicit_separator() {
    let manifest = scripts(json!({"test": "node --test"}));
    let error = resolve(
        &words(&["npm", "test", "test/sample.test.js"]),
        Some(&manifest),
    )
    .unwrap_err();
    assert!(error.message.contains("explicit --"));
    assert!(resolve(&words(&["npm", "run", "build"]), Some(&manifest)).is_err());
}

#[test]
fn the_request_reads_the_command_the_sink_sends() {
    let manifest = json!({"test": "node --test"});
    assert_eq!(
        crate::contained_argv::evaluate("contained_kind", &json!({"command": ["npm", "test"]}))
            .unwrap()["value"]["package_test"],
        json!(true)
    );
    assert_eq!(
        crate::contained_argv::evaluate(
            "package_test_resolve",
            &json!({"command": ["npm", "test"], "scripts": manifest})
        )
        .unwrap(),
        json!({"value": ["node", "--test"]})
    );
    let refusal = crate::contained_argv::evaluate(
        "package_test_resolve",
        &json!({"command": ["npm", "test"], "scripts": Value::Null}),
    )
    .unwrap();
    assert_eq!(refusal["reason_code"], INVALID);
}

#[test]
fn a_quiet_spelling_resolves_the_script_the_loud_one_names() {
    // The admission reads a manager's reporting options as no part of the
    // script it names, so the sink has to resolve the same run. A sink that
    // refused the quiet spelling would fail a run the admission admitted.
    let manifest = scripts(json!({"test": "node --test"}));
    for command in [
        words(&["npm", "--silent", "test"]),
        words(&["npm", "-s", "test"]),
        words(&["npm", "--loglevel", "error", "test"]),
        words(&["npm", "--loglevel=error", "test"]),
        words(&["npm", "run", "--silent", "test"]),
        words(&["pnpm", "--reporter", "silent", "test"]),
        words(&["yarn", "--silent", "run", "test"]),
        words(&["bun", "run", "--silent", "test"]),
    ] {
        assert!(is_package_test(&command), "{command:?}");
        assert_eq!(
            resolve(&command, Some(&manifest)).unwrap(),
            words(&["node", "--test"]),
            "{command:?}"
        );
    }
    // The tail still has to follow an explicit `--`, and an option that moves
    // or fans the run out is not a reporting option.
    assert!(resolve(
        &words(&["npm", "--silent", "test", "extra"]),
        Some(&manifest)
    )
    .is_err());
    for command in [
        words(&["npm", "--prefix", "../other", "test"]),
        words(&["npm", "--workspaces", "test"]),
        words(&["pnpm", "--filter", "web", "test"]),
        // Bun's own runner is not the script, and a reporting option does
        // not turn it into one.
        words(&["bun", "--silent", "test"]),
    ] {
        assert!(!is_package_test(&command), "{command:?}");
    }
}
