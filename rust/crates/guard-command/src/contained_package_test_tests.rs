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
        crate::contained_argv::evaluate(
            "package_test_command",
            &json!({"command": ["npm", "test"]})
        )
        .unwrap(),
        json!({"value": true})
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
