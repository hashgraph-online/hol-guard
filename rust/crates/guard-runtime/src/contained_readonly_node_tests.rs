use super::*;

#[test]
fn only_an_indented_option_line_offers_the_wasm_option() {
    let help = b"Options:\n  --disable-wasm-trap-handler  disable trap-handler-based WebAssembly bound checks\n";
    assert!(offers_wasm_trap_option(help));
    assert!(offers_wasm_trap_option(b"\t--disable-wasm-trap-handler"));
    // Unindented, a longer option, or one carried in prose is not it.
    assert!(!offers_wasm_trap_option(b"--disable-wasm-trap-handler\n"));
    assert!(!offers_wasm_trap_option(
        b"  --disable-wasm-trap-handler-for-workers\n"
    ));
    assert!(!offers_wasm_trap_option(
        b"  see --disable-wasm-trap-handler\n"
    ));
    assert!(!offers_wasm_trap_option(
        b"  --disable-wasm-trap-handler\r\n"
    ));
    assert!(!offers_wasm_trap_option(b""));
}

#[test]
fn only_an_outright_allow_or_a_transform_runs_vitest_route_lets_the_help_run() {
    let response = |value: Value| -> Map<String, Value> {
        let Value::Object(response) = value else {
            unreachable!()
        };
        response
    };
    let outright = response(json!({ "decision": "allow", "policy_action": "allow" }));
    assert!(allowed(&outright, false));
    assert!(allowed(&outright, true));
    // The transform image runs under Vitest's route, so a run that starts
    // one may read the help as that route; no other run may.
    let vitest = response(json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": VITEST_ROUTE.0,
        "required_execution_profile": VITEST_ROUTE.1,
    }));
    assert!(allowed(&vitest, true));
    assert!(!allowed(&vitest, false));
    let mut observed = vitest.clone();
    observed.insert("observe_mode".to_owned(), Value::Bool(true));
    assert!(!allowed(&observed, true));
    for refused in [
        json!({ "decision": "allow", "policy_action": "require-reapproval" }),
        json!({ "decision": "deny", "policy_action": "allow" }),
        json!({ "decision": "allow", "policy_action": "allow", "observe_mode": true }),
        json!({
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_node_test_readonly_containment_required",
            "required_execution_profile": NODE_TEST_PROFILE,
        }),
        json!({}),
    ] {
        assert!(!allowed(&response(refused.clone()), false));
        assert!(!allowed(&response(refused), true));
    }
}

/// A plan for `profile` whose command wrote `settings` in front of the runner.
fn plan(profile: &str, settings: &[(&str, &str)]) -> ReadonlyPlan {
    let mut plan: ReadonlyPlan = serde_json::from_value(json!({
        "profile_version": profile,
        "backend": "bubblewrap",
        "backend_executable": "/usr/bin/bwrap",
        "workspace": "/work",
        "cwd": "/work",
        "executable": "/usr/bin/node",
        "command": ["/usr/bin/node", "--test"],
        "allowed_executables": ["/usr/bin/node"],
        "denied_capabilities": [],
    }))
    .unwrap();
    plan.settings = settings
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    plan
}

fn carried(profile: &str, settled: Option<&str>, settings: &[(&str, &str)]) -> Option<String> {
    let mut environment = BTreeMap::new();
    if let Some(settled) = settled {
        environment.insert("NODE_OPTIONS".to_owned(), settled.to_owned());
    }
    carry_written_options(&plan(profile, settings), &mut environment);
    environment.get("NODE_OPTIONS").cloned()
}

#[test]
fn every_node_route_carries_the_inert_options_the_command_wrote() {
    // The review projects the prefix away and routes the command to the
    // sandbox, so a run that drops it does different work than the one that
    // was reviewed. Vitest is not the only route that has to carry it.
    for profile in [
        NODE_EVAL_PROFILE,
        VITEST_PROFILE,
        NODE_TEST_PROFILE,
        NODE_TOOL_PROFILE,
        NODE_BUILD_PROFILE,
    ] {
        assert_eq!(
            carried(
                profile,
                None,
                &[("NODE_OPTIONS", "--experimental-vm-modules")]
            )
            .as_deref(),
            Some("--experimental-vm-modules"),
            "{profile} dropped the written options",
        );
        // Guard's own options stay in front of the caller's.
        assert_eq!(
            carried(
                profile,
                Some("--disable-wasm-trap-handler"),
                &[("NODE_OPTIONS", "--max-old-space-size=4096")]
            )
            .as_deref(),
            Some("--disable-wasm-trap-handler --max-old-space-size=4096"),
            "{profile} reordered Guard's own options",
        );
    }
}

#[test]
fn only_the_inert_node_options_variable_itself_is_carried() {
    // Re-screened, not trusted: a loader or preload never reaches the run.
    for refused in [
        "--require ./x.js",
        "--import ./x.mjs",
        "--inspect",
        "--max-old-space-size",
        "--max-old-space-size=big",
        "",
    ] {
        assert_eq!(
            carried(NODE_TEST_PROFILE, None, &[("NODE_OPTIONS", refused)]),
            None,
            "carried {refused:?}",
        );
        assert_eq!(
            carried(
                NODE_TEST_PROFILE,
                Some("--disable-wasm-trap-handler"),
                &[("NODE_OPTIONS", refused)]
            )
            .as_deref(),
            Some("--disable-wasm-trap-handler"),
        );
    }
    // Only the spelling Node actually reads is that variable.
    assert_eq!(
        carried(
            NODE_TEST_PROFILE,
            None,
            &[("node_options", "--no-warnings")]
        ),
        None,
    );
    // Another inert setting is carried by the run's own filter, not here.
    assert_eq!(carried(NODE_TEST_PROFILE, None, &[("CI", "1")]), None);
    assert_eq!(carried(NODE_TEST_PROFILE, None, &[]), None);
    // The last value written is the one the shell would have exported.
    assert_eq!(
        carried(
            NODE_TEST_PROFILE,
            None,
            &[
                ("NODE_OPTIONS", "--no-warnings"),
                ("NODE_OPTIONS", "--trace-warnings")
            ]
        )
        .as_deref(),
        Some("--trace-warnings"),
    );
}

/// The sink's own arguments. The route this test drives never asks the
/// resident, so none of these values is read.
fn arguments() -> Arguments {
    Arguments {
        harness: "claude-code".to_owned(),
        guard_home: std::path::PathBuf::from("/guard"),
        workspace: std::path::PathBuf::from("/work"),
        request_file: std::path::PathBuf::from("/work/request.json"),
        request_sha256: String::new(),
        home: std::path::PathBuf::from("/home"),
    }
}

#[test]
fn settling_a_run_is_what_carries_the_written_options() {
    // Driven through `settle` rather than the helper it ends with: the run
    // reaches the wiring, not the helper, and a route that settles its
    // environment without that step starts Node on the caller's variables or
    // drops the ones the reviewed command wrote.
    let arguments = arguments();
    let authority = Authority {
        arguments: &arguments,
        workspace: "/work".to_owned(),
    };
    let plan = plan(
        NODE_TEST_PROFILE,
        &[("NODE_OPTIONS", "--experimental-vm-modules")],
    );
    assert_ne!(
        plan.backend,
        backend::BUBBLEWRAP,
        "the sandbox probe would run"
    );
    let mut environment = BTreeMap::from([
        ("NODE_OPTIONS".to_owned(), "--require ./x.js".to_owned()),
        ("NODE_PATH".to_owned(), "/caller/modules".to_owned()),
        ("CI".to_owned(), "1".to_owned()),
    ]);
    let signals = process::Signals::install();

    settle(
        &Map::new(),
        std::path::Path::new("/work"),
        &authority,
        &plan,
        &mut environment,
        &signals,
        5,
    )
    .expect("the run settles with no probe to make");

    // The caller's own Node variables went; the command's own value is back.
    assert_eq!(
        environment.get("NODE_OPTIONS").map(String::as_str),
        Some("--experimental-vm-modules"),
    );
    assert_eq!(environment.get("NODE_PATH"), None);
    assert_eq!(environment.get("CI").map(String::as_str), Some("1"));
}
