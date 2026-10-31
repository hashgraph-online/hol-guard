use super::*;

const VECTORS: &str = include_str!("../testdata/hook_direct_review/review_request_vectors.json");

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    document["vectors"].as_array().expect("vector list").clone()
}

fn text<'a>(vector: &'a Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is text"))
}

fn environment(vector: &Value) -> BTreeMap<String, String> {
    vector["environment"]
        .as_object()
        .expect("environment")
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().expect("text").to_owned()))
        .collect()
}

fn exact(vector: &Value) -> ExactKeys<'_> {
    if let Some(token) = vector["exact"]["token"].as_str() {
        ExactKeys::Token(token)
    } else if let Some(reason) = vector["exact"]["once_only"].as_str() {
        ExactKeys::OnceOnly(reason)
    } else {
        ExactKeys::Neither
    }
}

fn input<'a>(vector: &'a Value, environment: &'a BTreeMap<String, String>) -> RequestInput<'a> {
    RequestInput {
        harness: text(vector, "harness"),
        payload: vector["payload"].as_object().expect("payload"),
        workspace: text(vector, "workspace"),
        home_dir: text(vector, "home_dir"),
        environment,
        host_cwd: vector["host_cwd"].as_str(),
        request_id: text(vector, "request_id"),
        approval_center_url: text(vector, "approval_center_url"),
        review_binding: vector["review_binding"].as_str(),
        exact: exact(vector),
        hint: None,
    }
}

/// The vectors were recorded where `os.path.expanduser` reads `HOME`; the
/// Windows expansion from `USERPROFILE` has its own CPython comparison below.
#[cfg(unix)]
#[test]
fn envelope_query_matches_the_daemon() {
    for vector in vectors() {
        let name = text(&vector, "name");
        let environment = environment(&vector);
        let input = input(&vector, &environment);
        let query = envelope_query(&input).expect(name);
        let expected = &vector["query"];
        assert_eq!(query.workspace, text(expected, "workspace"), "{name}");
        assert_eq!(query.home_dir, text(expected, "home_dir"), "{name}");
        assert_eq!(
            query.devin_project_dir,
            expected["devin_project_dir"].as_str(),
            "{name}"
        );
        assert_eq!(query.path_env, expected["path_env"].as_str(), "{name}");
        let host = &expected["host"];
        assert_eq!(
            query.host.tilde_home.as_deref(),
            host["tilde_home"].as_str(),
            "{name}"
        );
        assert_eq!(
            query.host.default_home.as_deref(),
            host["default_home"].as_str(),
            "{name}"
        );
        assert_eq!(query.host.cwd.as_deref(), host["cwd"].as_str(), "{name}");
        assert_eq!(text(expected, "harness"), input.harness, "{name}");
        assert_eq!(text(expected, "event_name"), "PreToolUse", "{name}");
        // The daemon's query keeps the hook's key order; the resident's map
        // is sorted, so compare the canonical forms.
        let canonical = |wire: &Value| OValue::from_wire(wire).expect("wire").canonical_json();
        assert_eq!(
            canonical(&tagged(&vector["payload"])),
            canonical(&expected["payload"]),
            "{name}"
        );
    }
}

#[test]
fn request_matches_the_daemon() {
    for vector in vectors() {
        let name = text(&vector, "name");
        let environment = environment(&vector);
        let input = input(&vector, &environment);
        let result = vector["result"].as_object().expect("result");
        let receipt = Some(&vector["receipt"]).filter(|receipt| !receipt.is_null());
        let request = finish(&input, result, receipt, vector["envelope"].clone());
        if vector["hint_candidate"].as_bool() == Some(true) {
            assert_eq!(request, None, "{name}");
        } else {
            assert_eq!(request.as_ref(), Some(&vector["request"]), "{name}");
        }
    }
}

#[test]
fn hint_candidates_match_the_daemon() {
    for vector in vectors() {
        let payload = vector["payload"].as_object().expect("payload");
        let result = vector["result"].as_object().expect("result");
        assert_eq!(
            allow_hint_candidate(payload, result),
            vector["hint_candidate"].as_bool(),
            "{}",
            text(&vector, "name")
        );
    }
}

#[cfg(unix)]
#[test]
fn the_adapter_answers_a_shell_review() {
    let vector = vectors().into_iter().next().expect("a vector");
    let environment = environment(&vector);
    let input = input(&vector, &environment);
    let result = vector["result"].as_object().expect("result");
    let request = build(&input, result, None).expect("request");
    let envelope = &request["action_envelope_json"];
    assert_eq!(envelope["action_type"], "shell_command");
    assert_eq!(envelope["pre_execution_result"], "review");
    assert_eq!(envelope["exact_context_token"], "exact-token-1");
}

/// Which stage answers `None` for the first vector after `edit`.
#[cfg(unix)]
#[derive(Debug, PartialEq)]
enum Deferred {
    Query,
    Adapter,
    Finish,
    No,
}

#[cfg(unix)]
fn deferred_at(edit: impl Fn(&mut Value, &mut BTreeMap<String, String>)) -> Deferred {
    let mut vector = vectors().into_iter().next().expect("a vector");
    let mut environment = environment(&vector);
    edit(&mut vector, &mut environment);
    let input = input(&vector, &environment);
    let result = vector["result"].as_object().expect("result");
    let receipt = Some(&vector["receipt"]).filter(|receipt| !receipt.is_null());
    let Some(query) = envelope_query(&input) else {
        return Deferred::Query;
    };
    if adapter_envelope(&input, &query).is_none() {
        return Deferred::Adapter;
    }
    match finish(&input, result, receipt, vector["envelope"].clone()) {
        None => Deferred::Finish,
        Some(_) => Deferred::No,
    }
}

#[cfg(unix)]
#[test]
fn unanswerable_shapes_defer() {
    assert_eq!(deferred_at(|_, _| {}), Deferred::No);
    let home = deferred_at(|_, environment| {
        environment.remove("HOME");
    });
    assert_eq!(home, Deferred::Query);
    assert_eq!(
        deferred_at(|vector, _| vector["workspace"] = json!("")),
        Deferred::Query
    );
    let servers =
        deferred_at(|vector, _| vector["payload"]["mcpServers"] = json!({"b": {}, "a": {}}));
    assert_eq!(servers, Deferred::Adapter);
    let cline = deferred_at(|vector, _| vector["harness"] = json!("cline"));
    assert_eq!(cline, Deferred::Adapter);
    let oversize = deferred_at(|vector, _| {
        vector["payload"]["tool_input"]["description"] = json!("x".repeat(MAX_PAYLOAD_BYTES));
    });
    assert_eq!(oversize, Deferred::Adapter);
    for edit in [
        (|vector: &mut Value| vector["result"]["reason"] = json!(["not", "text"]))
            as fn(&mut Value),
        |vector| vector["envelope"]["action_type"] = json!("teleport"),
        |vector| vector["envelope"]["action_id"] = json!(""),
        |vector| vector["envelope"]["target_paths"] = json!([1]),
        |vector| vector["envelope"]["schema_version"] = json!("1"),
        |vector| vector["envelope"]["extra"] = json!(null),
        |vector| {
            vector["envelope"]
                .as_object_mut()
                .expect("envelope")
                .remove("script_name");
        },
        |vector| {
            vector["result"]["command_extensions"] = json!({});
            vector["receipt"] = json!({"payload_kind": "pre_tool"});
        },
    ] {
        assert_eq!(deferred_at(|vector, _| edit(vector)), Deferred::Finish);
    }
}

#[test]
fn command_extension_reviews_need_the_typed_binding() {
    let result = Object::new();
    let mut extension_result = Object::new();
    extension_result.insert("command_extensions".to_owned(), json!({}));
    let bound = json!({
        "policy_digest": "p",
        "rule_digest": "r",
        "runtime_identity": "i",
        "command_extensions": {"uncertainty_count": 0},
    });
    assert!(policy_binding_valid(&result, None));
    assert!(!policy_binding_valid(&extension_result, None));
    assert!(policy_binding_valid(&extension_result, Some(&bound)));
    let mut uncertain = bound.clone();
    uncertain["command_extensions"]["uncertainty_count"] = json!(-1);
    assert!(!policy_binding_valid(&extension_result, Some(&uncertain)));
    let mut flagged = bound.clone();
    flagged["command_extensions"]["uncertainty_count"] = json!(false);
    assert!(!policy_binding_valid(&result, Some(&flagged)));
    let mut unsigned = bound;
    unsigned["rule_digest"] = json!(null);
    assert!(!policy_binding_valid(&extension_result, Some(&unsigned)));
}

#[test]
fn false_and_float_zero_uncertainty_are_hint_candidates() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "ls"}});
    let payload = payload.as_object().expect("payload");
    for count in [json!(false), json!(0.0)] {
        let result = json!({
            "minimum_action": "review",
            "reason_code": "native_command_review_required",
            "command_extensions": {"binding": {"uncertainty_count": count, "observations_digest": "d"}},
        });
        let result = result.as_object().expect("result");
        assert_eq!(allow_hint_candidate(payload, result), Some(true));
    }
}

#[test]
fn the_working_directory_cursor_sends_is_a_hint_candidate() {
    // Cursor copies the hook's cwd into every shell tool input it forwards,
    // so rejecting that key left Cursor reviews with no Extension to name.
    for key in ["working_directory", "workingDirectory"] {
        let payload = json!({"tool_name": "Bash", "tool_input": {"command": "ls", key: "/w"}});
        let payload = payload.as_object().expect("payload");
        let result = json!({
            "minimum_action": "review",
            "reason_code": "native_command_review_required",
            "command_extensions": {"binding": {"uncertainty_count": 0, "observations_digest": "d"}},
        });
        let result = result.as_object().expect("result");
        assert_eq!(allow_hint_candidate(payload, result), Some(true), "{key}");
    }
}

#[test]
fn any_rule_uncertain_observations_are_hint_candidates() {
    let payload = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "docker version --format '{{.Server.Version}}'"},
    });
    let payload = payload.as_object().expect("payload");
    for (extension_id, rule_id) in [
        (
            "command.container-runtime",
            "command.container-runtime.docker-sensitive",
        ),
        (
            "command.kubernetes-secrets",
            "command.kubernetes-secrets.secret-read",
        ),
        (
            "command.data-protection",
            "command.data-protection.file-upload",
        ),
    ] {
        let result = json!({
            "minimum_action": "review",
            "reason_code": "native_command_review_required",
            "command_extensions": {
                "binding": {"uncertainty_count": 1, "observations_digest": "d"},
                "observations": [
                    {
                        "extension_id": extension_id,
                        "rule_id": rule_id,
                        "uncertainty_reasons": ["matcher-failure"],
                    }
                ],
            },
        });
        let result = result.as_object().expect("result");
        assert_eq!(
            allow_hint_candidate(payload, result),
            Some(true),
            "{rule_id}"
        );
    }
    // Ruleless permission uncertainty cannot be settled by any one
    // permission, so it is never a hint candidate.
    let result = json!({
        "minimum_action": "review",
        "reason_code": "native_command_review_required",
        "command_extensions": {
            "binding": {"uncertainty_count": 1, "observations_digest": "d"},
            "observations": [],
            "permission_observations": [
                {"uncertainty_reasons": ["matcher-failure"]}
            ],
        },
    });
    let result = result.as_object().expect("result");
    assert_eq!(allow_hint_candidate(payload, result), Some(false));
    // A fixed PreTool floor reviews whatever the extensions say, so an
    // extension Allow can never settle it and it is not a hint candidate.
    let result = json!({
        "minimum_action": "review",
        "reason_code": "native_sensitive_access_review",
        "command_extensions": {
            "binding": {"uncertainty_count": 0, "observations_digest": "d"},
        },
    });
    let result = result.as_object().expect("result");
    assert_eq!(allow_hint_candidate(payload, result), Some(false));
}

#[cfg(windows)]
#[test]
fn windows_expanded_home_matches_cpython() {
    for profile in [
        r"C:\Users\Guard Tester",
        r"C:\Users\Guard Tester\",
        "~guard",
    ] {
        let output = std::process::Command::new("python")
            .args(["-c", "import os; print(os.path.expanduser('~'), end='')"])
            .env("USERPROFILE", profile)
            .output()
            .expect("python runs");
        assert!(output.status.success(), "{profile:?}");
        let cpython = String::from_utf8(output.stdout).expect("utf-8");
        let environment = BTreeMap::from([("USERPROFILE".to_owned(), profile.to_owned())]);
        assert_eq!(expanded_home(&environment), Some(cpython), "{profile:?}");
    }
    // Without `USERPROFILE` ntpath joins `HOMEDRIVE` and `HOMEPATH`.
    for (drive, path) in [
        (Some("C:"), r"\Users\guard"),
        (None, r"\Users\guard"),
        (Some("c:"), "/Users/guard"),
        (Some("C:"), "Users"),
    ] {
        let mut command = std::process::Command::new("python");
        command
            .args(["-c", "import os; print(os.path.expanduser('~'), end='')"])
            .env_remove("USERPROFILE")
            .env("HOMEPATH", path);
        let mut environment = BTreeMap::from([("HOMEPATH".to_owned(), path.to_owned())]);
        match drive {
            Some(drive) => {
                command.env("HOMEDRIVE", drive);
                environment.insert("HOMEDRIVE".to_owned(), drive.to_owned());
            }
            None => {
                command.env_remove("HOMEDRIVE");
            }
        }
        let output = command.output().expect("python runs");
        assert!(output.status.success(), "{drive:?} {path:?}");
        let cpython = String::from_utf8(output.stdout).expect("utf-8");
        assert_eq!(
            expanded_home(&environment),
            Some(cpython),
            "{drive:?} {path:?}"
        );
    }
    // A UNC home share goes through `splitroot`; the daemon joins it.
    let environment = BTreeMap::from([
        ("HOMEDRIVE".to_owned(), r"\\srv\share".to_owned()),
        ("HOMEPATH".to_owned(), r"\".to_owned()),
    ]);
    assert_eq!(expanded_home(&environment), None);
}

/// Expected values are CPython's `ntpath.join(drive, path)`.
#[test]
fn home_drive_join_is_ntpath_join_or_left_to_the_daemon() {
    for (drive, path, joined) in [
        ("C:", r"\Users\guard", Some(r"C:\Users\guard")),
        ("", r"\Users\guard", Some(r"\Users\guard")),
        ("c:", "/Users/guard", Some("c:/Users/guard")),
        ("C:", "Users", Some("C:Users")),
        ("C:", "", Some("C:")),
        ("", "", Some("")),
        (r"\\srv\share", r"\", None),
        ("C:", r"\\srv\share", None),
        ("C:", r"D:\x", None),
        ("CD", r"\x", None),
    ] {
        assert_eq!(
            join_home_drive(drive, path).as_deref(),
            joined,
            "{drive:?} {path:?}"
        );
    }
}
