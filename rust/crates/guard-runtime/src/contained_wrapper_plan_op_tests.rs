use super::*;
use guard_command::pretool::CONTAINED_WRAPPER_PLAN_UNSUPPORTED;
use guard_contracts::CONTAINED_WRAPPER_PLAN_REQUEST_SCHEMA;

fn request(command: &str, workspace: &std::path::Path) -> ContainedWrapperPlanRequestV1 {
    ContainedWrapperPlanRequestV1 {
        schema: CONTAINED_WRAPPER_PLAN_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        command: command.to_owned(),
        workspace: workspace.to_string_lossy().into_owned(),
        cwd: Some(workspace.to_string_lossy().into_owned()),
        home_dir: None,
        project_root_query: None,
    }
}

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("temporary workspace")
}

#[test]
fn a_plain_command_is_not_wrapped_and_is_not_refused() {
    // Nothing to peel, so the sink carries on to its other routes rather than
    // running the text whole in its sandbox.
    let root = workspace();
    let answer = evaluate(&request("pytest -q", root.path()));
    assert_eq!(answer["plan"], Value::Null);
    assert_eq!(answer["refusal"], Value::Null);
}

#[test]
fn a_head_filter_is_peeled_with_its_count() {
    let root = workspace();
    let answer = evaluate(&request("pytest -q | head -n 20", root.path()));
    let plan = &answer["plan"];
    assert_eq!(plan["core"], Value::from("pytest -q"));
    assert_eq!(plan["output"]["kind"], Value::from("head"));
    assert_eq!(plan["output"]["count"], Value::from(20));
    assert_eq!(plan["output"]["merge_stderr"], Value::from(false));
    assert_eq!(answer["refusal"], Value::Null);
}

#[test]
fn a_short_head_flag_reaches_the_sink_as_the_same_count() {
    // The sink applies the number, not the spelling, so `-20` and `-n 20`
    // must arrive identically. The Python peel normalized them too.
    let root = workspace();
    let short = evaluate(&request("pytest -q | head -20", root.path()));
    let long = evaluate(&request("pytest -q | head -n 20", root.path()));
    assert_eq!(short["plan"]["output"], long["plan"]["output"]);
}

#[test]
fn a_merged_producer_reports_the_merge_without_a_filter() {
    let root = workspace();
    let answer = evaluate(&request("pytest -q 2>&1", root.path()));
    assert_eq!(answer["plan"]["core"], Value::from("pytest -q"));
    assert_eq!(answer["plan"]["output"]["kind"], Value::from("all"));
    assert_eq!(answer["plan"]["output"]["merge_stderr"], Value::from(true));
}

#[test]
fn a_status_echo_reports_its_label() {
    let root = workspace();
    let answer = evaluate(&request("pytest -q; echo \"exit=$?\"", root.path()));
    assert_eq!(answer["plan"]["core"], Value::from("pytest -q"));
    assert_eq!(
        answer["plan"]["output"]["status_label"],
        Value::from("exit=")
    );
}

#[test]
fn an_unsupported_filter_is_refused_rather_than_left_alone() {
    // The Python peel raised here, and the sink answered that by running the
    // command whole in its sandbox. A silent `None` would instead send the
    // command down the sink's other routes, which is a different decision.
    let root = workspace();
    let answer = evaluate(&request("pytest -q | xargs rm", root.path()));
    assert_eq!(answer["plan"], Value::Null);
    assert_eq!(
        answer["refusal"],
        Value::from(CONTAINED_WRAPPER_PLAN_UNSUPPORTED)
    );
}

#[test]
fn a_cd_outside_the_workspace_is_refused_without_a_home() {
    // No home means no sibling repository can be proved, so the target is
    // outside every root the sink may rebase to.
    let root = workspace();
    let other = workspace();
    let mut req = request(
        &format!("cd {} && pytest -q", other.path().display()),
        root.path(),
    );
    req.home_dir = None;
    let answer = evaluate(&req);
    assert_eq!(answer["plan"], Value::Null);
    assert_eq!(
        answer["refusal"],
        Value::from(CONTAINED_WRAPPER_PLAN_UNSUPPORTED)
    );
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let root = workspace();
    let mut req = request("pytest -q", root.path());
    req.schema = "guard-other-request.v1".to_owned();
    assert_eq!(
        refusal(&req),
        Some("native_contained_wrapper_plan_schema_mismatch")
    );
}

#[test]
fn a_request_without_a_workspace_is_refused() {
    let root = workspace();
    let mut req = request("pytest -q", root.path());
    req.workspace = String::new();
    assert_eq!(
        refusal(&req),
        Some("native_contained_wrapper_plan_missing_workspace")
    );
}

#[test]
fn an_unquoted_backslash_is_read_the_way_the_classifier_reads_it() {
    // The peel and the classifier have to name the same command. The host
    // decides whether an unquoted `\` separates a path or escapes the next
    // character, so the core text follows that same reading.
    let root = workspace();
    let answer = evaluate(&request(
        r"cargo test --manifest-path C:\repo\Cargo.toml | head -n 5",
        root.path(),
    ));
    let expected = if cfg!(windows) {
        r"cargo test --manifest-path 'C:\repo\Cargo.toml'"
    } else {
        "cargo test --manifest-path C:repoCargo.toml"
    };
    assert_eq!(answer["plan"]["core"], Value::from(expected));
}

#[test]
fn the_result_binds_to_its_request() {
    let root = workspace();
    let req = request("pytest -q | head -n 5", root.path());
    let encoded = evaluate_contained_wrapper_plan_request(&req).expect("response");
    let result: Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(result["status"], Value::from("ok"));
    assert_eq!(result["request_id"], Value::from("req-1"));
    assert_eq!(
        result["request_sha256"],
        Value::from(
            request_digest_with_limit(&req, CONTAINED_WRAPPER_PLAN_MAX_BYTES).expect("digest")
        )
    );
}

#[test]
fn a_directory_question_is_answered_beside_the_peel() {
    // The sink asks whether a run root is a sibling repository before it
    // knows whether the command carries a wrapper, so the answer does not
    // depend on one being peeled.
    let home = workspace();
    let checkout = home.path().join("beside");
    std::fs::create_dir_all(checkout.join(".git")).expect("checkout");
    let root = workspace();
    let mut req = request("pytest -q", root.path());
    req.home_dir = Some(home.path().to_string_lossy().into_owned());
    req.project_root_query = Some(checkout.to_string_lossy().into_owned());
    let answer = evaluate(&req);
    assert_eq!(answer["plan"], Value::Null);
    // The answer comes back in the caller's spelling, because the sink compares
    // it with the run root it asked about.
    assert_eq!(
        answer["project_root"],
        Value::from(checkout.to_string_lossy().into_owned())
    );
}

#[test]
fn the_walk_stops_before_the_base_it_climbs_from() {
    // Home itself holding a `.git` is not a sibling repository, so a directory
    // under it whose own tree carries no checkout has no root at all.
    let home = workspace();
    std::fs::create_dir_all(home.path().join(".git")).expect("home checkout");
    let plain = home.path().join("notes");
    std::fs::create_dir_all(&plain).expect("directory");
    let root = workspace();
    let mut req = request("pytest -q", root.path());
    req.home_dir = Some(home.path().to_string_lossy().into_owned());
    req.project_root_query = Some(plain.to_string_lossy().into_owned());
    assert_eq!(evaluate(&req)["project_root"], Value::Null);
}

#[test]
fn a_directory_in_no_repository_is_no_sibling_root() {
    let home = workspace();
    let plain = home.path().join("notes");
    std::fs::create_dir_all(&plain).expect("directory");
    let root = workspace();
    let mut req = request("pytest -q", root.path());
    req.home_dir = Some(home.path().to_string_lossy().into_owned());
    req.project_root_query = Some(plain.to_string_lossy().into_owned());
    assert_eq!(evaluate(&req)["project_root"], Value::Null);
}
