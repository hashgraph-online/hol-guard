use serde_json::{json, Value};

use super::run_command;
use crate::runtime_identity_range::SemVer;

const OLD_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn artifact(id: &str, family: &str, version: &str, hash: Option<&str>, assurance: &str) -> Value {
    json!({
        "artifact_id": id, "family": family, "vendor": "nodejs", "version": version,
        "build_id": null, "os": "linux", "arch": "x64", "executable_sha256": hash,
        "component_identity_sha256": null, "identity_assurance": assurance,
    })
}

fn node_advisory() -> Value {
    json!({
        "advisory_id": "GHSA-node-1", "family": "node", "vendor": "nodejs",
        "version_scheme": "semver",
        "ranges": [{"introduced": "20.0.0", "fixed": "20.11.1"}, {"introduced": "22.0.0", "fixed": "22.4.1"}],
    })
}

fn instance(id: &str, artifact: &str, pid: u32, state: &str, coverage: &str) -> Value {
    json!({
        "instance_id": id, "boot_identity": "boot-1", "pid": pid, "start_identity": format!("start-{pid}"),
        "artifact_id": artifact, "location_id": "loc-1", "state": state, "coverage": coverage,
    })
}

fn location(artifact: &str) -> Value {
    json!({"location_id": "loc-1", "artifact_id": artifact, "state": "present"})
}

fn assess(request: Value) -> Value {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

fn error(request: Value) -> String {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], false, "{reply}");
    reply["error"].as_str().unwrap().to_owned()
}

fn verdict(result: &Value) -> (&str, Vec<&str>) {
    let row = &result["advisories"][0];
    let reasons = row["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    (row["verdict"].as_str().unwrap(), reasons)
}

fn match_status(result: &Value, artifact_index: usize) -> (&str, &str) {
    let row = &result["artifacts"][artifact_index]["matches"][0];
    (
        row["status"].as_str().unwrap(),
        row["reason"].as_str().unwrap(),
    )
}

#[test]
fn semver_orders_prereleases_before_release() {
    let parse = |text| SemVer::parse(text).unwrap();
    assert!(parse("22.4.1-rc.1") < parse("22.4.1"));
    assert!(parse("1.0.0-alpha") < parse("1.0.0-alpha.1"));
    assert!(parse("1.0.0-2") < parse("1.0.0-alpha"));
    assert!(parse("v1.2.3+build.5") == parse("1.2.3"));
    for bad in [
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.2.x",
        "1.2.3-",
        "1.2.3-a..b",
        "",
    ] {
        assert!(SemVer::parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn self_reported_version_in_range_is_affected_but_cannot_clear() {
    let result = assess(json!({
        "artifacts": [
            artifact("a", "node", "22.3.0", None, "self_reported"),
            artifact("b", "node", "22.5.0", None, "self_reported"),
        ],
        "advisories": [node_advisory()],
    }));
    assert_eq!(match_status(&result, 0), ("affected", "in_range"));
    assert_eq!(
        match_status(&result, 1),
        ("unknown", "outside_ranges_untrusted")
    );
}

#[test]
fn bun_and_standalone_brotli_never_match_node_advisories() {
    let mut brotli = artifact(
        "brotli",
        "brotli",
        "22.3.0",
        Some(OLD_HASH),
        "vendor_verified",
    );
    brotli["vendor"] = json!("google");
    let result = assess(json!({
        "artifacts": [artifact("bun", "bun", "22.3.0", Some(OLD_HASH), "vendor_verified"), brotli],
        "advisories": [node_advisory()],
    }));
    for row in result["artifacts"].as_array().unwrap() {
        assert_eq!(row["matches"], json!([]), "{row}");
    }
    assert_eq!(verdict(&result).0, "not_observed");
}

#[test]
fn unsupported_inputs_stay_unknown() {
    let mut scheme = node_advisory();
    scheme["version_scheme"] = json!("calver");
    let result = assess(json!({
        "artifacts": [artifact("a", "node", "22.3.0", Some(OLD_HASH), "vendor_verified")],
        "advisories": [scheme],
    }));
    assert_eq!(
        match_status(&result, 0),
        ("unknown", "version_scheme_unsupported")
    );

    let result = assess(json!({
        "artifacts": [artifact("a", "node", "22.4.1-rc.1", Some(OLD_HASH), "vendor_verified")],
        "advisories": [node_advisory()],
    }));
    assert_eq!(
        match_status(&result, 0),
        ("unknown", "prerelease_unhandled")
    );
    assert_eq!(verdict(&result), ("unknown", vec!["match_unknown"]));

    let mut vendorless = artifact("a", "node", "22.3.0", Some(OLD_HASH), "vendor_verified");
    vendorless["vendor"] = Value::Null;
    let result = assess(json!({"artifacts": [vendorless], "advisories": [node_advisory()]}));
    assert_eq!(match_status(&result, 0), ("unknown", "vendor_unknown"));
}

#[test]
fn prerelease_opt_in_and_last_affected_bound() {
    let mut advisory = node_advisory();
    advisory["include_prerelease"] = json!(true);
    advisory["ranges"] = json!([{"introduced": "22.0.0", "last_affected": "22.4.1-rc.2"}]);
    let result = assess(json!({
        "artifacts": [
            artifact("rc2", "node", "22.4.1-rc.2", Some(OLD_HASH), "vendor_verified"),
            artifact("rel", "node", "22.4.1", Some(NEW_HASH), "vendor_verified"),
        ],
        "advisories": [advisory],
    }));
    assert_eq!(match_status(&result, 0), ("affected", "in_range"));
    assert_eq!(match_status(&result, 1), ("not_affected", "outside_ranges"));
}

#[test]
fn vendor_backport_clears_only_trusted_builds() {
    let mut advisory = node_advisory();
    advisory["backport_build_ids"] = json!(["distro-22.3.0-5"]);
    let mut trusted = artifact(
        "a-trusted",
        "node",
        "22.3.0",
        Some(OLD_HASH),
        "locally_trusted",
    );
    trusted["build_id"] = json!("distro-22.3.0-5");
    let mut hint = artifact("b-hint", "node", "22.3.0", None, "self_reported");
    hint["build_id"] = json!("distro-22.3.0-5");
    let result = assess(json!({"artifacts": [trusted, hint], "advisories": [advisory]}));
    assert_eq!(
        match_status(&result, 0),
        ("not_affected", "vendor_backport")
    );
    assert_eq!(match_status(&result, 1), ("unknown", "backport_unverified"));
}

#[test]
fn vendor_verified_without_hash_is_downgraded() {
    let result = assess(json!({
        "artifacts": [artifact("a", "node", "22.5.0", None, "vendor_verified")],
        "advisories": [node_advisory()],
    }));
    let row = &result["artifacts"][0];
    assert_eq!(row["identity_assurance"], "self_reported");
    assert_eq!(
        row["assurance_downgraded"],
        "vendor_verified_without_hash_or_version"
    );
    assert_eq!(row["identity_fingerprint"], Value::Null);
    assert_eq!(
        match_status(&result, 0),
        ("unknown", "outside_ranges_untrusted")
    );
}

#[test]
fn fingerprint_is_stable_and_binds_the_executable_hash() {
    let fingerprint = |hash| {
        assess(
            json!({"artifacts": [artifact("a", "node", "22.5.0", Some(hash), "vendor_verified")]}),
        )["artifacts"][0]["identity_fingerprint"]
            .clone()
    };
    assert_eq!(fingerprint(OLD_HASH), fingerprint(OLD_HASH));
    assert_ne!(fingerprint(OLD_HASH), fingerprint(NEW_HASH));
    assert_eq!(fingerprint(OLD_HASH).as_str().unwrap().len(), 64);
}

fn replacement_request(old_state: &str, scope_complete: bool, new_coverage: &str) -> Value {
    json!({
        "artifacts": [
            artifact("old", "node", "22.3.0", Some(OLD_HASH), "vendor_verified"),
            artifact("new", "node", "22.4.1", Some(NEW_HASH), "vendor_verified"),
        ],
        "locations": [location("new")],
        "instances": [
            instance("i-old", "old", 41, old_state, "bound_launch"),
            instance("i-new", "new", 42, "running", new_coverage),
        ],
        "advisories": [node_advisory()],
        "scope_complete": scope_complete,
    })
}

#[test]
fn replaced_disk_with_old_process_running_requires_restart() {
    let result = assess(replacement_request("running", true, "bound_launch"));
    assert_eq!(
        verdict(&result),
        (
            "restart_required",
            vec!["affected_instance_running_after_replacement"]
        )
    );
    assert_eq!(
        result["advisories"][0]["affected_instance_ids"],
        json!(["i-old"])
    );
}

#[test]
fn fix_is_verified_only_with_complete_scope_and_bound_trusted_replacement() {
    let result = assess(replacement_request("exited", true, "bound_launch"));
    assert_eq!(verdict(&result), ("fixed_verified", vec![]));
    assert_eq!(
        result["advisories"][0]["replacement_instance_ids"],
        json!(["i-new"])
    );

    let result = assess(replacement_request("exited", false, "bound_launch"));
    assert_eq!(
        verdict(&result),
        ("fix_unverified", vec!["scope_incomplete"])
    );

    for coverage in ["observed_only", "preflight_only"] {
        let result = assess(replacement_request("exited", true, coverage));
        assert_eq!(
            verdict(&result),
            ("fix_unverified", vec!["no_bound_trusted_replacement"])
        );
    }

    let result = assess(replacement_request("unknown", true, "bound_launch"));
    assert_eq!(
        verdict(&result),
        ("unknown", vec!["affected_instance_state_unknown"])
    );
}

#[test]
fn affected_artifact_still_installed_is_not_fixed() {
    let mut request = replacement_request("exited", true, "bound_launch");
    request["locations"] = json!([location("old")]);
    request["instances"][0]["location_id"] = Value::Null;
    request["instances"][1]["location_id"] = Value::Null;
    let result = assess(request);
    assert_eq!(
        verdict(&result),
        ("affected", vec!["affected_artifact_installed"])
    );
}

#[test]
fn invalid_requests_are_refused() {
    let base = || replacement_request("running", true, "bound_launch");

    let mut duplicate_process = base();
    duplicate_process["instances"][1]["pid"] = json!(41);
    duplicate_process["instances"][1]["start_identity"] = json!("start-41");
    assert_eq!(
        error(duplicate_process),
        "runtime_identity_instance_conflict"
    );

    let mut dangling = base();
    dangling["instances"][0]["artifact_id"] = json!("missing");
    assert_eq!(error(dangling), "runtime_identity_unknown_artifact");

    let mut bad_hash = base();
    bad_hash["artifacts"][0]["executable_sha256"] = json!("ABC");
    assert_eq!(error(bad_hash), "runtime_identity_artifact_invalid");

    let mut both_bounds = base();
    both_bounds["advisories"][0]["ranges"] = json!([{"fixed": "1.0.0", "last_affected": "0.9.0"}]);
    assert_eq!(error(both_bounds), "runtime_identity_advisory_invalid");

    let mut repeated = base();
    repeated["advisories"] = json!([node_advisory(), node_advisory()]);
    assert_eq!(error(repeated), "runtime_identity_advisory_duplicate");

    let mut zero_pid = base();
    zero_pid["instances"][0]["pid"] = json!(0);
    assert_eq!(error(zero_pid), "runtime_identity_instance_invalid");

    let reply = run_command(br#"{"artifacts": [], "extra": 1}"#);
    assert_eq!(reply.unwrap_err(), "runtime_identity_request_invalid");

    let many = vec![artifact("a", "node", "1.0.0", None, "unknown"); 1];
    let mut huge = json!({"artifacts": many, "advisories": []});
    huge["advisories"] = Value::Array(vec![node_advisory(); 1_025]);
    assert_eq!(error(huge), "runtime_identity_request_too_large");
}

#[test]
fn vendorless_advisory_flags_but_never_clears() {
    let mut advisory = node_advisory();
    advisory["vendor"] = Value::Null;
    let result = assess(json!({
        "artifacts": [
            artifact("a-old", "node", "22.3.0", Some(OLD_HASH), "vendor_verified"),
            artifact("b-new", "node", "22.4.1", Some(NEW_HASH), "vendor_verified"),
        ],
        "advisories": [advisory],
    }));
    assert_eq!(match_status(&result, 0), ("affected", "in_range"));
    assert_eq!(
        match_status(&result, 1),
        ("unknown", "advisory_vendor_unspecified")
    );
}

#[test]
fn unidentified_or_uncertain_locations_block_a_verified_fix() {
    let mut unidentified = replacement_request("exited", true, "bound_launch");
    unidentified["locations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"location_id": "loc-2", "artifact_id": null, "state": "present"}));
    assert_eq!(
        verdict(&assess(unidentified)),
        ("fix_unverified", vec!["location_unidentified"])
    );

    let mut uncertain = replacement_request("exited", true, "bound_launch");
    uncertain["locations"] =
        json!([{"location_id": "loc-1", "artifact_id": "old", "state": "unknown"}]);
    assert_eq!(
        verdict(&assess(uncertain)),
        ("unknown", vec!["affected_location_state_unknown"])
    );
}

#[test]
fn restart_is_not_enough_while_an_affected_build_remains() {
    let mut installed = replacement_request("running", true, "bound_launch");
    installed["locations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"location_id": "loc-2", "artifact_id": "old", "state": "present"}));
    assert_eq!(
        verdict(&assess(installed)),
        (
            "affected",
            vec![
                "affected_instance_running_after_replacement",
                "affected_artifact_installed"
            ]
        )
    );

    let mut uncertain_peer = replacement_request("running", true, "bound_launch");
    uncertain_peer["instances"]
        .as_array_mut()
        .unwrap()
        .push(instance("i-old-2", "old", 43, "unknown", "observed_only"));
    assert_eq!(
        verdict(&assess(uncertain_peer)),
        (
            "restart_required",
            vec![
                "affected_instance_running_after_replacement",
                "affected_instance_state_unknown"
            ]
        )
    );

    for (peer, reason) in [
        (
            json!({"location_id": "loc-2", "artifact_id": "old", "state": "unknown"}),
            "affected_location_state_unknown",
        ),
        (
            json!({"location_id": "loc-2", "state": "present"}),
            "location_unidentified",
        ),
    ] {
        let mut request = replacement_request("running", true, "bound_launch");
        request["locations"].as_array_mut().unwrap().push(peer);
        assert_eq!(
            verdict(&assess(request)),
            (
                "affected",
                vec!["affected_instance_running_after_replacement", reason]
            )
        );
    }
}

#[test]
fn malformed_build_metadata_and_inverted_ranges_are_refused() {
    assert!(SemVer::parse("22.5.0+bad space").is_none());
    assert!(SemVer::parse("22.5.0+").is_none());
    assert!(SemVer::parse("22.5.0+build.1-x").is_some());

    let invert = |range: Value| {
        let mut request = replacement_request("running", true, "bound_launch");
        request["advisories"][0]["ranges"] = json!([range]);
        request
    };
    for range in [
        json!({"introduced": "2.0.0", "fixed": "1.0.0"}),
        json!({"introduced": "2.0.0", "fixed": "2.0.0"}),
        json!({"introduced": "2.0.0", "last_affected": "1.9.9"}),
    ] {
        assert_eq!(error(invert(range)), "runtime_identity_advisory_invalid");
    }
    assess(invert(
        json!({"introduced": "2.0.0", "last_affected": "2.0.0"}),
    ));

    let mut pairs = json!({"advisories": vec![node_advisory(); 128]});
    pairs["artifacts"] = Value::Array(vec![artifact("a", "node", "1.0.0", None, "unknown"); 129]);
    assert_eq!(error(pairs), "runtime_identity_request_too_large");
}
