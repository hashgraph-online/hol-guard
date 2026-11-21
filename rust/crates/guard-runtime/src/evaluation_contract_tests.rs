use serde_json::{json, Value};

use super::dispatch;
use crate::evaluation_contract_scope::{local_endpoint, record_timestamp, windows_temporary};

const ENDPOINT: &str = "http://127.0.0.1:8765/receiver";

fn profile() -> Value {
    let digest = format!("sha256:{}", "b".repeat(64));
    json!({
        "profileId": "synthetic-local-v1",
        "buildIdentity": {"product": "hol-guard-core", "version": "3.4.2", "artifactDigest": digest},
        "installedArtifacts": [
            {"artifactId": "core-fixture", "kind": "core", "version": "3.4.2", "digest": digest}
        ],
        "network": {"mode": "local_only", "allowedEndpoints": [ENDPOINT], "proxyUrl": null},
        "targetScope": {
            "rootPath": "/eval/root",
            "allowedPaths": ["/eval/root/workspace"],
            "allowedEndpoints": [ENDPOINT],
        },
        "resourceLimits": {"maxDurationSeconds": 60},
        "expectedCapabilities": [{"capabilityId": "synthetic.read", "expectedAction": "allow"}],
    })
}

fn result(profile: &Value) -> Value {
    let artifact = profile["installedArtifacts"][0].clone();
    json!({
        "profileId": profile["profileId"],
        "buildIdentity": profile["buildIdentity"],
        "artifactIdentity": artifact,
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [{
            "caseId": "synthetic.read",
            "status": "passed",
            "expectedAction": "allow",
            "observedAction": "allow",
            "proofType": "unit_test",
            "witness": {
                "kind": "loopback_receiver",
                "path": "/eval/root/workspace/sentinel",
                "endpoint": ENDPOINT,
            },
        }],
    })
}

fn check_profile(profile: &Value) -> Value {
    dispatch(&json!({"op": "profile", "profile": profile, "portable": true, "temp_root": "/tmp"}))
        .unwrap()
}

fn check_result(result: &Value, profile: Option<&Value>) -> Value {
    dispatch(&json!({
        "op": "result",
        "result": result,
        "profile": profile,
        "portable": true,
        "temp_root": "/tmp",
    }))
    .unwrap()
}

fn error(answer: &Value) -> &str {
    answer["error"].as_str().unwrap_or("")
}

#[test]
fn valid_records_pass() {
    let profile = profile();
    assert_eq!(check_profile(&profile), json!({"ok": true}));
    assert_eq!(
        check_result(&result(&profile), Some(&profile)),
        json!({"ok": true})
    );
}

#[test]
fn malformed_requests_are_refused() {
    assert!(dispatch(&json!({"op": "other", "portable": true, "temp_root": "/tmp"})).is_err());
    assert!(dispatch(&json!({"op": "profile", "profile": {}, "temp_root": "/tmp"})).is_err());
}

#[test]
fn profile_rules_report_python_messages() {
    let mut profile = profile();
    profile["targetScope"]["allowedPaths"] = json!(["/elsewhere"]);
    assert_eq!(
        error(&check_profile(&profile)),
        "targetScope.allowedPaths[] must remain under targetScope.rootPath"
    );
    let mut profile = self::profile();
    profile["targetScope"]["rootPath"] = json!("relative/root");
    assert_eq!(
        error(&check_profile(&profile)),
        "targetScope.rootPath must be an absolute local path"
    );
    let mut profile = self::profile();
    profile["network"]["proxyUrl"] = json!("http://127.0.0.1:9999/");
    assert_eq!(
        error(&check_profile(&profile)),
        "network.proxyUrl must be within targetScope.allowedEndpoints"
    );
    let mut profile = self::profile();
    profile["expectedCapabilities"] = json!([
        {"capabilityId": "a", "expectedAction": "allow"},
        {"capabilityId": "a", "expectedAction": "block"},
    ]);
    assert_eq!(
        error(&check_profile(&profile)),
        "profile has duplicate expected capability IDs"
    );
    let mut profile = self::profile();
    profile["buildIdentity"]["artifactDigest"] = json!("sha256:other");
    assert_eq!(
        error(&check_profile(&profile)),
        "buildIdentity.artifactDigest must identify an installed artifact"
    );
}

#[test]
fn portable_windows_paths_compare_case_insensitively() {
    let mut profile = profile();
    profile["targetScope"]["rootPath"] = json!(r"C:\Eval\Root");
    profile["targetScope"]["allowedPaths"] = json!([r"c:/eval/root/Workspace"]);
    assert_eq!(check_profile(&profile), json!({"ok": true}));
    profile["targetScope"]["allowedPaths"] = json!([r"C:\Eval\Root\..\x"]);
    assert_eq!(
        error(&check_profile(&profile)),
        "targetScope.allowedPaths[] must be an absolute local path"
    );
    for share in [
        r"\\server\share\x",
        "//server/share/x",
        r"/\server\share\x",
        r"\/server/share/x",
    ] {
        profile["targetScope"]["allowedPaths"] = json!([share]);
        assert_eq!(
            error(&check_profile(&profile)),
            "targetScope.allowedPaths[] must be an absolute local path",
            "{share}"
        );
    }
}

#[test]
fn endpoints_must_be_numeric_loopback() {
    let name = "endpoint";
    let refused = |url: &str| local_endpoint(&json!(url), name).unwrap_err();
    assert!(local_endpoint(&json!("https://[::1]:8443/x"), name).is_ok());
    assert!(local_endpoint(&json!("http://127.9.0.1./"), name).is_ok());
    assert_eq!(
        refused("http://localhost:1/"),
        "endpoint must use a numeric loopback IP"
    );
    assert_eq!(
        refused("http://127.000.0.1/"),
        "endpoint must use a numeric loopback IP"
    );
    assert!(local_endpoint(&json!("http://[::ffff:7f00:1]/"), name).is_ok());
    assert_eq!(
        refused("http://[::ffff:10.0.0.1]/"),
        "endpoint must use a numeric loopback IP"
    );
    assert_eq!(
        refused("http://[::127.0.0.1]/"),
        "endpoint must use a numeric loopback IP"
    );
    assert_eq!(
        refused("http://u@127.0.0.1/"),
        "endpoint must not contain credentials or a fragment"
    );
    assert_eq!(
        refused("http://127.0.0.1/#x"),
        "endpoint must not contain credentials or a fragment"
    );
    assert_eq!(
        refused("http://127.0.0.1:0/"),
        "endpoint has an invalid port"
    );
    assert_eq!(
        refused("http://127.0.0.1:70000/"),
        "endpoint must be a loopback HTTP(S) endpoint"
    );
    assert_eq!(
        refused("ftp://127.0.0.1/"),
        "endpoint must be a loopback HTTP(S) endpoint"
    );
    assert_eq!(
        refused("http://127.0.0.1/ x"),
        "endpoint must be a loopback HTTP(S) endpoint"
    );
}

#[test]
fn timestamps_need_a_zone_and_truncate_fractions() {
    let at = |text: &str| record_timestamp(&json!(text), "at");
    assert_eq!(at("1970-01-01T00:00:01.0000019Z"), Ok(1_000_001));
    assert_eq!(at("1970-01-01T01:00:00+01:00"), Ok(0));
    assert_eq!(at("1970-01-01T06:00:00+05:60"), Ok(0));
    assert_eq!(at("2024-02-29T00:00:00-00:30"), at("2024-02-29T00:30:00Z"));
    for bad in [
        "2026-09-23T12:00:00",
        "2026-02-30T00:00:00Z",
        "2026-09-23T24:00:00Z",
        "2026-09-23T12:00:00+24:00",
        "2026-09-23T12:00:00.Z",
    ] {
        assert_eq!(
            at(bad),
            Err("at must be a zoned RFC3339 timestamp".to_owned()),
            "{bad}"
        );
    }
}

#[test]
fn result_rules_report_python_messages() {
    let profile = profile();
    let mut late = result(&profile);
    late["finishedAt"] = json!("2026-09-23T12:01:00.000001Z");
    assert_eq!(
        error(&check_result(&late, Some(&profile))),
        "result duration exceeds profile maxDurationSeconds"
    );
    late["finishedAt"] = json!("2026-09-23T12:01:00Z");
    assert_eq!(check_result(&late, Some(&profile)), json!({"ok": true}));

    let passed = result(&profile);
    assert_eq!(
        error(&check_result(&passed, None)),
        "passed result requires the evaluation profile for complete coverage"
    );
    let mut summary = result(&profile);
    summary["summary"] = json!({
        "passed": 1.0, "failed": false, "unsupported": 0, "blockedEnvironment": 0, "notRun": 0
    });
    assert_eq!(check_result(&summary, Some(&profile)), json!({"ok": true}));
    summary["summary"]["failed"] = json!(1);
    assert_eq!(
        error(&check_result(&summary, Some(&profile))),
        "result summary does not match cases"
    );

    let mut outside = result(&profile);
    outside["cases"][0]["witness"]["path"] = json!("/eval/root/other");
    assert_eq!(
        error(&check_result(&outside, Some(&profile))),
        "result witness path is outside the profile target scope"
    );
    let mut endpoint = result(&profile);
    endpoint["cases"][0]["witness"]["endpoint"] = json!("http://127.0.0.1:8765/receiver/");
    assert_eq!(
        error(&check_result(&endpoint, Some(&profile))),
        "result witness endpoint is outside the profile target scope"
    );
}

#[test]
fn enforcement_cases_need_distinct_witnesses() {
    let mut profile = profile();
    profile["expectedCapabilities"][0]["expectedAction"] = json!("block");
    let mut result = result(&profile);
    result["evidenceIdentity"]["evidenceType"] = json!("live_installed_host_test");
    let case = &mut result["cases"][0];
    case["expectedAction"] = json!("block");
    case["observedAction"] = json!("block");
    case["proofType"] = json!("live_installed_host_test");
    case["witness"] = json!({
        "kind": "loopback_receiver",
        "endpoint": ENDPOINT,
        "allowedEndpoint": "http://127.0.0.1:8765/receiver/",
        "receiverReady": true,
        "deniedReached": false,
        "allowedReached": true,
    });
    assert_eq!(
        error(&check_result(&result, Some(&profile))),
        "passed enforcement case requires distinct denied and allowed witnesses"
    );
    result["cases"][0]["witness"]["allowedEndpoint"] = json!(ENDPOINT.replace("receiver", "other"));
    result["cases"][0]["witness"]["receiverReady"] = json!(1);
    assert_eq!(
        error(&check_result(&result, Some(&profile))),
        "passed enforcement case requires ready receiver, absent denied effect, and present allowed effect"
    );
}

#[test]
fn windows_temporary_rejects_a_junction_escape() {
    let resolve = |path: &str| {
        Some(if path.starts_with(r"C:\Temp\junction") {
            r"D:\outside\sentinel".to_owned()
        } else {
            path.to_owned()
        })
    };
    assert!(windows_temporary(r"C:\Temp\private", r"C:\Temp", &resolve));
    assert!(windows_temporary(
        r"c:/temp/Private/x",
        r"C:\Temp",
        &resolve
    ));
    assert!(!windows_temporary(r"C:\Temp", r"C:\Temp", &resolve));
    assert!(!windows_temporary(
        r"C:\Temp\junction\sentinel",
        r"C:\Temp",
        &resolve
    ));
    for share in [r"\\server\share\x", "//server/share/x"] {
        assert!(!windows_temporary(share, r"C:\Temp", &resolve), "{share}");
    }
}
