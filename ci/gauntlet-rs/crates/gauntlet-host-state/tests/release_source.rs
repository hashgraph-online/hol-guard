use gauntlet_host_state::{ReleaseSourceError, TagLookupPlan};
use serde_json::Value;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

#[test]
fn fixed_git_tag_lookup_matches_pinned_python_without_network() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_release_source_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/local_vm.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-release-source-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let mut operations: Value =
            serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
        operations
            .as_object_mut()
            .unwrap()
            .extend(case["overrides"].as_object().unwrap().clone());
        let tag = case["tag"].as_str().unwrap();
        if case["refusal"] == "tag-not-allowed" {
            assert_eq!(
                TagLookupPlan::new(&operations, tag),
                Err(ReleaseSourceError::TagNotAllowed)
            );
            assert!(case["calls"].as_array().unwrap().is_empty());
            continue;
        }
        let plan = TagLookupPlan::new(&operations, tag).unwrap();
        let calls = case["calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1, "{case}");
        assert_eq!(
            plan.argv,
            serde_json::from_value::<Vec<String>>(calls[0]["argv"].clone()).unwrap()
        );
        assert_eq!(
            plan.to_json()["env_delta"]["GIT_TERMINAL_PROMPT"],
            calls[0]["git_terminal_prompt"]
        );
        assert_eq!(calls[0]["text"], true);
        assert_eq!(calls[0]["timeout"], 60);
        assert_eq!(plan.to_json()["execution_eligible"], false);
        let result = plan.parse_response(case["stdout"].as_str().unwrap().as_bytes());
        if case["accepted"] == true {
            assert_eq!(result.unwrap(), case["result"], "{case}");
        } else {
            let expected = match case["refusal"].as_str().unwrap() {
                "missing-tag" => ReleaseSourceError::MissingTag,
                "invalid-response" => ReleaseSourceError::InvalidResponse,
                other => panic!("unexpected Python refusal {other}"),
            };
            assert_eq!(result, Err(expected), "{case}");
        }
    }
}

#[test]
fn malformed_or_oversize_git_output_refuses() {
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    let plan = TagLookupPlan::new(&operations, "v3.48.0").unwrap();
    assert_eq!(
        plan.parse_response(&[0xff]),
        Err(ReleaseSourceError::InvalidResponse)
    );
    assert_eq!(
        plan.parse_response(&vec![b'x'; 64 * 1024 + 1]),
        Err(ReleaseSourceError::TooLarge)
    );
}

#[test]
fn read_only_git_runner_uses_fixed_plan_and_reports_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let fake_git = temporary.path().join("fake-git");
    fs::write(
        &fake_git,
        b"#!/bin/sh\nprintf '%s\\t%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v3.48.0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_git, Permissions::from_mode(0o700)).unwrap();
    let mut operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    operations["git"] = fake_git.to_str().unwrap().into();
    let plan = TagLookupPlan::new(&operations, "v3.48.0").unwrap();
    assert_eq!(plan.execute_read_only().unwrap()["sha"], "a".repeat(40));
    let unchanged = plan.recheck_pinned_sha_read_only(&"a".repeat(40)).unwrap();
    assert_eq!(unchanged["tag"], "v3.48.0");
    assert_eq!(unchanged["tag_unchanged"], true);
    assert_eq!(unchanged["execution_eligible"], false);
    assert_eq!(
        plan.recheck_pinned_sha_read_only(&"b".repeat(40)),
        Err(ReleaseSourceError::MovedTag)
    );
    assert_eq!(
        plan.recheck_pinned_sha_read_only("not-a-sha"),
        Err(ReleaseSourceError::InvalidExpectedSha)
    );
    fs::write(&fake_git, b"#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(plan.execute_read_only(), Err(ReleaseSourceError::GitFailed));
}
