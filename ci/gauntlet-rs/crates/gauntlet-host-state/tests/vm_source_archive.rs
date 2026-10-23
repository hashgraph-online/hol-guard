use gauntlet_host_state::{VmSourceArchiveError, VmSourceArchiveProbePlan};
use serde_json::{json, Value};

const JOB_ID: &str = "0123456789abcdef";

fn plan() -> VmSourceArchiveProbePlan {
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    VmSourceArchiveProbePlan::new(&operations, JOB_ID, &"a".repeat(64)).unwrap()
}

#[test]
fn fixed_lima_probe_binds_archive_identity_without_admission() {
    let plan = plan();
    assert_eq!(plan.argv[0], "/opt/homebrew/bin/limactl");
    assert_eq!(plan.argv[1], "shell");
    assert_eq!(plan.argv[2], "hol-beta-bootstrap-20261016-004");
    assert_eq!(plan.argv[4], "/usr/bin/python3");
    assert_eq!(plan.argv[5], "-I");
    assert!(plan.argv[8].contains("O_NOFOLLOW"));
    assert_eq!(
        plan.argv[9],
        "/home/construct.guest/hol-gauntlet-source-0123456789abcdef.tar.gz"
    );
    let response = json!({"sha256":"a".repeat(64),"bytes":44902294,"uid":501,"mode":384});
    let proof = plan
        .parse_response(response.to_string().as_bytes())
        .unwrap();
    assert_eq!(proof["job_id"], JOB_ID);
    assert_eq!(proof["source_archive_sha256"], "a".repeat(64));
    assert_eq!(proof["bytes"], 44902294);
    assert_eq!(proof["execution_eligible"], false);
}

#[test]
fn wrong_pin_and_unsafe_guest_metadata_refuse() {
    let plan = plan();
    let valid = json!({"sha256":"a".repeat(64),"bytes":44902294,"uid":501,"mode":384});
    let mut wrong = valid.clone();
    wrong["sha256"] = "b".repeat(64).into();
    assert_eq!(
        plan.parse_response(wrong.to_string().as_bytes()),
        Err(VmSourceArchiveError::DigestMismatch)
    );
    for (name, value) in [
        ("uid", json!(0)),
        ("mode", json!(420)),
        ("bytes", json!(0)),
        ("bytes", json!(256 * 1024 * 1024 + 1_u64)),
    ] {
        let mut changed = valid.clone();
        changed[name] = value;
        assert_eq!(
            plan.parse_response(changed.to_string().as_bytes()),
            Err(VmSourceArchiveError::InvalidProbe),
            "{name}"
        );
    }
    assert_eq!(
        plan.parse_response(b"{\"sha256\":\"a\",\"sha256\":\"b\"}"),
        Err(VmSourceArchiveError::InvalidProbe)
    );
}

#[test]
fn arbitrary_job_and_oversized_response_refuse() {
    let operations: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    assert_eq!(
        VmSourceArchiveProbePlan::new(&operations, "../outside", &"a".repeat(64)),
        Err(VmSourceArchiveError::InvalidInput)
    );
    let plan = plan();
    assert_eq!(
        plan.parse_response(&vec![b'x'; 2049]),
        Err(VmSourceArchiveError::TooLarge)
    );
}
