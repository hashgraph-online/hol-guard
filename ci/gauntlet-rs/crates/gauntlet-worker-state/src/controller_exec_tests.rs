use super::*;
use crate::{fixed_staging_control_plan, StagingControlPins, StagingRole};

#[test]
fn staging_plan_matches_descriptor_launcher_environment() {
    let config_digest = "a".repeat(64);
    let private_manifest_sha256 = "b".repeat(64);
    let interpreter_sha256 = "c".repeat(64);
    let pins = StagingControlPins {
        build_job_id: "aabbccddeeff0011",
        run_id: "1122334455667788",
        source_sha: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        version: "3.49.0",
        config_digest: &config_digest,
        private_manifest_sha256: &private_manifest_sha256,
        controller_path: "/opt/hol-gauntlet/controller-aabbccddeeff0011",
        python_path: "/opt/hol-benchmark-controller-20261013/.venv/bin/python",
        interpreter_sha256: &interpreter_sha256,
    };
    let plan = fixed_staging_control_plan(&pins, StagingRole::Success).unwrap();
    assert_eq!(plan.argv()[0], pins.python_path);
    assert!(plan.argv().len() <= MAX_ARGV);
    let mut environment = plan.environment();
    environment.insert("HOL_GAUNTLET_RUST_SIGNING_KEY_FD", "9".to_owned());
    assert_eq!(
        fixed_environment(&environment, Some(9)).unwrap().len(),
        SIGNED_ENV_KEYS.len()
    );
}

#[test]
fn controller_environment_accepts_only_the_fixed_keys_and_exact_signing_fd() {
    let mut environment = BTreeMap::from([
        (
            "HOL_GAUNTLET_RUST_JOB_SLICE",
            "holgauntletrust1234567890abcdef.slice".to_owned(),
        ),
        ("HOME", "/root".to_owned()),
        ("LANG", "C.UTF-8".to_owned()),
        ("PATH", "/usr/bin:/bin".to_owned()),
    ]);
    assert_eq!(fixed_environment(&environment, None).unwrap().len(), 4);
    environment.insert("HOL_GAUNTLET_RUST_SIGNING_KEY_FD", "9".to_owned());
    assert_eq!(fixed_environment(&environment, Some(9)).unwrap().len(), 5);
    assert!(fixed_environment(&environment, Some(10)).is_err());
    assert!(fixed_environment(&environment, None).is_err());
    environment.remove("HOL_GAUNTLET_RUST_SIGNING_KEY_FD");
    environment.remove("HOME");
    assert!(matches!(
        fixed_environment(&environment, None),
        Err(ControllerExecError::InvalidPlan)
    ));
    environment.insert("HOME", "/root".to_owned());
    environment.insert("UNTRUSTED", "value".to_owned());
    assert!(matches!(
        fixed_environment(&environment, None),
        Err(ControllerExecError::InvalidPlan)
    ));
}

#[test]
fn stale_report_directory_or_symlink_blocks_a_fresh_job_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = rustix::fs::open(
        temp.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let job = "a1b2c3d4e5f60718";
    assert!(require_absent_child(&output, job).is_ok());
    std::fs::create_dir(temp.path().join(job)).unwrap();
    assert!(matches!(
        require_absent_child(&output, job),
        Err(ControllerExecError::OutputExists)
    ));
    std::fs::remove_dir(temp.path().join(job)).unwrap();
    std::os::unix::fs::symlink("missing", temp.path().join(job)).unwrap();
    assert!(matches!(
        require_absent_child(&output, job),
        Err(ControllerExecError::OutputExists)
    ));
}
