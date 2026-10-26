//! Locale and no-output-authority launch regression.
use super::*;

#[test]
fn bash_owned_launch_preserves_locale_and_checks_no_output_authority() {
    let (_root, mut request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf '%s\\n' 'ä' z | sort\n",
    )
    .unwrap();
    request
        .execution_environment
        .environment_names
        .push("LC_ALL".into());
    request
        .environment
        .insert("LC_ALL".into(), "en_US.UTF-8".into());
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert!(captured.report.is_none());
    let mut reference = std::process::Command::new("/usr/bin/sort")
        .env_clear()
        .env("LC_ALL", "en_US.UTF-8")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut reference.stdin.take().unwrap(), "ä\nz\n".as_bytes()).unwrap();
    let reference = reference.wait_with_output().unwrap();
    assert!(reference.status.success());
    let mut allowed = Gate {
        allow: true,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    let result = crate::native_exact_action_op::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut allowed,
    )
    .unwrap();
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, reference.stdout);
    assert_eq!(
        (allowed.prepared, allowed.committed, allowed.released),
        (0, 1, 1)
    );
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let mut denied = Gate {
        allow: false,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    assert!(crate::native_exact_action_op::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut denied,
    )
    .is_err());
    assert_eq!(
        (denied.prepared, denied.committed, denied.released),
        (0, 1, 0)
    );
}
