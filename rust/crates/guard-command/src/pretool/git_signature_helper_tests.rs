use super::{search_path, user_programs};

#[test]
fn user_and_system_settings_name_the_programs_a_check_can_start() {
    assert_eq!(user_programs(b"").unwrap(), ["gpg", "gpgsm", "ssh-keygen"]);
    assert_eq!(
        user_programs(
            b"global\0gpg.format\nssh\0global\0gpg.ssh.program\n/opt/signer/bin/ssh-sign\0"
        )
        .unwrap(),
        ["gpg", "gpgsm", "/opt/signer/bin/ssh-sign"]
    );
    assert_eq!(
        user_programs(b"system\0gpg.program\n/usr/local/bin/gpg2\0").unwrap(),
        ["/usr/local/bin/gpg2", "gpgsm", "ssh-keygen"]
    );
}

#[test]
fn a_setting_from_the_repository_or_command_line_keeps_the_review() {
    for reply in [
        &b"local\0gpg.program\n/usr/bin/gpg\0"[..],
        b"worktree\0gpg.ssh.program\nssh-keygen\0",
        b"command\0gpg.x509.program\ngpgsm\0",
        b"local\0gpg.format\nssh\0",
        b"local\0gpg.ssh.allowedsignersfile\nsigners\0",
        b"global\0gpg.format\nssh\0local\0gpg.ssh.allowedsignersfile\nsigners\0",
    ] {
        assert!(user_programs(reply).is_none(), "{reply:?}");
    }
}

#[test]
fn a_program_git_cannot_place_keeps_the_review() {
    for reply in [
        &b"global\0gpg.program\n\0"[..],
        b"global\0gpg.program\0",
        b"global\0gpg.program\nbin/gpg\0",
        b"global\0gpg.ssh.program\n../signer\0",
        b"global\0gpg.program\n/usr/bin/gpg\0\0global\0",
        b"global\0gpg.program\n/usr/bin/gpg",
    ] {
        assert!(user_programs(reply).is_none(), "{reply:?}");
    }
}

#[test]
fn a_later_setting_replaces_the_program_an_earlier_one_named() {
    // A global setting overrides the system one, and the two OpenPGP keys
    // name the same program, so only the last one counts.
    assert_eq!(
        user_programs(
            b"system\0gpg.program\n/old/missing/gpg\0global\0gpg.program\n/usr/bin/gpg\0"
        )
        .unwrap(),
        ["/usr/bin/gpg", "gpgsm", "ssh-keygen"]
    );
    assert_eq!(
        user_programs(
            b"system\0gpg.program\n/old/missing/gpg\0global\0gpg.openpgp.program\n/usr/bin/gpg2\0"
        )
        .unwrap(),
        ["/usr/bin/gpg2", "gpgsm", "ssh-keygen"]
    );
    // An overridden record still has to come from a scope the user owns.
    assert!(
        user_programs(b"local\0gpg.program\n/tmp/x\0global\0gpg.program\n/usr/bin/gpg\0").is_none()
    );
}

#[test]
fn a_program_path_the_kernel_resolves_per_process_is_never_trusted() {
    use crate::pretool::git_config_trust::process_relative;
    use std::path::Path;
    for path in [
        "/proc/self/cwd/signer",
        "/proc/thread-self/cwd/gpg",
        "/proc/1/root/usr/bin/gpg",
        "/dev/fd/3",
        "/dev/stdin",
    ] {
        assert!(process_relative(Path::new(path)), "{path}");
    }
    for path in [
        "/usr/bin/gpg",
        "/opt/proc/gpg",
        "/dev/null",
        "gpg",
        "bin/gpg",
    ] {
        assert!(!process_relative(Path::new(path)), "{path}");
    }
}

#[test]
fn a_search_path_with_a_per_process_entry_proves_nothing() {
    let environment = |path: &str| guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_owned(),
        ..Default::default()
    };
    assert!(search_path(Some(&environment("/usr/bin:/bin"))).is_some());
    for path in [
        "/proc/self/cwd:/usr/bin",
        "/usr/bin:/dev/fd/3",
        "bin:/usr/bin",
    ] {
        assert!(search_path(Some(&environment(path))).is_none(), "{path}");
    }
}
