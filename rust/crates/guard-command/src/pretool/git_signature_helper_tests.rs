use super::user_programs;

#[test]
fn user_and_system_settings_name_the_programs_a_check_can_start() {
    assert_eq!(user_programs(b"").unwrap(), ["gpg", "gpgsm", "ssh-keygen"]);
    assert_eq!(
        user_programs(
            b"global\0gpg.format\nssh\0global\0gpg.ssh.program\n/opt/signer/bin/ssh-sign\0"
        )
        .unwrap(),
        ["/opt/signer/bin/ssh-sign", "gpg", "gpgsm"]
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
