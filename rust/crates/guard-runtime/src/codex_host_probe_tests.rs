use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use super::*;

/// Unix socket paths must fit macOS's 104-byte `sockaddr_un` limit, so the
/// scratch directory is short and under `/tmp`.
fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("hgp")
        .tempdir_in("/tmp")
        .unwrap()
}

fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

fn private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir(&path).unwrap();
    mode(&path, 0o700);
    path
}

fn everywhere(_path: &Path) -> bool {
    true
}

#[test]
fn translated_codex_process_layouts() {
    let cases: [(&[u8], bool); 6] = [
        (b"/opt/codex/codex\0app-server\0", true),
        (
            b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/codex/codex\0app-server\0",
            true,
        ),
        (
            b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/other/codex\0app-server\0",
            false,
        ),
        (b"/run/rosetta/rosetta\0codex\0codex\0app-server\0", false),
        (
            b"/run/rosetta/rosetta\0/opt/other/tool\0/opt/other/tool\0app-server\0",
            false,
        ),
        (
            b"/run/rosetta/rosetta\0/opt/codex/codex\0/opt/codex/codex\0exec\0",
            false,
        ),
    ];
    for (arguments, expected) in cases {
        assert_eq!(
            translated_codex_process(arguments),
            Ok(expected),
            "{}",
            String::from_utf8_lossy(arguments)
        );
    }
    let mut oversized = b"/opt/codex/codex\0".to_vec();
    oversized.extend(std::iter::repeat_n(b'x', 65_536));
    assert_eq!(translated_codex_process(&oversized), Ok(false));
}

#[test]
fn pid_record_must_be_private_and_not_symlinked() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let record = control.join(MARKER);

    let target = directory.path().join("target");
    std::fs::write(&target, std::process::id().to_string()).unwrap();
    symlink(&target, &record).unwrap();
    // A symlinked marker is refused by the open itself, so it is never read.
    assert_eq!(managed_pid(&record), Err(Stop::Code(UNAVAILABLE)));
    assert_eq!(
        optional_managed_pid(&control.join("socket")),
        Err(Stop::Code(UNAVAILABLE))
    );
    std::fs::remove_file(&record).unwrap();

    std::fs::write(&record, std::process::id().to_string()).unwrap();
    mode(&record, 0o644);
    assert_eq!(managed_pid(&record), Err(Stop::Code(UNTRUSTED)));
}

#[test]
fn pid_record_must_be_a_small_decimal_above_one() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let record = control.join(MARKER);
    let write = |text: &[u8]| {
        std::fs::write(&record, text).unwrap();
        mode(&record, 0o600);
    };
    write(b"4242\n");
    assert_eq!(managed_pid(&record), Ok(4242));
    for text in [
        &b"1"[..],
        b"0",
        b"abc",
        b"-5",
        b"+7",
        b" ",
        b"99999999999",
        b"",
    ] {
        write(text);
        assert_eq!(managed_pid(&record), Err(Stop::Code(UNTRUSTED)), "{text:?}");
    }
    write(&[b'7'; 33]);
    assert_eq!(managed_pid(&record), Err(Stop::Code(UNTRUSTED)));
}

#[test]
fn missing_marker_is_optional_and_dangling_marker_is_not() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let socket = control.join("app-server-control.sock");
    assert_eq!(optional_managed_pid(&socket), Ok(None));
    symlink(directory.path().join("missing"), control.join(MARKER)).unwrap();
    assert!(matches!(
        optional_managed_pid(&socket),
        Err(Stop::Code(UNAVAILABLE | UNTRUSTED))
    ));
}

#[test]
fn host_identity_follows_the_marker() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let socket = control.join("app-server-control.sock");
    // Without Guard's marker only the process itself has to be a real pid.
    assert_eq!(host_identity_matches(&socket, 4242, None), Ok(true));
    assert_eq!(host_identity_matches(&socket, 1, None), Ok(false));
    let record = control.join(MARKER);
    std::fs::write(&record, "4242").unwrap();
    mode(&record, 0o600);
    assert_eq!(host_identity_matches(&socket, 4242, Some(4242)), Ok(true));
    assert_eq!(host_identity_matches(&socket, 4243, Some(4242)), Ok(false));
    assert_eq!(host_identity_matches(&socket, 4242, None), Ok(false));
    std::fs::write(&record, "4243").unwrap();
    assert_eq!(host_identity_matches(&socket, 4242, Some(4242)), Ok(false));
}

#[test]
fn socket_alias_is_pinned_to_its_private_target() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let alias = control.join("app-server-control.sock");
    let target = control.join("daemon.sock");
    let _listener = UnixListener::bind(&target).unwrap();
    symlink(&target, &alias).unwrap();
    let pin = socket_target(&alias, &everywhere).unwrap();
    assert_eq!(Path::new(&pin.target), target);
    assert_eq!(socket_target(&alias, &everywhere), Ok(pin.clone()));
    // Pointing the alias elsewhere changes the pin.
    let other = control.join("other.sock");
    let _other_listener = UnixListener::bind(&other).unwrap();
    std::fs::remove_file(&alias).unwrap();
    symlink(&other, &alias).unwrap();
    assert_ne!(socket_target(&alias, &everywhere), Ok(pin));
}

#[test]
fn socket_alias_to_a_shared_directory_is_rejected() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let shared = directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    mode(&shared, 0o755);
    let target = shared.join("daemon.sock");
    let _listener = UnixListener::bind(&target).unwrap();
    let alias = control.join("app-server-control.sock");
    symlink(&target, &alias).unwrap();
    assert_eq!(
        socket_target(&alias, &everywhere),
        Err(Stop::Code(UNTRUSTED))
    );
}

#[test]
fn socket_in_a_shared_control_directory_is_rejected() {
    let directory = scratch();
    let control = directory.path().join("app-server-control");
    std::fs::create_dir(&control).unwrap();
    mode(&control, 0o755);
    let socket = control.join("app-server-control.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    assert_eq!(
        socket_target(&socket, &everywhere),
        Err(Stop::Code(UNTRUSTED))
    );
}

#[test]
fn relative_alias_and_untrusted_root_are_rejected() {
    let directory = scratch();
    let control = private_directory(directory.path(), "app-server-control");
    let target = control.join("daemon.sock");
    let _listener = UnixListener::bind(&target).unwrap();
    let alias = control.join("app-server-control.sock");
    symlink("daemon.sock", &alias).unwrap();
    assert_eq!(
        socket_target(&alias, &everywhere),
        Err(Stop::Code(UNTRUSTED))
    );
    std::fs::remove_file(&alias).unwrap();
    symlink(&target, &alias).unwrap();
    assert_eq!(
        socket_target(&alias, &|_: &Path| false),
        Err(Stop::Code(UNTRUSTED))
    );
}

#[test]
fn missing_socket_is_an_absent_host() {
    let directory = scratch();
    assert_eq!(
        socket_target(
            &directory.path().join("nothing/app-server-control.sock"),
            &everywhere
        ),
        Err(Stop::Absent)
    );
}
