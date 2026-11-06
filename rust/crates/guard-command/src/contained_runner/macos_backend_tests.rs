//! Real macOS backend proofs: a contained command runs under `sandbox-exec`
//! against an ephemeral snapshot, and the live workspace, the user's protected
//! files, the system's own configuration and the network all stay out of reach.
//!
//! `/usr/bin/sandbox-exec` ships with macOS, so unlike the Linux proofs these
//! need no provisioned host and run wherever the crate's tests run.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::kill;
use nix::unistd::Pid;

use super::common::file_sha256;
use super::contract::{Policy, Request};
use super::exec::execute_contained;
use super::vector_support::Workspace;

const SENTINEL: &str = "synthetic-secret-sentinel";

fn request(workspace: &Path, argv: &[&str]) -> Request {
    let workspace = workspace.to_string_lossy().into_owned();
    let argv: Vec<String> = argv.iter().map(|part| (*part).to_owned()).collect();
    let executable_digest = file_sha256(Path::new(&argv[0])).expect("executable digest");
    Request::new(
        &argv,
        &workspace,
        &[("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        Policy::new(&workspace).expect("policy"),
        Vec::new(),
        &"1".repeat(64),
        &executable_digest,
        "op.contained.macos",
    )
    .expect("request")
}

fn workspace_root() -> (Workspace, PathBuf) {
    let workspace = Workspace::new();
    let path = fs::canonicalize(&workspace.path).expect("canonical workspace");
    (workspace, path)
}

fn pid_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn a_write_lands_in_the_ephemeral_snapshot_and_never_in_the_workspace() {
    let (_workspace, root) = workspace_root();

    let result = execute_contained(
        &request(&root, &["/bin/sh", "-c", "printf allowed > result.txt"]),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_eq!(result.exit_code, Some(0), "{}", result.stderr);
    // The command succeeded against its private copy; the reviewed workspace is
    // untouched because it was never the directory the command ran in.
    assert!(!root.join("result.txt").exists());
}

#[test]
fn a_write_outside_the_snapshot_is_denied() {
    let (_workspace, root) = workspace_root();
    let external = root.parent().expect("fixture root").join("external");
    fs::write(&external, b"unchanged").expect("write external");

    let result = execute_contained(
        &request(
            &root,
            &[
                "/bin/sh",
                "-c",
                &format!("printf changed > {}", external.display()),
            ],
        ),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_ne!(result.exit_code, Some(0));
    assert_eq!(fs::read(&external).expect("read external"), b"unchanged");
}

#[test]
fn a_protected_file_in_the_live_workspace_cannot_be_read() {
    let (_workspace, root) = workspace_root();
    let protected = root.join(".guard");
    fs::create_dir(&protected).expect("create .guard");
    let credentials = protected.join("credentials.json");
    fs::write(&credentials, SENTINEL).expect("write credentials");

    let result = execute_contained(
        &request(
            &root,
            &["/bin/sh", "-c", &format!("cat {}", credentials.display())],
        ),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_ne!(result.exit_code, Some(0));
    assert!(!result.stdout.contains(SENTINEL));
    assert!(!result.stderr.contains(SENTINEL));
}

#[test]
fn an_undeclared_live_workspace_file_cannot_be_read() {
    let (_workspace, root) = workspace_root();
    let private = root.join("ordinary-private-input.txt");
    fs::write(&private, SENTINEL).expect("write private input");

    // Only reviewed inputs are copied into the snapshot. Everything else in the
    // workspace stays invisible, however ordinary it looks.
    let result = execute_contained(
        &request(
            &root,
            &["/bin/sh", "-c", &format!("cat {}", private.display())],
        ),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_ne!(result.exit_code, Some(0));
    assert!(!result.stdout.contains(SENTINEL));
    assert!(!result.stderr.contains(SENTINEL));
}

#[test]
fn the_system_configuration_cannot_be_read() {
    let sensitive = Path::new("/Library/Preferences/SystemConfiguration/preferences.plist");
    if !sensitive.is_file() {
        return;
    }
    let (_workspace, root) = workspace_root();

    let result = execute_contained(
        &request(
            &root,
            &["/bin/sh", "-c", &format!("cat {}", sensitive.display())],
        ),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_ne!(result.exit_code, Some(0));
    assert_eq!(result.stdout, "");
}

#[test]
fn the_network_is_denied_even_for_loopback() {
    // `/usr/bin/python3` is an xcrun shim when a full Xcode is selected, and
    // the profile rightly refuses to read Xcode, so the interpreter never
    // starts. The system Perl runs from `/usr` and `/System` alone.
    let interpreter = Path::new("/usr/bin/perl");
    if !interpreter.is_file() {
        return;
    }
    let (_workspace, root) = workspace_root();

    let result = execute_contained(
        &request(
            &root,
            &[
                "/usr/bin/perl",
                "-MSocket",
                "-e",
                // The socket is created before the guarded call so that exit
                // code 42 can only mean the bind itself was refused, not that
                // the interpreter failed to start or load Socket.
                "socket(my $s, PF_INET, SOCK_STREAM, 0) or exit 3; \
                 bind($s, pack_sockaddr_in(0, inet_aton('127.0.0.1'))) or exit 42; exit 0",
            ],
        ),
        60.0,
    )
    .expect("execute");

    assert!(result.enforced());
    assert_eq!(result.exit_code, Some(42), "{}", result.stderr);
}

#[test]
fn a_backgrounded_descendant_does_not_outlive_the_launch() {
    let (_workspace, root) = workspace_root();

    let result = execute_contained(
        &request(&root, &["/bin/sh", "-c", "sleep 30 & printf '%s' $!"]),
        30.0,
    )
    .expect("execute");

    assert!(result.enforced());
    // The profile denies process-fork, so the background job usually never
    // starts and `$!` expands to nothing. That refusal is itself the contained
    // outcome; only a reported pid is worth outliving the launch.
    let Ok(descendant) = result.stdout.trim().parse::<i32>() else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while pid_alive(descendant) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !pid_alive(descendant),
        "the backgrounded descendant must not survive the launch"
    );
}

#[test]
fn a_timeout_still_attests_enforcement() {
    let (_workspace, root) = workspace_root();

    let result =
        execute_contained(&request(&root, &["/bin/sh", "-c", "sleep 30"]), 0.5).expect("execute");

    // A launch that ran out of time still ran under the sandbox, so the
    // attestation must keep saying so rather than degrading to unenforced.
    assert!(result.enforced());
    assert!(result.timed_out);
    assert_eq!(result.exit_code, None);
}
