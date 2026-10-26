use crate::{Isolation, PinnedCommand};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture(
    hardened: bool,
    jit_entitlement: bool,
    generated_code: bool,
) -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("fixture.c");
    let image = temporary.path().join("fixture");
    let program: &[u8] = if generated_code {
        br#"#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
int main(void) {
  ptrace(PT_TRACE_ME, 0, 0, 0);
  unsigned char *code = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
#if defined(__aarch64__)
  const unsigned char bytes[] = {0x40,0x05,0x80,0x52,0xc0,0x03,0x5f,0xd6};
#elif defined(__x86_64__)
  const unsigned char bytes[] = {0xb8,0x2a,0,0,0,0xc3};
#endif
  memcpy(code, bytes, sizeof(bytes));
  mprotect(code, 4096, PROT_READ|PROT_EXEC);
  int result = ((int (*)(void))code)();
  printf("generated=%d\n", result);
  return 0;
}
"#
    } else {
        b"#include <stdio.h>\nint main(void){fputs(\"bound\\n\",stdout);return 23;}\n"
    };
    fs::write(&source, program).unwrap();
    run(Command::new("/usr/bin/clang")
        .args(["-O0", "-Wl,-no_uuid"])
        .arg(&source)
        .arg("-o")
        .arg(&image));
    let mut signing = Command::new("/usr/bin/codesign");
    signing.args([
        "--force",
        "--sign",
        "-",
        "--identifier",
        "guard.hardened-image-test",
    ]);
    if hardened {
        signing.args(["--options", "runtime"]);
    }
    if jit_entitlement {
        let entitlements = temporary.path().join("entitlements.plist");
        fs::write(
            &entitlements,
            b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>",
        )
        .unwrap();
        signing.arg("--entitlements").arg(entitlements);
    }
    run(signing.arg(&image));
    let image = fs::canonicalize(image).unwrap();
    (temporary, image)
}

fn literal(path: &Path) -> String {
    format!(
        "\"{}\"",
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

fn isolation(command: &PinnedCommand) -> Isolation {
    let image = literal(command.effective_executable_path());
    Isolation {
        seatbelt: Some(format!(
            r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec (literal {image}))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (literal {image}))
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (literal {image}))
(allow sysctl-read)
(allow signal)"#
        )),
        ..Isolation::default()
    }
}

#[test]
fn hardened_entitlement_free_image_runs_with_terminal_status() {
    let (_temporary, image) = fixture(true, false, false);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let isolation = isolation(&command);
    let output = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap();
    assert_eq!(output.exit_code, Some(23));
    assert_eq!(output.stdout, b"bound\n");
    assert!(output.stderr.is_empty());
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
}

#[test]
fn ad_hoc_image_without_hardened_runtime_is_rejected_before_launch() {
    let (_temporary, image) = fixture(false, false, false);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let isolation = isolation(&command);
    let error = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn hardened_image_with_jit_entitlement_is_rejected_before_launch() {
    let (_temporary, image) = fixture(true, true, false);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let isolation = isolation(&command);
    let error = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn hardened_launch_requires_a_seatbelt_profile() {
    let (_temporary, image) = fixture(true, false, false);
    let command = PinnedCommand::new(
        &image,
        &[OsStr::new("unused")],
        image.parent().unwrap(),
        &[],
    )
    .unwrap();
    let error = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn hardened_image_cannot_execute_generated_code() {
    let (_temporary, image) = fixture(true, false, true);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let isolation = isolation(&command);
    let output = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap();
    assert_eq!(output.exit_code, Some(-libc::SIGKILL));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
}

#[test]
fn same_inode_rewrite_after_final_binding_is_killed() {
    let (_temporary, image) = fixture(true, false, false);
    let (_changed_temporary, changed) = fixture(true, false, true);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let target = command.effective_executable_path().to_owned();
    let mut sockets = [-1; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) },
        0
    );
    let child_socket = unsafe { fs::File::from_raw_fd(sockets[0]) };
    let mut controller = unsafe { fs::File::from_raw_fd(sockets[1]) };
    let attacker = std::thread::spawn(move || {
        let mut marker = [0u8];
        controller.read_exact(&mut marker).unwrap();
        assert_eq!(marker, [1]);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = fs::read(changed).unwrap();
        let mut target_file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&target)
            .unwrap();
        target_file.write_all(&replacement).unwrap();
        target_file.sync_all().unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).unwrap();
        controller.write_all(&marker).unwrap();
    });
    crate::unix::hardened_spawn::enable_resume_probe();
    let mut isolation = isolation(&command);
    isolation.inherited_files.push(child_socket);
    let output = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap();
    attacker.join().unwrap();
    assert_eq!(output.exit_code, Some(-libc::SIGKILL));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn replacement_after_static_review_cannot_execute_a_different_signed_image() {
    let (_temporary, image) = fixture(true, false, false);
    let (_changed_temporary, changed) = fixture(true, false, true);
    let command = PinnedCommand::new(&image, &[], image.parent().unwrap(), &[]).unwrap();
    let isolation = isolation(&command);
    let target = command.effective_executable_path().to_owned();
    crate::unix::process_regressions::set_before_fork(move || {
        let parent = target.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = parent.join("replacement");
        fs::copy(changed, &replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
        fs::rename(replacement, target).unwrap();
    });
    let error = command
        .capture_hardened_image(
            b"",
            4096,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            isolation,
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}
