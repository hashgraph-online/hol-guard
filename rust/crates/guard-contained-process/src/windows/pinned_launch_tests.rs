//! A pinned command holds the reviewed executable from inspection to launch.
//! These cases swap the file the path names after it was pinned and check
//! that launch either runs the reviewed bytes or refuses, never the swap.
//!
//! The reviewed tool is a copy of `hostname.exe`, not `cmd.exe`: the launcher
//! quotes every argument, and `cmd /c` does not read a quoted `"echo"` as its
//! builtin.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use crate::{CapturedOutput, Isolation, PinnedCommand};

fn system_tool(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join(name)
}

/// A workspace whose `tools\tool.exe` is a private copy of `hostname.exe`.
fn workspace() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let canonical = directory.path().canonicalize().unwrap();
    let canonical = canonical.to_string_lossy();
    let root = match canonical.strip_prefix(r"\\?\UNC\") {
        Some(share) => PathBuf::from(format!(r"\\{share}")),
        None => PathBuf::from(canonical.trim_start_matches(r"\\?\")),
    };
    fs::create_dir(root.join("tools")).unwrap();
    fs::copy(system_tool("hostname.exe"), tool(&root)).unwrap();
    (directory, root)
}

fn tool(root: &Path) -> PathBuf {
    root.join("tools").join("tool.exe")
}

/// What a system program prints, read from the system copy directly.
fn system_output(name: &str) -> String {
    let output = std::process::Command::new(system_tool(name))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Another program's bytes. `whoami` prints `domain\user`, never the bare
/// host name.
fn swap_bytes() -> Vec<u8> {
    fs::read(system_tool("whoami.exe")).unwrap()
}

fn environment() -> Vec<(OsString, OsString)> {
    ["SystemRoot", "SystemDrive", "windir"]
        .into_iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect()
}

fn pin(root: &Path) -> PinnedCommand {
    PinnedCommand::new(&tool(root), &[], root, &environment()).unwrap()
}

fn run(command: PinnedCommand) -> std::io::Result<CapturedOutput> {
    command.capture(
        &[],
        64 * 1024,
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
        Isolation::default(),
    )
}

fn printed(output: &CapturedOutput, expected: &str) -> bool {
    !expected.is_empty()
        && output.exit_code == Some(0)
        && String::from_utf8_lossy(&output.stdout).trim() == expected
}

fn ran_reviewed(output: &CapturedOutput) -> bool {
    printed(output, &system_output("hostname.exe"))
}

fn ran_swap(output: &CapturedOutput) -> bool {
    printed(output, &system_output("whoami.exe"))
}

#[test]
fn the_unpinned_path_can_be_swapped_so_the_pinned_cases_are_not_vacuous() {
    let (_directory, root) = workspace();
    assert!(ran_reviewed(&run(pin(&root)).unwrap()));

    fs::write(tool(&root), swap_bytes()).unwrap();

    let swapped = run(pin(&root)).unwrap();
    assert!(ran_swap(&swapped), "{swapped:?}");
    assert!(!ran_reviewed(&swapped), "{swapped:?}");
}

#[test]
fn a_pinned_executable_cannot_be_overwritten_or_renamed_before_launch() {
    let (_directory, root) = workspace();
    let pinned = pin(&root);

    assert!(fs::write(tool(&root), swap_bytes()).is_err());
    assert!(fs::rename(tool(&root), root.join("tools").join("moved.exe")).is_err());
    assert!(fs::remove_file(tool(&root)).is_err());

    let output = run(pinned).unwrap();
    assert!(ran_reviewed(&output), "{output:?}");
}

#[test]
fn a_replaced_parent_directory_never_launches_the_replacement() {
    let (_directory, root) = workspace();
    let pinned = pin(&root);

    let replaced = fs::rename(root.join("tools"), root.join("reviewed-tools")).is_ok();
    if replaced {
        fs::create_dir(root.join("tools")).unwrap();
        fs::write(tool(&root), swap_bytes()).unwrap();
    }

    match run(pinned) {
        Ok(output) => {
            assert!(!replaced, "{output:?}");
            assert!(ran_reviewed(&output), "{output:?}");
        }
        Err(error) => assert!(replaced, "{error}"),
    }
}
