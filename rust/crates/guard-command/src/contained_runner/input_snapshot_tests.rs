//! Proofs for the private snapshot a contained launch runs against: the
//! reviewed inputs and the reviewed interpreter are copied under the runner's
//! own root, and anything whose identity moved between review and launch stops
//! the launch instead of being carried into the sandbox.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::common::file_sha256;
use super::contract::{Backend, Input, Policy, Request};
use super::input_snapshot::{pin_executable, snapshot_inputs};
use super::vector_support::Workspace;

const TOOL_BODY: &[u8] = b"#!/bin/sh\nexec /bin/true\n";

struct Fixture {
    workspace: Workspace,
    root: PathBuf,
    tool: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let workspace = Workspace::new();
        let tool = workspace.path.join("tool");
        fs::write(&tool, TOOL_BODY).expect("write tool");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).expect("tool mode");
        // A sibling of the reviewed workspace, inside the fixture root the
        // workspace removes on drop.
        let root = workspace
            .path
            .parent()
            .expect("fixture root")
            .join("runner-root");
        fs::create_dir_all(&root).expect("create runner root");
        Self {
            workspace,
            root,
            tool,
        }
    }

    fn request(&self, inputs: Vec<Input>, executable_digest: &str) -> Request {
        let workspace = self.workspace.text();
        Request::new(
            &[self.tool.to_string_lossy().into_owned()],
            &workspace,
            &[],
            Policy::new(&workspace).expect("policy"),
            inputs,
            &"1".repeat(64),
            executable_digest,
            "op.contained.snapshot",
        )
        .expect("request")
    }

    fn input(&self, name: &str, body: &[u8]) -> (PathBuf, Input) {
        let source = self.workspace.path.join(name);
        if let Some(parent) = source.parent() {
            fs::create_dir_all(parent).expect("input parent");
        }
        fs::write(&source, body).expect("write input");
        let digest = file_sha256(&source).expect("input digest");
        let input = Input::new(&source.to_string_lossy(), name, &digest).expect("input");
        (source, input)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reviewed_inputs_become_private_read_only_copies() {
    let fixture = Fixture::new();
    let (source, input) = fixture.input("nested/app.ts", b"export const value = 1;\n");
    let request = fixture.request(vec![input], &file_sha256(&fixture.tool).expect("digest"));

    let snapshot_cwd = snapshot_inputs(&request, &fixture.root).expect("snapshot");

    // The command runs against the copy under the runner's own root, never the
    // reviewed workspace itself.
    assert!(snapshot_cwd.starts_with(&fixture.root));
    assert!(!snapshot_cwd.starts_with(&fixture.workspace.path));
    let copy = fixture.root.join("workspace").join("nested").join("app.ts");
    assert_eq!(
        fs::read(&copy).expect("read copy"),
        fs::read(&source).expect("read source")
    );
    // Read-only: the contained command cannot edit its own reviewed inputs.
    let mode = fs::metadata(&copy).expect("copy metadata").mode() & 0o777;
    assert_eq!(mode, 0o400, "a non-executable input is copied read-only");
    for name in ["home", "tmp"] {
        let private = fixture.root.join(name);
        assert!(private.is_dir(), "{name} must be a private directory");
        assert_eq!(
            fs::metadata(&private).expect("metadata").mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn an_executable_input_keeps_its_executable_bit_without_becoming_writable() {
    let fixture = Fixture::new();
    let (source, input) = fixture.input("run.sh", b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).expect("source mode");
    let request = fixture.request(vec![input], &file_sha256(&fixture.tool).expect("digest"));

    snapshot_inputs(&request, &fixture.root).expect("snapshot");

    let copy = fixture.root.join("workspace").join("run.sh");
    assert_eq!(
        fs::metadata(&copy).expect("copy metadata").mode() & 0o777,
        0o500
    );
}

#[test]
fn an_input_that_changed_since_review_stops_the_launch() {
    let fixture = Fixture::new();
    let (source, input) = fixture.input("app.ts", b"export const value = 1;\n");
    let request = fixture.request(vec![input], &file_sha256(&fixture.tool).expect("digest"));
    // The reviewed digest was taken from the old bytes; swapping them now is
    // the race the snapshot exists to lose safely.
    fs::write(&source, b"export const value = 2;\n").expect("rewrite input");

    assert_eq!(
        snapshot_inputs(&request, &fixture.root),
        Err("containment input identity changed before snapshot".to_owned())
    );
}

#[test]
fn an_executable_that_changed_since_review_stops_the_launch() {
    let fixture = Fixture::new();
    let request = fixture.request(Vec::new(), &"a".repeat(64));

    assert_eq!(
        pin_executable(&request, &fixture.root, Backend::LinuxBwrap),
        Err("executable identity changed before contained execution".to_owned())
    );
}

#[test]
#[cfg(target_os = "linux")]
fn the_reviewed_executable_is_pinned_as_a_read_only_copy() {
    let fixture = Fixture::new();
    let digest = file_sha256(&fixture.tool).expect("digest");
    let request = fixture.request(Vec::new(), &digest);

    let pinned = pin_executable(&request, &fixture.root, Backend::LinuxBwrap).expect("pin");

    let pinned = Path::new(&pinned);
    assert_eq!(pinned, fixture.root.join("guard-exec"));
    assert_eq!(file_sha256(pinned).expect("pinned digest"), digest);
    assert_eq!(
        fs::metadata(pinned).expect("pinned metadata").mode() & 0o777,
        0o500,
        "the pinned copy must not be writable by the contained command"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn the_macos_sandbox_accepts_only_an_immutable_system_executable() {
    let fixture = Fixture::new();
    let request = fixture.request(Vec::new(), &file_sha256(&fixture.tool).expect("digest"));

    // A workspace-owned interpreter could be replaced between the pin and the
    // launch, and the macOS backend has no private copy to run instead.
    assert_eq!(
        pin_executable(&request, &fixture.root, Backend::MacosSandbox),
        Err("macOS containment requires an immutable system executable".to_owned())
    );

    let system = "/bin/sh".to_owned();
    let system_request = Request::new(
        &[system.clone()],
        &fixture.workspace.text(),
        &[],
        Policy::new(&fixture.workspace.text()).expect("policy"),
        Vec::new(),
        &"1".repeat(64),
        &file_sha256(Path::new(&system)).expect("digest"),
        "op.contained.snapshot",
    )
    .expect("request");
    assert_eq!(
        pin_executable(&system_request, &fixture.root, Backend::MacosSandbox),
        Ok(system)
    );
}
