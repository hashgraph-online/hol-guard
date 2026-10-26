//! Real Linux backend proofs: exit-status fidelity, exec-failure honesty and
//! the enforced vitest boundary.
//!
//! These run a genuine sandboxed child, so they need a provisioned host with
//! `bubblewrap`, a `userns`-permitting AppArmor profile and an installed vitest
//! fixture. Only the nightly containment job has that, so every test here is a
//! no-op unless `GUARD_LINUX_CONTAINMENT=1` selects it.

use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::common::{file_sha256, sha256_hex};
use super::contract::{Input, Policy, Request};
use super::decision::EXECUTION_PROOF_REQUIREMENTS;
use super::exec::{execute_contained, TempRoot};
use super::health::{contained_positive_proof, current_health, now_micros};
use super::snapshot::complete_workspace_snapshot;
use crate::effect_decision::ProofRoute;

const SENTINEL: &str = "synthetic-secret-sentinel";

/// `true` when the provisioned containment job selected these tests.
fn provisioned() -> bool {
    std::env::var("GUARD_LINUX_CONTAINMENT").is_ok_and(|value| value == "1")
}

fn canonical(path: &Path) -> String {
    fs::canonicalize(path)
        .expect("canonicalize")
        .to_string_lossy()
        .into_owned()
}

/// First `node` on `PATH`, resolved through its symlinks.
fn node_executable() -> String {
    let path = std::env::var_os("PATH").expect("PATH");
    let found = std::env::split_paths(&path)
        .map(|directory| directory.join("node"))
        .find(|candidate| candidate.is_file())
        .expect("node on PATH");
    canonical(&found)
}

fn request(
    workspace: &Path,
    argv: &[String],
    inputs: Option<(String, Vec<Input>)>,
) -> Result<Request, String> {
    let workspace = canonical(workspace);
    let (digest, inputs) = inputs.unwrap_or_else(|| ("empty".to_owned(), Vec::new()));
    // The Python integration test keyed its launch digest on the snapshot
    // digest and the argv tuple; keep the same two facts bound here.
    let launch_digest = sha256_hex(format!("linux-integration:{digest}:{argv:?}").as_bytes());
    Request::new(
        argv,
        &workspace,
        &[],
        Policy::new(&workspace)?,
        inputs,
        &launch_digest,
        &file_sha256(Path::new(&argv[0]))?,
        "integration-test",
    )
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn real_backend_preserves_child_exit_status() {
    if !provisioned() {
        return;
    }
    let shell = canonical(Path::new("/bin/sh"));
    for status in [0, 1, 17] {
        let workspace = TempRoot::create("guard-containment-exit-").expect("workspace");
        let command = format!("exit {status}");
        let request =
            request(&workspace.0, &argv(&[&shell, "-c", &command]), None).expect("request");
        let result = execute_contained(&request, 30.0).expect("execute");
        assert!(result.enforced(), "{}", result.stderr);
        assert_eq!(result.exit_code, Some(status));
        assert!(result.attestation.failure.is_none());
    }
}

#[test]
fn exec_failure_cannot_mint_an_enforcement_attestation() {
    if !provisioned() {
        return;
    }
    let workspace = TempRoot::create("guard-containment-execfail-").expect("workspace");
    let invalid = workspace.0.join("invalid-executable");
    // A missing shebang interpreter is a true exec startup failure. Plain text
    // without a shebang is intentionally eligible for POSIX /bin/sh fallback
    // and therefore is not evidence that containment failed to start.
    fs::write(&invalid, b"#!/definitely/missing/guard-interpreter\n").expect("write");
    fs::set_permissions(&invalid, fs::Permissions::from_mode(0o500)).expect("chmod");

    let path = invalid.to_string_lossy().into_owned();
    let request = request(&workspace.0, &argv(&[&path]), None).expect("request");
    let result = execute_contained(&request, 30.0).expect("execute");

    assert!(!result.enforced());
    assert_eq!(result.exit_code, None);
    assert!(result.attestation.failure.is_some());
}

/// Copy a directory tree, preserving symbolic links as links.
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create");
    for entry in fs::read_dir(source).expect("read_dir") {
        let entry = entry.expect("entry");
        let target = destination.join(entry.file_name());
        let metadata = entry.metadata().expect("metadata");
        let kind = entry.file_type().expect("file_type");
        if kind.is_symlink() {
            let link = fs::read_link(entry.path()).expect("read_link");
            std::os::unix::fs::symlink(link, target.as_path()).expect("symlink");
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
            fs::set_permissions(
                target.as_path(),
                fs::Permissions::from_mode(metadata.permissions().mode()),
            )
            .expect("chmod");
        }
    }
}

fn boundary_script(outside: &Path, host_marker: &Path, port: u16) -> String {
    let outside = serde_json::to_string(&outside.to_string_lossy()).expect("json");
    let host_marker = serde_json::to_string(&host_marker.to_string_lossy()).expect("json");
    format!(
        r#"import {{ test, expect }} from 'vitest';
import fs from 'node:fs';
import net from 'node:net';
test('contained runtime boundaries', async () => {{
  const value: number = 7;
  expect(value).toBe(7);
  for (const path of ['.env', {outside}]) {{
    expect(() => fs.readFileSync(path, 'utf8')).toThrow();
  }}
  expect(() => fs.writeFileSync({host_marker}, 'escaped')).toThrow();
  fs.writeFileSync('ephemeral-result.txt', 'snapshot only');
  await new Promise<void>((resolve, reject) => {{
    const socket = net.connect({{host: '127.0.0.1', port: {port}}});
    socket.setTimeout(1000);
    socket.on('connect', () => {{ socket.destroy(); reject(new Error('host network exposed')); }});
    socket.on('error', () => {{ socket.destroy(); resolve(); }});
    socket.on('timeout', () => {{ socket.destroy(); resolve(); }});
  }});
}});
"#
    )
}

#[test]
fn real_vitest_cannot_read_credentials_write_host_or_use_host_network() {
    if !provisioned() {
        return;
    }
    let fixture = fs::canonicalize(PathBuf::from(
        std::env::var_os("GUARD_VITEST_FIXTURE").expect("fixture"),
    ))
    .expect("fixture exists");
    let root = TempRoot::create("guard-containment-vitest-").expect("root");
    let workspace = root.0.join("workspace");
    copy_tree(&fixture, &workspace);
    fs::write(workspace.join(".env"), format!("GUARD_CANARY={SENTINEL}\n")).expect("env");
    let outside = root.0.join("outside.txt");
    fs::write(&outside, SENTINEL).expect("outside");
    let host_marker = root.0.join("must-not-exist.txt");

    // A real listener the contained child must not reach. Non-blocking accept
    // stands in for the Python socket timeout: a queued connection would be
    // returned instead of `WouldBlock`.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();

    fs::write(
        workspace.join("boundary.test.ts"),
        boundary_script(&outside, &host_marker, port),
    )
    .expect("script");

    let node = node_executable();
    let snapshot = complete_workspace_snapshot(&workspace, true).expect("snapshot");
    let request = request(
        &workspace,
        &argv(&[
            &node,
            "node_modules/vitest/vitest.mjs",
            "run",
            "boundary.test.ts",
            "--reporter=dot",
        ]),
        Some(snapshot),
    )
    .expect("request");

    let (health, fingerprint) = current_health().expect("health");
    assert!(health.probe_enforced, "{}", health.to_value());

    let result = execute_contained(&request, 90.0).expect("execute");
    assert!(result.enforced(), "{}", result.stderr);
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}{}",
        result.stdout,
        result.stderr
    );

    let proof = contained_positive_proof(
        &result.attestation,
        &request,
        &health,
        &EXECUTION_PROOF_REQUIREMENTS,
        now_micros(),
        &fingerprint,
    )
    .expect("proof");
    assert_eq!(proof.route, ProofRoute::Contained);
    assert!(proof.enforced);

    assert!(!format!("{}{}", result.stdout, result.stderr).contains(SENTINEL));
    assert!(!host_marker.exists());
    assert!(!workspace.join("ephemeral-result.txt").exists());
    assert_eq!(
        fs::read_to_string(outside.as_path()).expect("outside"),
        SENTINEL
    );
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the contained child reached the host listener"),
        Err(error) => panic!("unexpected accept failure: {error}"),
    }
}
