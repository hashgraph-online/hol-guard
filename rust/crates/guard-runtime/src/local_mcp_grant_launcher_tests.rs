//! Package-launcher equivalence vectors.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use guard_contracts::LocalMcpGrantRequestV1;
use rusqlite::params;

use super::{hash, state, Rig, TOOL};
use crate::local_mcp_grant_identity::slug_command_id;

const ARGS: [&str; 2] = ["-y", "@scope/pkg@1.0.0"];

fn identity(command: &str) -> guard_command::mcp_decision::McpServerIdentity {
    let args: Vec<String> = ARGS.iter().map(|arg| (*arg).to_owned()).collect();
    guard_command::mcp_decision::build_mcp_server_identity("", command, &args, "stdio", None, &[])
}

/// A stored `npx` launch, plus a request that reaches the same executable
/// through an absolute path and so carries a different identity hash.
fn rig_with_launcher() -> (Rig, PathBuf, LocalMcpGrantRequestV1) {
    let rig = Rig::new();
    let bin = rig.home.join("bin");
    fs::create_dir(&bin).unwrap();
    let npx = bin.join("npx");
    fs::write(&npx, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&npx, fs::Permissions::from_mode(0o755)).unwrap();
    let stored = identity("npx");
    rig.connection
        .execute(
            "insert into local_cli_observation values ('local-cli.mcp-s', ?1, ?2, \
             '2026-01-01', 'mcp', ?1, 'npx')",
            params![stored.identity_hash, "npx -y @scope/pkg@1.0.0"],
        )
        .unwrap();
    rig.connection
        .execute(
            "insert into local_cli_grant values ('local-cli.mcp-s', ?1, 'allowed', 1, 'x')",
            params![stored.identity_hash],
        )
        .unwrap();
    rig.command("local-cli.mcp-s", &slug_command_id(TOOL), Some("allow"));
    let runtime = identity(&npx.to_string_lossy());
    let mut request = rig.request(&runtime.identity_hash, TOOL, "allow");
    request.server.command = Some(npx.to_string_lossy().into_owned());
    request.server.package_name = runtime.package_name.clone();
    request.server.package_version = runtime.package_version.clone();
    request.server.package_source = Some(runtime.package_source.clone());
    request.server.env_values_hash = Some(runtime.env_values_hash.clone());
    request.launcher_path = Some(bin.to_string_lossy().into_owned());
    (rig, npx, request)
}

#[test]
fn equivalent_launchers_resolve_to_the_stored_grant() {
    let (_rig, _npx, mut request) = rig_with_launcher();
    assert_eq!(state(&request), "allowed");
    // The calling process's PATH, not the resident's, resolves the stored `npx`.
    request.launcher_path = Some(String::new());
    assert_eq!(state(&request), "none");
}

#[test]
fn launcher_equivalence_never_crosses_package_or_environment() {
    let (_rig, _npx, request) = rig_with_launcher();
    let edits: [fn(&mut LocalMcpGrantRequestV1); 5] = [
        |r| r.server.package_name = Some("@scope/other".to_owned()),
        |r| r.server.package_version = Some("2.0.0".to_owned()),
        |r| r.server.package_source = Some("other-source".to_owned()),
        |r| r.server.env_values_hash = Some("e".repeat(64)),
        |r| r.server.env_values_hash = None,
    ];
    for edit in edits {
        let mut other = request.clone();
        edit(&mut other);
        assert_eq!(state(&other), "none");
    }
}

#[test]
fn ambiguous_launcher_matches_resolve_to_nothing() {
    let (rig, _npx, request) = rig_with_launcher();
    let stored = identity("npx");
    rig.connection
        .execute(
            "insert into local_cli_observation values ('local-cli.mcp-t', ?1, ?2, \
             '2026-01-02', 'mcp', ?1, 'npx')",
            params![stored.identity_hash, "npx -y @scope/pkg@1.0.0"],
        )
        .unwrap();
    rig.connection
        .execute(
            "insert into local_cli_grant values ('local-cli.mcp-t', ?1, 'allowed', 1, 'x')",
            params![stored.identity_hash],
        )
        .unwrap();
    assert_eq!(state(&request), "none");
    let _ = hash('a');
}
