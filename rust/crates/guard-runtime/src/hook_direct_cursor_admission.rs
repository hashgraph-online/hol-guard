//! The exact sink command a Cursor `beforeShellExecution` may run: one a
//! route probe wrote, naming Guard's sink or the runtime's own.

use super::{command, same_directory, CursorDefer, Scope, CURSOR, NATIVE_SINK_VERB, SINK_VERB};
use serde_json::{Map, Value};
use std::path::Path;

const SINK_FLAGS: [&str; 4] = [
    "--workspace",
    "--request-file",
    "--request-sha256",
    "--home",
];

pub(super) fn admitted(payload: &Map<String, Value>, scope: &Scope) -> Result<(), CursorDefer> {
    let Some(argv) =
        command(payload).and_then(|text| crate::mcp_proxy_shlex::split_with(text, "", ""))
    else {
        return Err(CursorDefer::SinkArgv);
    };
    let guard_head: Vec<&str> = scope
        .sink_command
        .iter()
        .map(String::as_str)
        .chain(["guard", SINK_VERB])
        .collect();
    let executable = std::env::current_exe().ok();
    let native_head: Option<Vec<&str>> = executable
        .as_deref()
        .and_then(Path::to_str)
        .filter(|_| scope.native)
        .map(|executable| vec![executable, NATIVE_SINK_VERB]);
    // The probe writes either Guard's sink or, for a call the runtime's own
    // sink reproduces, this runtime's: both re-authorize the saved call. Only
    // a scope that routes to the runtime's sink admits it, so a daemon that
    // never asked for it reviews that command as usual.
    let start = if argv.get(guard_head.len() - 1).map(String::as_str) == Some(SINK_VERB) {
        guard_head
    } else {
        native_head.ok_or(CursorDefer::SinkArgv)?
    };
    let head: Vec<&str> = start
        .into_iter()
        .chain(["--harness", CURSOR, "--guard-home"])
        .chain([scope.guard_home.as_str()])
        .collect();
    if argv.len() != head.len() + 2 * SINK_FLAGS.len()
        || argv
            .iter()
            .zip(&head)
            .any(|(argument, expected)| argument != expected)
    {
        return Err(CursorDefer::SinkArgv);
    }
    let tail = &argv[head.len()..];
    if tail
        .iter()
        .step_by(2)
        .zip(SINK_FLAGS)
        .any(|(flag, expected)| flag != expected)
    {
        return Err(CursorDefer::SinkArgv);
    }
    let [workspace, request, digest, home] = [&tail[1], &tail[3], &tail[5], &tail[7]];
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CursorDefer::SinkArgv);
    }
    if *home != scope.home_dir {
        return Err(CursorDefer::SinkHome);
    }
    if !same_directory(workspace, scope) {
        return Err(CursorDefer::SinkWorkspace);
    }
    if !snapshot_under_temp(Path::new(request)) {
        return Err(CursorDefer::SinkSnapshot);
    }
    Ok(())
}

/// Whether `request` is a snapshot the rewrite writes: a file in its own
/// directory under the temporary directory.
fn snapshot_under_temp(request: &Path) -> bool {
    if !request.is_absolute() {
        return false;
    }
    let Some(root) = request.parent().and_then(Path::parent) else {
        return false;
    };
    match (
        std::fs::canonicalize(root),
        std::fs::canonicalize(std::env::temp_dir()),
    ) {
        (Ok(root), Ok(temp)) => root == temp,
        _ => false,
    }
}
