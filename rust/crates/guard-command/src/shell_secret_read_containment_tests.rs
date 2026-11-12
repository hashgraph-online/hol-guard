//! Containment-root and ripgrep hidden-mode coverage for the local read
//! operand checks, ported from the retired Python
//! `local_read_operands` regression tests. These shapes are not reachable
//! from the recorded operand vectors, which replay parsed command text and
//! never carry an unresolvable containment root.

use crate::shell_secret_read_support::{
    local_read_operands_resolve_safely, ripgrep_args_expand_hidden_files,
};
use std::fs;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn local_read_rejects_missing_containment_root() {
    let workspace = tempfile::tempdir().expect("workspace");
    let target = workspace.path().join("target.txt");
    fs::write(&target, "safe").expect("write target");

    assert!(!local_read_operands_resolve_safely(
        "cat",
        &args(&[target.to_str().expect("target path")]),
        workspace.path(),
        &workspace.path().join("missing"),
    ));
}

#[cfg(unix)]
#[test]
fn local_read_rejects_symlink_loop_root() {
    let workspace = tempfile::tempdir().expect("workspace");
    let loop_root = workspace.path().join("loop");
    std::os::unix::fs::symlink("loop", &loop_root).expect("symlink loop");

    assert!(!local_read_operands_resolve_safely(
        "cat",
        &args(&["target.txt"]),
        workspace.path(),
        &loop_root,
    ));
}

#[test]
fn ripgrep_hidden_mode_parser_handles_clusters_and_option_values() {
    assert!(ripgrep_args_expand_hidden_files(&args(&[
        "-Fu", "API_KEY", "."
    ])));
    assert!(ripgrep_args_expand_hidden_files(&args(&[
        "-.F", "API_KEY", "."
    ])));
    assert!(!ripgrep_args_expand_hidden_files(&args(&[
        "-g*.ts", "API_KEY", "."
    ])));
    assert!(!ripgrep_args_expand_hidden_files(&args(&[
        "-g", "-u", "API_KEY", "."
    ])));
    assert!(!ripgrep_args_expand_hidden_files(&args(&["--", "-u", "."])));
}
