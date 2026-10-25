//! Native authority for verified local Vitest and TypeScript execution.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jsonc::loads_jsonc;
use crate::shell_execution_context::{
    model_shell_execution_context_bounded, ShellExecutionContext, ShellExecutionSegment,
    ShellModelLimits,
};

#[cfg(all(test, unix))]
#[path = "direct_tool_parity_tests.rs"]
mod parity_tests;

#[cfg(all(test, unix))]
#[path = "direct_tool_public_tests.rs"]
mod public_tests;

/// Immutable caller facts and resident-owned filesystem trust. Implementations
/// must never consult or mutate the resident process's ambient environment.
pub trait DirectToolAuthority {
    fn environment(&self) -> &BTreeMap<String, String>;
    fn trusted_command(&self, command: &str, cwd: &Path, home: &Path) -> bool;
    fn trusted_path(&self, path: &Path, cwd: &Path) -> bool;
    fn executable_file(&self, path: &Path) -> bool;
    fn temp_directory(&self) -> &Path;
    fn within_budget(&self) -> bool;
    fn deadline(&self) -> Option<std::time::Instant> {
        None
    }
    fn typescript_package_digest(&self, version: &str, integrity: &str) -> Option<&str> {
        trusted_typescript_package_digest(version, integrity)
    }
}

fn model_shell_execution_context(
    script: &str,
    cwd: Option<&Path>,
    workspace: Option<&Path>,
    home: Option<&Path>,
    authority: &dyn DirectToolAuthority,
) -> Option<ShellExecutionContext> {
    model_shell_execution_context_bounded(
        script,
        cwd,
        workspace,
        home,
        &ShellModelLimits {
            max_segments: 4096,
            max_segment_proofs: 4096,
            max_total_proofs: 64 * 1024,
            deadline: authority.deadline(),
        },
    )
    .ok()
}

fn read_bounded_bytes(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file exceeds limit"));
    }
    Ok(bytes)
}

fn read_bounded_text(path: &Path, limit: u64) -> std::io::Result<String> {
    String::from_utf8(read_bounded_bytes(path, limit)?)
        .map_err(|_| std::io::Error::other("invalid UTF-8"))
}

// ---------------------------------------------------------------------------
// Module constants (:27-41).
// ---------------------------------------------------------------------------

const LOCKFILE_NAMES: &[&str] = &["bun.lock", "package-lock.json"];
const DEPENDENCY_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PACKAGE_TREE_FILES: usize = 10_000;

/// `_TRUSTED_TYPESCRIPT_PACKAGES` (:35-40) — (version, integrity) -> sha256
/// package-tree digest.
fn trusted_typescript_package_digest(version: &str, integrity: &str) -> Option<&'static str> {
    if version == "5.9.3"
        && integrity
            == "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw=="
    {
        Some("e5e331517b5c57cef26c6ed1c1dd2193ed52002a49a276cf7971b499c7f83b0f")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Public entry points (defmap order).
// ---------------------------------------------------------------------------

/// `direct_local_vitest_execution_context` (:44-116).
pub fn direct_local_vitest_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> Option<ShellExecutionContext> {
    if !authority.within_budget() {
        return None;
    }
    let initial_root = cwd.unwrap_or(home_dir);
    let context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
        authority,
    )?;
    let workspace = literal_leading_cd_target(&context, initial_root, home_dir)?;
    let context = model_shell_execution_context(
        command_text,
        Some(&workspace),
        Some(&workspace),
        Some(home_dir),
        authority,
    )?;
    if !context.complete || context.segments.len() != 3 {
        return None;
    }
    let directory = &context.segments[0];
    let runner = &context.segments[1];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || runner.control_before != ["&&"]
        || runner.effective_cwd.as_deref() != Some(workspace.as_path())
    {
        return None;
    }
    let mut runner_tokens = runner.tokens.clone();
    if runner_tokens.last().map(|s| s.as_str()) != Some("2>&1") {
        return None;
    }
    runner_tokens.pop();
    if runner_tokens.len() < 4 || runner_tokens.iter().any(|t| has_shell_dynamics(t)) {
        return None;
    }
    let (runner_path, args, require_no_coverage) =
        vitest_runner_invocation(&runner_tokens, &workspace, home_dir, authority);
    let runner_path = runner_path?;
    let installed_version = verified_vitest_runner(&runner_path, &workspace, home_dir, authority)?;
    if !workspace_vitest_version_is_bound(&workspace, &installed_version) {
        return None;
    }
    let no_coverage_count = args
        .iter()
        .filter(|a| a.as_str() == "--no-coverage")
        .count();
    if args.is_empty()
        || args[0] != "run"
        || no_coverage_count > 1
        || (require_no_coverage && no_coverage_count != 1)
    {
        return None;
    }
    let targets: Vec<&String> = args[1..]
        .iter()
        .filter(|arg| arg.as_str() != "--no-coverage")
        .collect();
    if targets.is_empty() || targets.iter().any(|arg| arg.starts_with('-')) {
        return None;
    }
    if !targets
        .iter()
        .all(|target| contained_test_target(target, &workspace))
    {
        return None;
    }
    if !bounded_output_filter(
        &context.segments[2].tokens,
        &context.segments[2].control_before,
        &workspace,
        home_dir,
        authority,
    ) {
        return None;
    }
    authority.within_budget().then_some(context)
}

/// `direct_local_typescript_execution_context` (:119-186).
pub fn direct_local_typescript_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> Option<ShellExecutionContext> {
    let initial_root = cwd.unwrap_or(home_dir);
    let initial_context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
        authority,
    )?;
    let workspace = literal_leading_cd_target(&initial_context, initial_root, home_dir)?;
    let context = model_shell_execution_context(
        command_text,
        Some(&workspace),
        Some(&workspace),
        Some(home_dir),
        authority,
    )?;
    let diagnostic_filter_context =
        direct_typescript_diagnostic_filter_context(&context, &workspace, home_dir, authority);
    if diagnostic_filter_context.is_some() {
        return diagnostic_filter_context;
    }
    if !context.complete || context.segments.len() != 5 {
        return None;
    }
    let directory = &context.segments[0];
    let compiler = &context.segments[1];
    let grep = &context.segments[2];
    let count = &context.segments[3];
    let marker = &context.segments[4];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || compiler.control_before != ["&&"]
        || compiler.effective_cwd.as_deref() != Some(workspace.as_path())
        || grep.control_before != ["|"]
        || count.control_before != ["|"]
        || marker.control_before != [";"]
    {
        return None;
    }
    let mut compiler_tokens = compiler.tokens.clone();
    if compiler_tokens.last().map(|s| s.as_str()) != Some("2>&1") {
        return None;
    }
    compiler_tokens.pop();
    if compiler_tokens.len() != 5
        || !safe_node_heap_assignment(&compiler_tokens[0])
        || compiler_tokens[1..]
            != [
                "bun".to_owned(),
                "--smol".to_owned(),
                "./node_modules/typescript/bin/tsc".to_owned(),
                "--noEmit".to_owned(),
            ]
        || !trusted_path_command("bun", &workspace, home_dir, authority)
        || bun_runtime_config_exists(&workspace, home_dir, authority)
        || !workspace_typescript_is_bound(&workspace, authority)
    {
        return None;
    }
    if grep.tokens != ["grep".to_owned(), "error TS".to_owned()]
        || count.tokens != ["wc".to_owned(), "-l".to_owned()]
        || !trusted_path_command("grep", &workspace, home_dir, authority)
        || !trusted_path_command("wc", &workspace, home_dir, authority)
    {
        return None;
    }
    if marker.tokens != ["echo".to_owned(), "MY_TSC_ERRORS_COUNT_DONE".to_owned()] {
        return None;
    }
    Some(context)
}

/// `_safe_node_heap_assignment` (:188-190).
fn safe_node_heap_assignment(token: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})$").unwrap()
    });
    match RE.captures(token) {
        Some(caps) => caps[1]
            .parse::<u32>()
            .map(|value| (256..=32768).contains(&value))
            .unwrap_or(false),
        None => false,
    }
}

#[path = "direct_tool_metadata.rs"]
mod direct_tool_metadata;
use direct_tool_metadata::*;

#[path = "direct_tool_paths.rs"]
mod direct_tool_paths;
use direct_tool_paths::*;

#[path = "direct_tool_encoding.rs"]
mod direct_tool_encoding;
use direct_tool_encoding::*;

#[path = "direct_tool_semver.rs"]
mod direct_tool_semver;
pub(crate) use direct_tool_semver::semver_spec_matches;

#[cfg(test)]
#[path = "direct_tool_semver_tests.rs"]
mod direct_tool_semver_tests;

#[path = "direct_tool_environment.rs"]
mod direct_tool_environment;
use direct_tool_environment::*;

#[path = "direct_tool_typescript.rs"]
mod direct_tool_typescript;
use direct_tool_typescript::*;
