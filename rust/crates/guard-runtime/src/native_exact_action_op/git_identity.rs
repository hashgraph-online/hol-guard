//! Config-bound identity for an allowlisted read-only git command.

use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::git_config::git_config_digest;
use super::reasons::{Proof, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH};

const GLOBAL_OPTIONS: [&str; 2] = ["--no-pager", "--no-optional-locks"];
const READ_SUBCOMMANDS: [&str; 6] = ["status", "log", "diff", "show", "rev-parse", "ls-files"];
/// Options that write files, name helper programs, or redirect git's own lookup.
const FORBIDDEN_PREFIXES: [&str; 15] = [
    "--output",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "--config",
    "--upload-pack",
    "--receive-pack",
    "--open-files-in-pager",
    "--paginate",
    "--ext-diff",
    "--textconv",
    "--namespace",
    "--super-prefix",
    "--show-signature",
    "-O",
];
/// A `%G` placeholder in a log/show format verifies signatures with gpg.program.
const SIGNATURE_PLACEHOLDER: &str = "%G";
const BRANCH_FLAGS: [&str; 11] = [
    "-a",
    "-r",
    "-v",
    "-vv",
    "--all",
    "--remotes",
    "--verbose",
    "--list",
    "--show-current",
    "--no-color",
    "--color",
];
const WORKTREE_LIST_FLAGS: [&str; 3] = ["--porcelain", "-v", "--verbose"];

/// `git_readonly_identity`; `system` lists the machine-wide config and
/// attribute files the bound git reads.
pub(super) fn git_readonly_identity(
    arguments: &[String],
    cwd: &str,
    system: &[String],
    ctx: &Ctx,
) -> Proof<Value> {
    let mut target = cwd.to_owned();
    let mut index = 0;
    let mut changed_dir = false;
    while index < arguments.len() && arguments[index].starts_with('-') {
        let option = arguments[index].as_str();
        if GLOBAL_OPTIONS.contains(&option) {
            index += 1;
        } else if option == "-C"
            && !changed_dir
            && index + 1 < arguments.len()
            && !arguments[index + 1].starts_with('-')
        {
            target = directory(&arguments[index + 1], cwd)?;
            changed_dir = true;
            index += 2;
        } else {
            // -c, --exec-path, --git-dir, --work-tree, -p and unknown options.
            return Err(MUTABLE_LAUNCHER);
        }
    }
    if index >= arguments.len() {
        return Err(MUTABLE_LAUNCHER);
    }
    let subcommand = arguments[index].as_str();
    if !subcommand_is_read_only(subcommand, &arguments[index + 1..]) {
        return Err(MUTABLE_LAUNCHER);
    }
    let (root, git_dir, common_dir) = repository(&target)?;
    let invocation = &arguments[index..];
    let config_digest = git_config_digest(&root, &git_dir, &common_dir, system, invocation, ctx)?;
    Ok(json!({
        "kind": "git-readonly",
        "subcommand": subcommand,
        "target": target,
        "repository": root,
        "config_digest": config_digest,
    }))
}

fn subcommand_is_read_only(subcommand: &str, rest: &[String]) -> bool {
    let forbidden = rest.iter().any(|argument| {
        FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| argument.starts_with(prefix))
            || argument == "-c"
            || argument.contains(SIGNATURE_PLACEHOLDER)
    });
    if forbidden {
        return false;
    }
    if READ_SUBCOMMANDS.contains(&subcommand) {
        return true;
    }
    match subcommand {
        "branch" => {
            let flags: Vec<&String> = rest
                .iter()
                .filter(|argument| argument.starts_with('-'))
                .collect();
            let has_positionals = rest.iter().any(|argument| !argument.starts_with('-'));
            flags
                .iter()
                .all(|flag| BRANCH_FLAGS.contains(&flag.as_str()))
                && (!has_positionals || flags.iter().any(|flag| flag.as_str() == "--list"))
        }
        "remote" => {
            rest.is_empty() || (rest.len() == 1 && matches!(rest[0].as_str(), "-v" | "--verbose"))
        }
        "worktree" => {
            !rest.is_empty()
                && rest[0] == "list"
                && rest[1..]
                    .iter()
                    .all(|flag| WORKTREE_LIST_FLAGS.contains(&flag.as_str()))
        }
        _ => false,
    }
}

/// A strict-resolved directory, relative to `cwd`.
fn directory(value: &str, cwd: &str) -> Proof<String> {
    let joined = fs_path::join(cwd, value);
    let resolved = fs_path::resolve_strict(&joined).ok_or(UNPROVEN_LAUNCH)?;
    if fs_path::is_dir(&resolved) {
        Ok(resolved)
    } else {
        Err(UNPROVEN_LAUNCH)
    }
}

/// `(worktree root, git dir, common dir)` of the repository containing `start`.
fn repository(start: &str) -> Proof<(String, String, String)> {
    let mut directories = vec![fs_path::norm(start)];
    directories.extend(fs_path::parents(start));
    for dir in directories {
        let marker = fs_path::join(&dir, ".git");
        if fs_path::is_dir(&marker) {
            return Ok((dir, marker.clone(), marker));
        }
        if fs_path::is_file(&marker) {
            let bytes = std::fs::read(&marker).map_err(|_| UNPROVEN_LAUNCH)?;
            let text = String::from_utf8_lossy(&bytes);
            let rest = text.trim().strip_prefix("gitdir:").ok_or(UNPROVEN_LAUNCH)?;
            let git_dir = fs_path::resolve_strict(&fs_path::join(&dir, rest.trim()))
                .ok_or(UNPROVEN_LAUNCH)?;
            let mut common = git_dir.clone();
            let pointer = fs_path::join(&git_dir, "commondir");
            if fs_path::is_file(&pointer) {
                let pointed = std::fs::read_to_string(&pointer).map_err(|_| UNPROVEN_LAUNCH)?;
                common = fs_path::resolve_strict(&fs_path::join(&git_dir, pointed.trim()))
                    .ok_or(UNPROVEN_LAUNCH)?;
            }
            return Ok((dir, git_dir, common));
        }
    }
    Err(UNPROVEN_LAUNCH)
}
