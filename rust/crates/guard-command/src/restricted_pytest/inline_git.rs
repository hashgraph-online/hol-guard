//! The trusted Git an inline program may start inside its read-only sandbox.
//!
//! The pre-tool pass contains an inline program that runs Git only when the
//! Git it runs reads the work tree; one that discards work keeps its review.
//! The evaluation sandbox execs only the executables its plan names, so
//! without Git in that list the read the hook judged containable fails with
//! "No such file or directory" instead of running. The sandbox still denies
//! every workspace write, the network and any other program, so a Git it
//! starts can read the repository and nothing more.
use super::*;
use serde_json::{json, Value};

/// What a contained Git is told: read no system config (the sandbox withholds
/// it, and Git stops on a config it cannot open), take no optional lock,
/// never prompt and never fetch.
pub(super) const GIT_SETTINGS: [(&str, &str); 4] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
];

/// Whether a plan's executables include a Git.
pub(super) fn runs_git(allowed: &[PathBuf]) -> bool {
    allowed
        .iter()
        .any(|path| path.file_name().is_some_and(|name| name == "git"))
}

/// `git` as a word of its own, or the last part of an absolute path. The
/// directory, when there is one, is captured; a relative path such as
/// `./git` or `tools/git` never matches.
static GIT_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_./-])((?:/[A-Za-z0-9_.-]+)*/)?git(?:$|[^A-Za-z0-9_.-])").unwrap()
});

/// Each Git an inline program names that is a trusted executable outside the
/// workspace: a bare `git` resolved on the run's search path, and every
/// absolute path to one. A program that never names Git, or a Git the
/// workspace or an untrusted prefix provides, adds nothing.
pub(super) fn trusted_gits(
    program: &[String],
    cwd: &Path,
    workspace: &Path,
    search_path: &str,
) -> Vec<PathBuf> {
    let mut gits = Vec::new();
    for word in program {
        for found in GIT_WORD.captures_iter(word) {
            let git = match found.get(1) {
                // macOS's `/usr/bin/git` is a shim that asks `xcode-select`
                // for its tool, which a contained run cannot do (see
                // `developer_shim`). Named by path, it stays out of the plan;
                // a bare `git` resolves past the shim to the tool itself.
                Some(directory) => {
                    let git = PathBuf::from(format!("{}git", directory.as_str()));
                    if super::developer_shim::forwarded_tool(&git).is_some() {
                        continue;
                    }
                    git
                }
                None => match resolve_executable("git", cwd, search_path) {
                    Ok(git) => git,
                    Err(_) => continue,
                },
            };
            let trusted = git.is_absolute()
                && git.is_file()
                && !path_is_within_lexically(&git, workspace)
                && (path_is_within_any(&git, &TRUSTED_EXECUTABLE_ROOTS)
                    || super::developer_shim::is_developer_tool(&git))
                && executable_symlink_chain_is_approved(&git, workspace, None, &git);
            if trusted && !gits.contains(&git) {
                gits.push(git);
            }
        }
    }
    gits
}

/// Name each trusted Git the program runs in the plan, with the linked
/// worktree metadata it has to read. When that metadata cannot be safely
/// resolved, no Git is added and the program's Git call fails closed.
pub(super) fn grant(plan: &mut Value, program: &[String], search_path: &str) {
    let (Some(workspace), Some(cwd)) = (
        plan["workspace"].as_str().map(PathBuf::from),
        plan["cwd"].as_str().map(PathBuf::from),
    ) else {
        return;
    };
    let gits = trusted_gits(program, &cwd, &workspace, search_path);
    if gits.is_empty() {
        return;
    }
    let Some(roots) = super::git_plan::repository_read_roots(&workspace, &cwd) else {
        return;
    };
    let Some(allowed) = plan["allowed_executables"].as_array_mut() else {
        return;
    };
    for git in gits {
        let git = json!(git);
        if !allowed.contains(&git) {
            allowed.push(git);
        }
    }
    if roots.is_empty() {
        return;
    }
    if !plan["read_only_roots"].is_array() {
        plan["read_only_roots"] = json!([]);
    }
    let granted = plan["read_only_roots"].as_array_mut().unwrap();
    for root in roots {
        let root = json!(root);
        if !granted.contains(&root) {
            granted.push(root);
        }
    }
}
