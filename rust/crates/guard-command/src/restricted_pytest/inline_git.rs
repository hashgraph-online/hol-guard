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

static GIT_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^A-Za-z0-9_./-])git(?:$|[^A-Za-z0-9_.-])").unwrap());

/// The Git an inline program names, when it resolves to a trusted system
/// executable outside the workspace. A program that never names Git, or a Git
/// the workspace or an untrusted prefix provides, adds nothing.
pub(super) fn trusted_git(
    program: &[String],
    cwd: &Path,
    workspace: &Path,
    search_path: &str,
) -> Option<PathBuf> {
    if !program.iter().any(|word| GIT_WORD.is_match(word)) {
        return None;
    }
    let git = resolve_executable("git", cwd, search_path).ok()?;
    let trusted = !path_is_within_lexically(&git, workspace)
        && (path_is_within_any(&git, &TRUSTED_EXECUTABLE_ROOTS)
            || super::developer_shim::is_developer_tool(&git))
        && executable_symlink_chain_is_approved(&git, workspace, None, &git);
    trusted.then_some(git)
}
