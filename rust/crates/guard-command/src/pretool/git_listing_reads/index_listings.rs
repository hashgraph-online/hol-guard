//! The two plumbing listings that answer out of the index and the
//! repository's own layout: `git rev-parse` and `git ls-files`. Both print
//! what Git already holds and open no file the caller names, so each is read
//! by its flag grammar alone, and a spelling this pass has not read keeps
//! its review.

/// `rev-parse` flags that only choose which resolved form is printed, or
/// which question about the repository's own layout is answered. A plumbing
/// spelling that rewrites its arguments instead of resolving them —
/// `--parseopt`, `--sq-quote`, `--resolve-git-dir`, `--git-path` — is a
/// grammar this pass has not read, so it keeps its review.
const REV_PARSE_FLAGS: [&str; 16] = [
    "--verify",
    "-q",
    "--quiet",
    "--short",
    "--symbolic",
    "--symbolic-full-name",
    "--abbrev-ref",
    "--git-dir",
    "--absolute-git-dir",
    "--git-common-dir",
    "--show-toplevel",
    "--show-prefix",
    "--show-cdup",
    "--is-inside-work-tree",
    "--is-inside-git-dir",
    "--is-bare-repository",
];

/// `git rev-parse` prints what the revisions it is given resolve to, and the
/// paths of the repository it is standing in. It opens no file the caller
/// names and expands no format, so the grammar is the flag list and
/// revisions, which are words rather than options.
pub(super) fn rev_parse_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments
                .as_slice()
                .iter()
                .all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if REV_PARSE_FLAGS.contains(&argument.as_str()) || super::short_bundle(argument, "q") {
            continue;
        }
        // `--short=<n>` abbreviates to a width, and `--abbrev-ref=<mode>`
        // chooses how much of a ref name is dropped. Both print the same
        // revision the bare flag prints.
        if let Some(width) = argument.strip_prefix("--short=") {
            if !width.is_empty() && width.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
        }
        if matches!(
            argument.as_str(),
            "--abbrev-ref=strict" | "--abbrev-ref=loose"
        ) {
            continue;
        }
        return false;
    }
    true
}

/// `ls-files` flags that only choose which of the paths the index already
/// knows are printed, and how. `--exclude-from`/`-X` and
/// `--exclude-per-directory` read a file the caller names, `--format`
/// expands placeholders, `--with-tree` reads another tree, and
/// `--recurse-submodules` walks repositories with configuration this probe
/// never saw. None of those is here, so each keeps its review.
const LS_FILES_FLAGS: [&str; 25] = [
    "-c",
    "--cached",
    "-d",
    "--deleted",
    "-m",
    "--modified",
    "-o",
    "--others",
    "-i",
    "--ignored",
    "-s",
    "--stage",
    "-u",
    "--unmerged",
    "-k",
    "--killed",
    "-t",
    "-v",
    "-z",
    "--exclude-standard",
    "--full-name",
    "--directory",
    "--no-empty-directory",
    "--error-unmatch",
    "--deduplicate",
];

/// Whether an `ls-files` read asks which tracked files differ from the index.
/// Git answers that by comparing the working-tree copy with the stored blob,
/// and when the stat data alone cannot decide it reads the file and converts
/// it to its stored form, which runs the repository's clean filters. Only the
/// modified selector asks for that comparison: the deleted, untracked, killed
/// and unmerged selectors are answered from `lstat`, the directory walk and
/// the index alone, so none of them hashes a file.
pub(in crate::pretool) fn compares_working_tree(subcommand: &str, rest: &[String]) -> bool {
    subcommand == "ls-files"
        && rest
            .iter()
            .take_while(|argument| *argument != "--")
            .any(|argument| {
                argument == "-m"
                    || argument == "--modified"
                    || (super::short_bundle(argument, "cdmoisuktvz") && argument.contains('m'))
            })
}

/// `git ls-files` prints the paths the index holds, optionally compared
/// against the files on disk. The operands are pathspecs the index is
/// matched against, never files it opens.
pub(super) fn ls_files_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments
                .as_slice()
                .iter()
                .all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if LS_FILES_FLAGS.contains(&argument.as_str())
            || super::short_bundle(argument, "cdmoisuktvz")
        {
            continue;
        }
        // `--abbrev[=<n>]` shortens the object names `--stage` prints.
        if argument == "--abbrev" {
            continue;
        }
        if let Some(width) = argument.strip_prefix("--abbrev=") {
            if !width.is_empty() && width.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
        }
        return false;
    }
    true
}
