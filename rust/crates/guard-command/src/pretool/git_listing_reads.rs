//! The git subcommands that only print: `shortlog`, `check-ignore`,
//! `count-objects`, `check-attr`, `sparse-checkout list`, `rev-parse` and
//! `ls-files`.
//!
//! `shortlog` counts the commits history already holds, `check-ignore`
//! answers which ignore rule a path matches, `count-objects` reports how much
//! the object store holds, `check-attr` answers which attributes apply to a
//! path, and `sparse-checkout list` prints the patterns the working tree is
//! already narrowed to, `rev-parse` prints what a revision the caller named
//! resolves to, and `ls-files` prints the paths the index already holds.
//! None writes a ref, an object or a file, and none
//! reads a file's contents. All still run under the repository's
//! configuration, so the configuration probe clears them before the read is
//! proven, and options outside these lists keep their review.

/// `shortlog` flags that take no value. `-w` carries an optional inline
/// width instead, which [`shortlog_read_form`] checks.
const SHORTLOG_FLAGS: [&str; 10] = [
    "-n",
    "--numbered",
    "-s",
    "--summary",
    "-e",
    "--email",
    "-c",
    "--committer",
    "--all",
    "--no-merges",
];

/// `shortlog` options whose value names a grouping or a commit range.
///
/// `--format` and `--pretty` are not here. A pretty format expands `%G`,
/// which verifies signatures through the configured program, so a shortlog
/// that carries one keeps its review the way every other history read with
/// one does. `--group` reaches the same expansion through
/// `--group=format:<format>`, so [`shortlog_value`] admits only the groupings
/// that name a field of the commit itself.
const SHORTLOG_VALUES: [&str; 2] = ["--group", "--max-count"];

/// Whether the value one of those options carries is a proven read.
fn shortlog_value(name: &str, value: &str) -> bool {
    match name {
        "--group" => {
            matches!(value, "author" | "committer")
                || value.strip_prefix("trailer:").is_some_and(trailer_token)
        }
        "--max-count" => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        _ => false,
    }
}

/// Whether a `trailer:` grouping names a trailer the way a commit message
/// writes one: the key before the colon, which is a header name.
fn trailer_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `check-ignore` flags. All of them change what is printed and nothing else.
const CHECK_IGNORE_FLAGS: [&str; 6] = ["-q", "--quiet", "-v", "--verbose", "-z", "--no-index"];

/// `count-objects` flags. Both only change how the counts are printed; the
/// command takes no operand at all.
const COUNT_OBJECTS_FLAGS: [&str; 4] = ["-v", "--verbose", "-H", "--human-readable"];

/// `check-attr` flags. `--cached` reads the attributes from the index instead
/// of the work tree, and the rest change what is printed.
const CHECK_ATTR_FLAGS: [&str; 4] = ["-a", "--all", "--cached", "-z"];

/// Whether the listing reads the index, which can start `core.fsmonitor`.
/// `check-ignore` consults the index unless `--no-index` is given; a shortlog
/// reads commits and never the index.
pub(crate) fn reads_index(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "check-ignore" => !options(rest).any(|argument| argument == "--no-index"),
        // Attributes come from the index whether or not `--cached` keeps the
        // work tree out of it.
        "check-attr" => true,
        // Every `ls-files` spelling prints what the index holds, and the
        // working-tree ones compare it against the files on disk.
        "ls-files" => true,
        // A revision only reaches the index through an index-stage spelling
        // such as `:path` or `:0:path`; `HEAD` and the repository questions
        // are answered out of the object store and the configuration.
        "rev-parse" => options(rest).any(|argument| argument.starts_with(':')),
        // A count walks the object store and never the index.
        _ => false,
    }
}

/// Whether the listing prints the rule that matched and the file it came
/// from, which `check-ignore` does in its verbose form. That file is
/// `core.excludesFile` as often as it is the repository's own `.gitignore`.
pub(crate) fn prints_rule_source(subcommand: &str, rest: &[String]) -> bool {
    subcommand == "check-ignore"
        && options(rest).any(|argument| {
            matches!(argument, "-v" | "--verbose")
                || (short_bundle(argument, "qvz") && argument.contains('v'))
        })
}

/// The words before `--`, which are the only ones Git reads as options.
fn options(rest: &[String]) -> impl Iterator<Item = &str> {
    rest.iter()
        .take_while(|argument| *argument != "--")
        .map(String::as_str)
}

/// Whether `subcommand rest...` is a proven listing read.
pub(crate) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "shortlog" => shortlog_read_form(rest),
        "check-ignore" => check_ignore_read_form(rest),
        "count-objects" => count_objects_read_form(rest),
        "check-attr" => check_attr_read_form(rest),
        "sparse-checkout" => sparse_checkout_read_form(rest),
        "rev-parse" => rev_parse_read_form(rest),
        "ls-files" => ls_files_read_form(rest),
        _ => false,
    }
}

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
fn rev_parse_read_form(rest: &[String]) -> bool {
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
        if REV_PARSE_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "q") {
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
pub(super) fn compares_working_tree(subcommand: &str, rest: &[String]) -> bool {
    subcommand == "ls-files"
        && rest
            .iter()
            .take_while(|argument| *argument != "--")
            .any(|argument| {
                argument == "-m"
                    || argument == "--modified"
                    || (short_bundle(argument, "cdmoisuktvz") && argument.contains('m'))
            })
}

/// `git ls-files` prints the paths the index holds, optionally compared
/// against the files on disk. The operands are pathspecs the index is
/// matched against, never files it opens.
fn ls_files_read_form(rest: &[String]) -> bool {
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
        if LS_FILES_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "cdmoisuktvz") {
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

/// Whether a `sparse-checkout` spelling is the one that only prints.
///
/// `list` writes nothing: it prints the patterns `.git/info/sparse-checkout`
/// already holds. Every other spelling — `init`, `set`, `add`, `reapply`,
/// `disable`, and `check-rules`, which reads the patterns off its own input —
/// narrows or widens the working tree, so each keeps its review. `list` takes
/// no options of its own, so a word beside it is a spelling this grammar has
/// not read.
fn sparse_checkout_read_form(rest: &[String]) -> bool {
    rest.len() == 1 && rest[0] == "list"
}

/// Whether a one-dash spelling is a bundle of single-letter flags. Git's
/// option parser reads `-sn` as `-s -n`, so a bundle prints exactly what the
/// same letters spelled apart print, and the read grammar has to admit both.
/// `-w` carries an optional inline width, so it is matched before this and
/// never appears in a bundle here.
fn short_bundle(argument: &str, letters: &str) -> bool {
    match argument.strip_prefix('-') {
        Some(rest) if rest.len() > 1 && !rest.starts_with('-') => {
            rest.chars().all(|letter| letters.contains(letter))
        }
        _ => false,
    }
}

/// Whether the width a `-w` spelling carries inline is a plain comma-separated
/// count. An empty rest means the bare flag.
fn inline_width(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',')
}

fn shortlog_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments.all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if SHORTLOG_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        if let Some(width) = argument.strip_prefix("-w") {
            if inline_width(width) {
                continue;
            }
            return false;
        }
        if short_bundle(argument, "nsec") {
            continue;
        }
        if let Some((name, value)) = argument.split_once('=') {
            if SHORTLOG_VALUES.contains(&name) && shortlog_value(name, value) {
                continue;
            }
            return false;
        }
        if SHORTLOG_VALUES.contains(&argument.as_str()) {
            let Some(value) = arguments.next() else {
                return false;
            };
            if shortlog_value(argument, value) {
                continue;
            }
            return false;
        }
        return false;
    }
    true
}

fn check_ignore_read_form(rest: &[String]) -> bool {
    let mut names = 0_usize;
    let mut arguments = rest.iter();
    let mut stdin = false;
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            let operands = arguments.as_slice();
            return operands.iter().all(|operand| !operand.is_empty())
                && (names + operands.len() > 0 || stdin);
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            names += 1;
            continue;
        }
        if CHECK_IGNORE_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "qvz") {
            continue;
        }
        // `--stdin` takes the paths from the pipe the command already has,
        // and the command prints which rule matched each of them.
        if argument == "--stdin" {
            stdin = true;
            continue;
        }
        return false;
    }
    names > 0 || stdin
}

/// `git count-objects` prints the size of the object store. It reads no path
/// the caller names, so the grammar is the flag list and nothing else; an
/// operand would be a spelling this pass has not modelled.
fn count_objects_read_form(rest: &[String]) -> bool {
    rest.iter().all(|argument| {
        COUNT_OBJECTS_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "vH")
    })
}

/// `git check-attr` prints which attributes apply to the paths it is given.
/// The paths are matched against the attribute rules, never opened, so the
/// operands only have to be names and the command has to have something to
/// report on: a path, or the pipe `--stdin` already reads.
fn check_attr_read_form(rest: &[String]) -> bool {
    let mut operands = 0_usize;
    let mut stdin = false;
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            let rest = arguments.as_slice();
            return rest.iter().all(|operand| !operand.is_empty())
                && (operands + rest.len() > 0 || stdin);
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            operands += 1;
            continue;
        }
        if CHECK_ATTR_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "az") {
            continue;
        }
        if argument == "--stdin" {
            stdin = true;
            continue;
        }
        // `--source=<tree-ish>` reads the attributes out of a named tree,
        // which is a form this pass has not modelled.
        return false;
    }
    operands > 0 || stdin
}
