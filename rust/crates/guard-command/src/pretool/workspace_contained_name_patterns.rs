//! Option values a search compares names against and never opens.
//!
//! The reach check refuses any argument that runs through `.git`, since Git's
//! metadata belongs to `git` alone. `find . -not -path './.git/*'` and
//! `grep -r --exclude-dir=.git x .` name that directory only to leave it out of
//! the walk, so the value of a name test is skipped rather than read as a path.

/// `find` tests whose next argument is a pattern matched against each name or
/// path the walk visits. None of them opens what the pattern names. A test
/// that does open its argument, such as `-newer` or `-fprint`, is not here.
const FIND_NAME_TESTS: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
];

/// `grep` options whose value is a glob matched against file or directory
/// names. Only the attached `--exclude-dir=VALUE` spelling is skipped: a
/// separated value can be taken by an earlier option instead, as in
/// `grep -e --exclude-dir .git/config`, where `.git/config` is a file grep
/// reads.
const GREP_NAME_GLOBS: &[&str] = &["--exclude", "--exclude-dir", "--include"];

/// Whether `argument` is a `find` name test, so the argument after it is a
/// pattern.
pub(super) fn separated(name: &str, argument: &str) -> bool {
    name == "find" && FIND_NAME_TESTS.contains(&argument)
}

/// Whether the attached value of `option` is a name glob.
pub(super) fn attached(name: &str, option: &str) -> bool {
    matches!(name, "grep" | "egrep" | "fgrep") && GREP_NAME_GLOBS.contains(&option)
}
