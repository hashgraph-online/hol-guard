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

/// `find` actions that run the words after them as a command of their own,
/// up to a `;`, or a `+` right after `{}`.
const FIND_EXEC_ACTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// The arguments of a `name` segment that can name a path it opens: all of
/// them except a name test or name glob and its pattern. The command a
/// `find -exec` runs parses its own arguments, so inside it nothing is
/// skipped: in `find . -exec grep -e -name .git/HEAD \;` the `-name` is
/// grep's pattern and `.git/HEAD` a file grep reads.
pub(super) fn opened<'a>(
    name: &'a str,
    arguments: &'a [String],
) -> impl Iterator<Item = &'a str> + 'a {
    let mut pattern_next = false;
    let mut exec = false;
    let mut previous = "";
    arguments
        .iter()
        .map(String::as_str)
        .filter(move |&argument| {
            if exec {
                exec = !(matches!(argument, ";" | "\\;") || (argument == "+" && previous == "{}"));
                previous = argument;
                return true;
            }
            if std::mem::take(&mut pattern_next) {
                return false;
            }
            if name == "find" && FIND_EXEC_ACTIONS.contains(&argument) {
                exec = true;
                previous = argument;
                return true;
            }
            if name == "find" && FIND_NAME_TESTS.contains(&argument) {
                pattern_next = true;
                return false;
            }
            !argument.split_once('=').is_some_and(|(option, _)| {
                matches!(name, "grep" | "egrep" | "fgrep") && GREP_NAME_GLOBS.contains(&option)
            })
        })
}

#[cfg(test)]
mod tests {
    fn opened(name: &str, command: &[&str]) -> Vec<String> {
        let arguments: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
        super::opened(name, &arguments).map(str::to_owned).collect()
    }

    #[test]
    fn a_name_test_pattern_is_skipped() {
        let kept = opened("find", &[".", "-not", "-path", "./.git/*", "-type", "f"]);
        assert_eq!(kept, [".", "-not", "-type", "f"]);
        let kept = opened("grep", &["-rn", "--exclude-dir=.git", "x", "."]);
        assert_eq!(kept, ["-rn", "x", "."]);
    }

    #[test]
    fn an_exec_command_keeps_every_argument() {
        for terminator in [";", "\\;"] {
            let kept = opened(
                "find",
                &[".", "-exec", "grep", "-e", "-name", ".git/HEAD", terminator],
            );
            assert!(kept.iter().any(|word| word == ".git/HEAD"), "{terminator}");
        }
        // A `+` ends the command only right after `{}`.
        let kept = opened(
            "find",
            &[
                ".",
                "-exec",
                "grep",
                "-e",
                "+",
                "-name",
                ".git/HEAD",
                "{}",
                "+",
            ],
        );
        assert!(kept.iter().any(|word| word == ".git/HEAD"));
        // After the command ends, `find`'s own name tests are skipped again.
        let kept = opened(
            "find",
            &[".", "-execdir", "true", "{}", "+", "-path", "./.git/*"],
        );
        assert!(!kept.iter().any(|word| word == "./.git/*"));
    }
}
