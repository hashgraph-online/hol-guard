//! Closed grammar for a `git grep` invocation that only searches tracked
//! content or named revisions and prints the matches.
//!
//! Git accepts any unambiguous prefix of a long option, so long options must
//! match exactly. Opening matches in a program (`-O`), reading patterns from
//! a file (`-f`), searching outside the index (`--no-index`, `--untracked`),
//! running textconv helpers (`--textconv`) and descending into submodules are
//! outside this grammar and stay reviewed. The configured pager still needs
//! the configuration probe.

const FLAGS: &[&str] = &[
    "--all-match",
    "--and",
    "--basic-regexp",
    "--break",
    "--cached",
    "--column",
    "--count",
    "--extended-regexp",
    "--files-with-matches",
    "--files-without-match",
    "--fixed-strings",
    "--full-name",
    "--function-context",
    "--heading",
    "--ignore-case",
    "--invert-match",
    "--line-number",
    "--name-only",
    "--no-break",
    "--no-color",
    "--no-heading",
    "--no-recursive",
    "--no-textconv",
    "--not",
    "--null",
    "--only-matching",
    "--or",
    "--perl-regexp",
    "--quiet",
    "--recursive",
    "--show-function",
    "--text",
    "--word-regexp",
    "(",
    ")",
];

/// Long options whose value is a count.
const COUNTS: &[&str] = &[
    "--after-context",
    "--before-context",
    "--context",
    "--max-count",
    "--max-depth",
    "--threads",
];

/// Short options without a value.
const SHORT_FLAGS: &str = "EFGHILPWachilnopqrvwz";

/// Short options whose value is a count.
const SHORT_COUNTS: &str = "ABCm";

fn count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// The revisions and pathspecs when `arguments`, the tokens after the `grep`
/// subcommand, stay inside the read-only grammar. Patterns are search text,
/// not paths, and are left out.
pub(crate) fn targets(arguments: &[String]) -> Option<&[String]> {
    let mut patterns = 0usize;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if argument == "--" || !argument.starts_with('-') && !matches!(argument.as_str(), "(" | ")")
        {
            // Options end here: Git stops at the first non-option.
            index -= 1;
            break;
        }
        if FLAGS.contains(&argument.as_str()) {
            continue;
        }
        if argument == "-e" {
            arguments.get(index)?;
            index += 1;
            patterns += 1;
            continue;
        }
        if let Some((name, value)) = argument.split_once('=') {
            if COUNTS.contains(&name) && count(value) {
                continue;
            }
            if name == "--color" && matches!(value, "never" | "auto" | "always") {
                continue;
            }
            return None;
        }
        if argument == "--color" {
            continue;
        }
        if COUNTS.contains(&argument.as_str()) {
            if !arguments.get(index).is_some_and(|value| count(value)) {
                return None;
            }
            index += 1;
            continue;
        }
        if argument.starts_with("--") {
            return None;
        }
        match short_cluster(&argument[1..]) {
            Some(Short::Complete) => {}
            Some(Short::NeedsCount) => {
                if !arguments.get(index).is_some_and(|value| count(value)) {
                    return None;
                }
                index += 1;
            }
            Some(Short::NeedsPattern) => {
                arguments.get(index)?;
                index += 1;
                patterns += 1;
            }
            Some(Short::AttachedPattern) => patterns += 1,
            None => return None,
        }
    }
    let mut start = index;
    if patterns == 0 {
        // The first operand is the pattern.
        match arguments.get(start) {
            Some(pattern) if pattern != "--" => start += 1,
            _ => return None,
        }
    }
    // Revisions and pathspecs. A later option is an error in Git; refuse it
    // here rather than rely on that.
    let targets = &arguments[start..];
    let mut paths = false;
    targets
        .iter()
        .all(|operand| {
            if operand == "--" && !paths {
                paths = true;
                return true;
            }
            !operand.is_empty() && !operand.starts_with('-')
        })
        .then_some(targets)
}

enum Short {
    Complete,
    NeedsCount,
    NeedsPattern,
    AttachedPattern,
}

/// A cluster of short options such as `-in`, `-A3` or `-ie pattern`.
fn short_cluster(cluster: &str) -> Option<Short> {
    if cluster.is_empty() {
        return None;
    }
    // `-NUM` sets the context.
    if count(cluster) {
        return Some(Short::Complete);
    }
    for (position, flag) in cluster.char_indices() {
        let rest = &cluster[position + flag.len_utf8()..];
        if SHORT_FLAGS.contains(flag) {
            continue;
        }
        if SHORT_COUNTS.contains(flag) {
            return if rest.is_empty() {
                Some(Short::NeedsCount)
            } else {
                count(rest).then_some(Short::Complete)
            };
        }
        if flag == 'e' {
            return Some(if rest.is_empty() {
                Short::NeedsPattern
            } else {
                Short::AttachedPattern
            });
        }
        return None;
    }
    Some(Short::Complete)
}

#[cfg(test)]
mod tests {
    use super::targets;

    fn form(command: &str) -> bool {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        targets(&arguments).is_some()
    }

    #[test]
    fn searches_stay_inside_the_grammar() {
        for command in [
            "-l NEEDLE HEAD",
            "-l NEEDLE HEAD -- tests",
            "-n -i needle",
            "-in needle",
            "-rn needle src",
            "-A3 needle",
            "-C 2 needle",
            "-3 needle",
            "--max-depth=2 needle",
            "--max-count 5 needle",
            "-e one -e two",
            "-eone",
            "-e one --and -e two HEAD",
            "( -e one --or -e two ) HEAD",
            "--color=never --heading --break needle",
        ] {
            assert!(form(command), "{command}");
        }
    }

    #[test]
    fn patterns_are_not_targets() {
        for (command, expected) in [
            ("-l SOME_TOKEN_NAME HEAD", &["HEAD"][..]),
            ("-l SOME_TOKEN_NAME HEAD -- src", &["HEAD", "--", "src"][..]),
            ("-e SOME_TOKEN_NAME -- .env", &["--", ".env"][..]),
            ("-n needle", &[][..]),
        ] {
            let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
            let expected: Vec<String> = expected.iter().map(|value| (*value).to_owned()).collect();
            assert_eq!(targets(&arguments), Some(&expected[..]), "{command}");
        }
    }

    #[test]
    fn helpers_files_and_unknown_options_stay_reviewed() {
        for command in [
            "-O needle",
            "-Ovim needle",
            "-iO needle",
            "--open-files-in-pager needle",
            "--open-files-in-pager=vim needle",
            "--open needle",
            "-f patterns.txt",
            "--file=patterns.txt",
            "--no-index needle",
            "--untracked needle",
            "--textconv needle",
            "--recurse-submodules needle",
            "--ext-grep needle",
            "--max-depth=x needle",
            "-A x needle",
            "-e",
            "-l",
            "needle HEAD -O",
            "needle HEAD -- -O",
            "--ignore needle",
            "-x needle",
        ] {
            assert!(!form(command), "{command}");
        }
    }
}
