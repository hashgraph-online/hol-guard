//! `git rev-list` forms that only print commit names or counts.
//!
//! A commit walk reads history and writes nothing. It still honors
//! `pager.rev-list`, and walking a partial clone can fetch from its promisor,
//! so the configuration probe clears the read before it is proven. Only
//! options that select, order or count commits are listed. Object walks
//! (`--objects`, `--filter`, `--missing`), output formats (`--pretty`,
//! `--format`, `--header`, which can verify signatures), `--stdin`, bisection
//! and anything else keep their review.

/// Options that take no value.
const FLAGS: [&str; 39] = [
    "--count",
    "--left-right",
    "--left-only",
    "--right-only",
    "--cherry",
    "--cherry-pick",
    "--cherry-mark",
    "--first-parent",
    "--exclude-first-parent-only",
    "--merges",
    "--no-merges",
    "--no-min-parents",
    "--no-max-parents",
    "--reverse",
    "--topo-order",
    "--date-order",
    "--author-date-order",
    "--all",
    "--branches",
    "--tags",
    "--remotes",
    "--not",
    "--ancestry-path",
    "--boundary",
    "--parents",
    "--children",
    "--timestamp",
    "--abbrev-commit",
    "--no-abbrev-commit",
    "--simplify-by-decoration",
    "--full-history",
    "--dense",
    "--sparse",
    "--no-walk",
    "--do-walk",
    "--quiet",
    "--remove-empty",
    "--simplify-merges",
    "--show-pulls",
];

/// Options whose inline value is a count.
const COUNTS: [&str; 5] = [
    "--max-count",
    "--skip",
    "--min-parents",
    "--max-parents",
    "--abbrev",
];

/// Options whose inline value is a date or a ref pattern, never a path.
const SELECTORS: [&str; 10] = [
    "--since",
    "--after",
    "--until",
    "--before",
    "--max-age",
    "--min-age",
    "--branches",
    "--tags",
    "--remotes",
    "--exclude",
];

fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 9 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `rev-list rest...` is a proven commit walk.
pub(super) fn read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        // `--` starts pathspecs, which this proof does not screen.
        if argument == "--" || argument.is_empty() {
            return false;
        }
        if !argument.starts_with('-') {
            continue;
        }
        if argument == "-n" {
            if !arguments.next().is_some_and(|count| digits(count)) {
                return false;
            }
            continue;
        }
        // `-<n>` and `-n<n>` limit the walk like `--max-count`.
        if let Some(count) = argument.strip_prefix("-n").or_else(|| {
            argument
                .strip_prefix('-')
                .filter(|rest| !rest.starts_with('-'))
        }) {
            if !digits(count) {
                return false;
            }
            continue;
        }
        let proven = match argument.split_once('=') {
            Some((name, value)) if COUNTS.contains(&name) => digits(value),
            Some((name, value)) if SELECTORS.contains(&name) => {
                !value.is_empty() && !value.chars().any(char::is_control)
            }
            Some(_) => false,
            None => FLAGS.contains(&argument.as_str()),
        };
        if !proven {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::read_form;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn commit_walks_are_read_forms() {
        for rest in [
            "HEAD",
            "--count HEAD",
            "--left-right --count main...origin/main",
            "--count origin/main..HEAD",
            "-n 5 --first-parent HEAD",
            "-3 --reverse HEAD",
            "-n10 --no-merges main",
            "--max-count=20 --abbrev-commit --abbrev=12 HEAD",
            "--since=2.weeks --count --all",
            "--branches=feature/* --not --remotes",
        ] {
            assert!(read_form(&args(rest)), "{rest}");
        }
    }

    #[test]
    fn other_forms_keep_review() {
        for rest in [
            "--objects HEAD",
            "--objects-edge HEAD",
            "--filter=blob:none --objects HEAD",
            "--missing=print HEAD",
            "--stdin",
            "--pretty=format:%G? HEAD",
            "--format=%H HEAD",
            "--header HEAD",
            "--bisect HEAD",
            "--use-bitmap-index --count HEAD",
            "--disk-usage HEAD",
            "-n",
            "-n x HEAD",
            "-nx HEAD",
            "--max-count=x HEAD",
            "--since= HEAD",
            "--output=commits.txt HEAD",
            "--count HEAD -- src",
            "-x HEAD",
        ] {
            assert!(!read_form(&args(rest)), "{rest}");
        }
    }
}
