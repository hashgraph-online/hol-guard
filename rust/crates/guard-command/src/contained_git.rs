//! The read-only Git invocations a contained run may execute.
//!
//! Authority sends a Git read to containment whenever the repository could
//! run a helper of its own — a textconv filter, an external diff, a pager —
//! and that is the whole of Git's reading surface, not three verbs of it.
//! The sink used to carry its own list of `diff`, `log` and `show`, so an
//! everyday `git blame` or `git grep` arrived at a sink that refused to plan
//! it and failed the run outright. One grammar answers for both sides here.
//!
//! What is admitted is narrower than what authority contains: a verb earns a
//! place only when every form of it reads, or when its reading forms are
//! named, and only when Git answers it in its own process without reading a
//! helper's output or printing a setting. `git submodule status` reads too,
//! but it answers by launching Git again, which the sandbox refuses, so
//! admitting it would trade a refusal the caller can see for one it cannot.
//! `git hash-object` runs the repository's clean filter and `git notes show`
//! hands its note to a second Git for the same reason; `git notes list`
//! prints the ref itself and stays.
//! `git config` prints the settings themselves, among them the credential
//! helper a repository names, so it keeps its review rather than reaching a
//! sandbox that would print it. `git clean -n` and `git apply --check` print
//! without writing, but each is one option away from the verb that writes,
//! and that option grammar belongs to the proof that admitted them, not to a
//! second reading here.

/// Verbs whose every form reads the repository.
const READ_ONLY_VERBS: &[&str] = &[
    "blame",
    "cat-file",
    "check-attr",
    "check-ignore",
    "count-objects",
    "describe",
    "diff",
    "for-each-ref",
    "grep",
    "log",
    "ls-tree",
    "merge-base",
    "rev-list",
    "shortlog",
    "show",
    "show-ref",
];

/// Verbs that both read and write, with the subcommands that only read. An
/// empty subcommand stands for the verb written alone.
const READ_ONLY_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("bisect", &["log"]),
    ("notes", &["", "list"]),
    ("reflog", &["", "show", "exists"]),
    ("sparse-checkout", &["list"]),
    ("stash", &["list", "show"]),
];

/// Options that select a helper, redirect the output, or relocate Git itself.
/// Every one of them is refused wherever it stands in the vector.
const REFUSED_OPTIONS: &[&str] = &[
    "--exec-path",
    "--ext-diff",
    "-O",
    "-o",
    "--open-files-in-pager",
    "--output",
    "--textconv",
];
const REFUSED_PREFIXES: &[&str] = &["--exec-path=", "-O", "--open-files-in-pager=", "--output="];
/// Shell syntax never reaches a vector Git executes directly, so a word that
/// spells it is a sign the caller joined a command rather than split one.
const OPERATORS: &[&str] = &[";", "&&", "||", "|", "&"];

/// The helper screens Git honours for the verb, written ahead of the caller's
/// own words so an option-shaped pathname cannot push them past `--`.
fn disabled_helpers(verb: &str) -> &'static [&'static str] {
    match verb {
        "diff" | "log" | "show" => &["--no-ext-diff", "--no-textconv"],
        "blame" | "grep" => &["--no-textconv"],
        _ => &[],
    }
}

/// `read_only_invocation` - the verb a read-only Git vector names and the
/// arguments its contained run carries, or nothing when the vector is not one.
///
/// The caller's own `argv[0]` is read for its name only; the sink resolves the
/// executable it will actually run.
pub fn read_only_invocation(argv: &[String]) -> Option<(String, Vec<String>)> {
    let [program, verb, rest @ ..] = argv else {
        return None;
    };
    if !program_name(program).eq_ignore_ascii_case("git") {
        return None;
    }
    let subcommand = rest.first().map_or("", String::as_str);
    let admitted = READ_ONLY_VERBS.contains(&verb.as_str())
        || READ_ONLY_SUBCOMMANDS
            .iter()
            .any(|(named, forms)| named == verb && forms.contains(&subcommand));
    if !admitted {
        return None;
    }
    if rest.iter().any(|word| refused(word)) {
        return None;
    }
    let mut arguments: Vec<String> = disabled_helpers(verb)
        .iter()
        .map(|flag| (*flag).to_owned())
        .collect();
    arguments.extend(rest.iter().cloned());
    Some((verb.clone(), arguments))
}

fn refused(word: &str) -> bool {
    OPERATORS.contains(&word)
        || REFUSED_OPTIONS.contains(&word)
        || REFUSED_PREFIXES
            .iter()
            .any(|prefix| word.len() > prefix.len() && word.starts_with(prefix))
}

fn program_name(program: &str) -> &str {
    program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .trim_end_matches(".exe")
}

#[cfg(test)]
#[path = "contained_git_tests.rs"]
mod tests;
