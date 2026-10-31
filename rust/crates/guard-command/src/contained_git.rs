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
//!
//! The options a verb refuses are read the way Git reads them. A long option
//! may be written as any unambiguous prefix of its name, and short options
//! cluster, so comparing whole words would leave `--open` and `-nO` naming
//! the pager that `--open-files-in-pager` and `-O` were refused for. Both are
//! answered for the verb at hand, because Git's option table is per verb:
//! `--filters` is a filter driver for `cat-file` and nothing at all for
//! `rev-list`, and `-o` prints only the matching text for `grep` while it
//! names an output file elsewhere.
//!
//! A leading `-C` is Git's own way of reading a checkout the caller is not
//! standing in, and authority routes such a read to containment like any
//! other, so the grammar reports the directories it names instead of refusing
//! the vector for them. The sink resolves them inside the approved workspace
//! and starts the run there; handing them to Git would let the run step out
//! from under the roots the plan granted.

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

/// Options that relocate Git itself, whatever verb they are written against.
const REFUSED_EVERYWHERE: &[&str] = &["--exec-path"];

/// Shell syntax never reaches a vector Git executes directly, so a word that
/// spells it is a sign the caller joined a command rather than split one.
const OPERATORS: &[&str] = &[";", "&&", "||", "|", "&"];

/// `read_only_invocation` - what a read-only Git vector asks for, or nothing
/// when the vector is not one.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadOnlyInvocation {
    /// The verb the contained run executes.
    pub operation: String,
    /// The words after the verb, with the helper screens written first.
    pub arguments: Vec<String>,
    /// The directories `-C` named, in the order they were written. Git's own
    /// `-C` would move the run out from under the roots the plan grants, so
    /// the sink walks the same path itself and runs there instead.
    pub directories: Vec<String>,
}

/// Long options that name a program for Git to run or move Git's output into
/// a file, for the verbs that define them.
fn refused_long_options(verb: &str, subcommand: &str) -> &'static [&'static str] {
    match (verb, subcommand) {
        // `git reflog show` and `git stash list` are `git log` written another
        // way: both hand their words to the log walk, so both define the whole
        // log option set and are read for it here.
        ("diff" | "log" | "show" | "reflog", _) | ("stash", "show" | "list") => {
            &["--ext-diff", "--output", "--textconv"]
        }
        ("blame", _) => &["--textconv"],
        ("grep", _) => &["--open-files-in-pager", "--textconv"],
        // `--filters` runs the repository's smudge filter over the blob it
        // prints, which is the same program `--textconv` would have named.
        ("cat-file", _) => &["--filters", "--textconv"],
        _ => &[],
    }
}

/// Options a verb spells in full that also abbreviate a refused one. Git
/// resolves an exact spelling to the option that owns it, so `--text` is the
/// verb's own "treat the file as text" where the verb has one, and an
/// abbreviation of `--textconv` where it has none.
fn spelled_in_full(verb: &str) -> &'static [&'static str] {
    match verb {
        "diff" | "log" | "show" | "grep" => &["--text"],
        _ => &[],
    }
}

/// Short options whose value may be written against the letter. Git reads
/// every character after one of these as that value, so a scan for a refused
/// letter stops there, as Git's own parse does: the `O` in `git grep -eFOO`
/// is the pattern, not the pager.
fn short_value_letters(verb: &str) -> &'static str {
    match verb {
        "grep" => "efmABCO",
        "diff" | "log" | "show" | "stash" | "reflog" => "USGlLnOBCM",
        "blame" => "LCMS",
        _ => "",
    }
}

/// The helper screens Git honours for the verb, written ahead of the caller's
/// own words so an option-shaped pathname cannot push them past `--`.
fn disabled_helpers(verb: &str, subcommand: &str) -> &'static [&'static str] {
    match (verb, subcommand) {
        // `stash show` prints a diff, and `stash list` and `reflog show` print
        // one for `-p`, so all three read the same two helpers the diff family
        // does. `reflog exists` answers about a ref and defines neither.
        ("diff" | "log" | "show", _) | ("stash", "show" | "list") | ("reflog", "" | "show") => {
            &["--no-ext-diff", "--no-textconv"]
        }
        ("blame" | "grep", _) => &["--no-textconv"],
        _ => &[],
    }
}

/// `read_only_invocation` - the read a Git vector names, or nothing when the
/// vector is not a read this grammar answers for.
///
/// The caller's own `argv[0]` is read for its name only; the sink resolves the
/// executable it will actually run.
pub fn read_only_invocation(argv: &[String]) -> Option<ReadOnlyInvocation> {
    let [program, rest @ ..] = argv else {
        return None;
    };
    if !program_name(program).eq_ignore_ascii_case("git") {
        return None;
    }
    let (directories, rest) = named_directories(rest)?;
    let [verb, rest @ ..] = rest else {
        return None;
    };
    let subcommand = rest.first().map_or("", String::as_str);
    let admitted = READ_ONLY_VERBS.contains(&verb.as_str())
        || READ_ONLY_SUBCOMMANDS
            .iter()
            .any(|(named, forms)| named == verb && forms.contains(&subcommand));
    if !admitted {
        return None;
    }
    if rest.iter().any(|word| refused(word, verb, subcommand)) {
        return None;
    }
    let screens = disabled_helpers(verb, subcommand);
    let mut arguments: Vec<String> = Vec::with_capacity(rest.len() + screens.len());
    // A subcommand is the verb's own word, so the screens follow it rather
    // than standing between the verb and the form it names.
    let named = READ_ONLY_SUBCOMMANDS.iter().any(|(named, _)| named == verb);
    let rest = if named && !rest.is_empty() {
        arguments.push(rest[0].clone());
        &rest[1..]
    } else {
        rest
    };
    arguments.extend(screens.iter().map(|flag| (*flag).to_owned()));
    arguments.extend(rest.iter().cloned());
    Some(ReadOnlyInvocation {
        operation: verb.clone(),
        arguments,
        directories,
    })
}

/// The directories Git's leading `-C` names, and the words after them. Every
/// other global option configures Git itself — `-c` sets a setting such as
/// the pager, `--git-dir` moves the repository — so a vector that carries one
/// is not a read this grammar answers for.
fn named_directories(words: &[String]) -> Option<(Vec<String>, &[String])> {
    let mut directories = Vec::new();
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if word == "-C" {
            directories.push(named_directory(words.get(index + 1)?)?.to_owned());
            index += 2;
        } else if let Some(directory) = word.strip_prefix("-C") {
            directories.push(named_directory(directory)?.to_owned());
            index += 1;
        } else if word == "--no-pager" || word == "-P" {
            // The sink writes `--no-pager` itself, so a caller who asked for
            // it asked for what the contained run already does.
            index += 1;
        } else if word.starts_with('-') {
            return None;
        } else {
            break;
        }
    }
    Some((directories, &words[index..]))
}

fn named_directory(word: &str) -> Option<&str> {
    (!word.is_empty() && !word.starts_with('-') && !OPERATORS.contains(&word)).then_some(word)
}

fn refused(word: &str, verb: &str, subcommand: &str) -> bool {
    OPERATORS.contains(&word) || refused_long(word, verb, subcommand) || refused_short(word, verb)
}

/// Whether the word names a refused long option, written in full or as any
/// prefix of one, with or without its value.
fn refused_long(word: &str, verb: &str, subcommand: &str) -> bool {
    let name = word.split('=').next().unwrap_or(word);
    if !name.starts_with("--") || name.len() < 3 || spelled_in_full(verb).contains(&name) {
        return false;
    }
    refused_long_options(verb, subcommand)
        .iter()
        .chain(REFUSED_EVERYWHERE)
        .any(|option| option.starts_with(name))
}

/// Whether the word names a program for Git to run or a file for Git to write,
/// for a verb this grammar screens. The workspace containment route asks the
/// same question of the same verbs, so the screens are written once here
/// rather than kept in step by hand in two places.
pub(crate) fn names_helper_or_output(word: &str, verb: &str, subcommand: &str) -> bool {
    refused_long(word, verb, subcommand) || refused_short(word, verb)
}

/// Whether a short-option word carries a refused letter in a position Git
/// reads as a flag. `-O` names the pager `git grep` opens and the order file
/// `git diff` reads; `-o` writes the output to a file for the verbs that have
/// it, and prints only the matching text for `git grep`, which keeps it.
fn refused_short(word: &str, verb: &str) -> bool {
    let Some(flags) = word.strip_prefix('-') else {
        return false;
    };
    if flags.is_empty() || flags.starts_with('-') {
        return false;
    }
    let values = short_value_letters(verb);
    for letter in flags.chars() {
        if letter == 'O' || (letter == 'o' && verb != "grep") {
            return true;
        }
        if values.contains(letter) {
            return false;
        }
    }
    false
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
