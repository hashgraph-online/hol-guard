//! A search that prints the names of the files it matched.
//!
//! `rg -l TODO src | xargs wc -l` is the shape, and the words the child
//! receives are the paths the search printed. Two properties keep them inside
//! the walk: the search is given a root of its own, so every printed path
//! carries that root as its prefix and no word can begin with a dash, and a
//! path component cannot hold a separator, so a name with a space splits into
//! fragments that are still relative to the same working directory.
//!
//! `-l` is what makes the output a list of names rather than matching lines.
//! Symlink following (`rg -L`, `grep -R`), a pattern read from a file and a
//! pattern given with `-e` are not part of the shape, and every option outside
//! the tables below keeps the uncertain model.
//!
//! Each program is read with its own table. The two share short spellings that
//! mean different things: `-r` is grep's recursive walk and ripgrep's
//! `--replace VALUE`, `-E` is grep's extended syntax and ripgrep's
//! `--encoding VALUE`, and `-T` is grep's `--initial-tab` and ripgrep's
//! `--type-not VALUE`. One table for both shifts the positionals, so the roots
//! this reading reports are not the roots the search walks. A spelling whose
//! meaning is not the one listed for that program is simply absent from its
//! table, which keeps the command uncertain.

use crate::parser_executables::executable_basename;
use crate::CommandSegmentV1;

/// The roots a listing search walks and the name globs that bound it.
///
/// Whether the names are separated by NUL (`--null`) is recorded rather than
/// required, because the two readers that ask about this shape want different
/// answers. A contained harness runs the whole pipeline inside the workspace
/// sandbox, where a name split on a space is one more relative path the run
/// could already read, so the shape is enough to stop reading `xargs` as an
/// executor of unknown commands. The pretool proof allows the pipeline with no
/// sandbox around it, and a space in a name there hands the child a word that
/// was never proven -- a planted `x --files0-from=...` is the shape of it -- so
/// that reader asks for NUL separation on both halves, as it already does for
/// `find -print0`.
pub(crate) struct ListingShape<'a> {
    pub roots: Vec<&'a str>,
    pub patterns: Vec<&'a str>,
    pub null_separated: bool,
}

/// The option tables of one listing search.
struct ListingOptions {
    /// Options that stand alone.
    flags: &'static [&'static str],
    /// Options that take their value in the next word or after an `=`.
    values: &'static [&'static str],
    /// Options that take a value only in the `--option=value` form, and stand
    /// alone otherwise.
    inline_values: &'static [&'static str],
    /// Short options that may appear in one cluster.
    ///
    /// `grep -rl` is how the recursive listing is written, so the cluster has
    /// to be read. A short option that takes a value never joins one: its
    /// value would be the rest of the cluster.
    cluster: &'static [char],
}

const RG_OPTIONS: ListingOptions = ListingOptions {
    flags: &[
        "-l",
        "--files-with-matches",
        "-i",
        "--ignore-case",
        "-s",
        "--case-sensitive",
        "-S",
        "--smart-case",
        "-F",
        "--fixed-strings",
        "-P",
        "--perl-regexp",
        "-w",
        "--word-regexp",
        "-x",
        "--line-regexp",
        "--null",
        "--hidden",
        "--no-ignore",
        "--no-ignore-vcs",
        "--no-messages",
    ],
    values: &[
        "-g",
        "--glob",
        "--iglob",
        "-t",
        "--type",
        "-T",
        "--type-not",
        "-m",
        "--max-count",
        "--max-depth",
        "-j",
        "--threads",
        "--color",
    ],
    inline_values: &[],
    cluster: &['l', 'i', 's', 'S', 'F', 'P', 'w', 'x'],
};

const GREP_OPTIONS: ListingOptions = ListingOptions {
    flags: &[
        "-l",
        "--files-with-matches",
        "-i",
        "--ignore-case",
        "-s",
        "--no-messages",
        "-F",
        "--fixed-strings",
        "-E",
        "--extended-regexp",
        "-G",
        "--basic-regexp",
        "-P",
        "--perl-regexp",
        "-w",
        "--word-regexp",
        "-x",
        "--line-regexp",
        "-r",
        "--recursive",
        "-Z",
        "--null",
        // `--color` carries its value only after an `=`; written alone it is
        // the flag, and the next word is still the pattern.
        "--color",
        "--colour",
    ],
    values: &[
        "-m",
        "--max-count",
        "--include",
        "--exclude",
        "--exclude-dir",
    ],
    inline_values: &["--color", "--colour"],
    cluster: &['l', 'i', 's', 'F', 'E', 'G', 'P', 'w', 'x', 'r', 'Z'],
};

/// The tables of the program that will run, under the spelling on the line.
fn listing_options(tool: &str) -> Option<&'static ListingOptions> {
    match tool {
        "rg" => Some(&RG_OPTIONS),
        "grep" => Some(&GREP_OPTIONS),
        _ => None,
    }
}

/// Whether this program is one whose listing output is read at all.
fn listing_tool(tool: &str) -> bool {
    listing_options(tool).is_some()
}

/// Whether the word names only short flags this reading carries.
fn listing_cluster(word: &str, options: &ListingOptions) -> bool {
    word.len() > 2
        && !word.starts_with("--")
        && word.starts_with('-')
        && word[1..]
            .chars()
            .all(|flag| options.cluster.contains(&flag))
}

/// `rg -l PATTERN ROOT...` or `grep -rl PATTERN ROOT...`, read as the roots it
/// walks and the name globs that bound it.
pub(crate) fn shape<'a>(tool: &str, arguments: &'a [String]) -> Option<ListingShape<'a>> {
    let options = listing_options(tool)?;
    let arguments = super::without_stderr_merge(arguments);
    let mut positionals: Vec<&str> = Vec::new();
    let mut patterns: Vec<&str> = Vec::new();
    let mut unbounded_names = false;
    let mut lists_names = false;
    let mut null_separated = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).map(String::as_str) {
        index += 1;
        if !argument.starts_with('-') || argument == "-" {
            positionals.push(argument);
            continue;
        }
        if listing_cluster(argument, options) {
            lists_names = lists_names || argument.contains('l');
            null_separated = null_separated || argument.contains('Z');
            continue;
        }
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument, None),
        };
        if options.flags.contains(&name) && inline.is_none() {
            lists_names = lists_names || matches!(name, "-l" | "--files-with-matches");
            null_separated = null_separated || matches!(name, "-Z" | "--null");
            continue;
        }
        if inline.is_some() && options.inline_values.contains(&name) {
            continue;
        }
        if !options.values.contains(&name) {
            return None;
        }
        let value = match inline {
            Some(value) => value,
            None => {
                let value = arguments.get(index)?.as_str();
                index += 1;
                value
            }
        };
        if matches!(name, "-g" | "--glob" | "--iglob" | "--include") {
            patterns.push(value);
            continue;
        }
        // grep reads its name filters in the order they are written: the last
        // one a name matches decides, and a name matching none of them is
        // searched anyway unless the first filter was an `--include`. An
        // `--exclude` written ahead of every include therefore admits each
        // name neither of them mentions -- `--exclude='*.md' --include='*.rs'`
        // prints `.env.local` -- so the includes beside it bound nothing.
        if name == "--exclude" && patterns.is_empty() {
            unbounded_names = true;
        }
    }
    let (_, roots) = positionals.split_first()?;
    if !lists_names || roots.is_empty() || roots.len() > super::MAX_ROOTS {
        return None;
    }
    Some(ListingShape {
        roots: roots.to_vec(),
        patterns: if unbounded_names {
            Vec::new()
        } else {
            patterns
        },
        null_separated,
    })
}

/// A search segment whose printed names another segment may fan out over.
pub(crate) fn producer(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment
            .executable
            .as_deref()
            .and_then(|name| {
                let tool = executable_basename(name);
                listing_tool(tool).then(|| shape(tool, &segment.arguments))
            })
            .flatten()
            .is_some()
}

/// A `xargs` segment fed directly by a listing search of the same pipeline.
pub(crate) fn xargs_follows(
    previous: &CommandSegmentV1,
    pipeline_index: usize,
    execution_context: &str,
    arguments: &[String],
) -> bool {
    previous.pipeline_index + 1 == pipeline_index
        && previous.execution_context == execution_context
        && producer(previous)
        && super::xargs(arguments).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_listing_search_is_read_as_its_roots_and_globs() {
        let words = args(&["-l", "TODO", "src"]);
        let parsed = shape("rg", &words).unwrap();
        assert_eq!(parsed.roots, ["src"]);
        assert!(!parsed.null_separated);
        let words = args(&["-rlZ", "TODO", "src", "docs"]);
        let parsed = shape("grep", &words).unwrap();
        assert_eq!(parsed.roots, ["src", "docs"]);
        assert!(parsed.null_separated);
        let words = args(&["-l", "--glob", "*.ts", "TODO", "src"]);
        assert_eq!(shape("rg", &words).unwrap().patterns, ["*.ts"]);
        let words = args(&["-rl", "--include=*.rs", "TODO", "."]);
        assert_eq!(shape("grep", &words).unwrap().patterns, ["*.rs"]);
        assert!(shape("rg", &args(&["--files-with-matches", "TODO", "src"])).is_some());
        assert!(shape("rg", &args(&["-l", "--max-count", "1", "TODO", "src"])).is_some());
        assert!(shape("fd", &args(&["-l", "TODO", "src"])).is_none());
        for case in [
            // No root, so the printed names carry no prefix of their own.
            &["-l", "TODO"][..],
            // Matching lines, not names.
            &["-n", "TODO", "src"],
            // Symlinks leave the walk.
            &["-l", "-L", "TODO", "src"],
            // The pattern comes from somewhere this reading never saw.
            &["-l", "-e", "TODO", "src"],
            &["-l", "-f", "patterns.txt", "src"],
            // Null-separated input is a different reading of the search itself.
            &["-l", "-z", "TODO", "src"],
            // Options this reading does not carry.
            &["-l", "--pre", "decode", "TODO", "src"],
            &["-l", "--files", "src"],
        ] {
            assert!(shape("rg", &args(case)).is_none(), "{case:?}");
        }
        for case in [
            &["-rn", "TODO", "src"][..],
            &["-Rl", "TODO", "src"],
            &["-l", "--dereference-recursive", "TODO", "src"],
            &["-l", "-e", "TODO", "src"],
        ] {
            assert!(shape("grep", &args(case)).is_none(), "{case:?}");
        }
    }

    #[test]
    fn an_exclude_written_first_leaves_the_includes_bounding_nothing() {
        // The last filter a name matches decides, and a name matching none is
        // searched unless the first filter was an `--include`, so the globs
        // here do not describe what the search prints.
        let words = args(&["-rlZ", "--exclude=*.md", "--include=*.rs", "KEY", "src"]);
        assert!(shape("grep", &words).unwrap().patterns.is_empty());
        let words = args(&[
            "-rlZ",
            "--exclude",
            "*.md",
            "--include",
            "*.rs",
            "KEY",
            "src",
        ]);
        assert!(shape("grep", &words).unwrap().patterns.is_empty());
        // An exclude after the includes only narrows them further.
        let words = args(&["-rlZ", "--include=*.rs", "--exclude=*.md", "KEY", "src"]);
        assert_eq!(shape("grep", &words).unwrap().patterns, ["*.rs"]);
        // A directory filter keeps its own list, which never re-admits a name.
        let words = args(&[
            "-rlZ",
            "--exclude-dir=target",
            "--include=*.rs",
            "KEY",
            "src",
        ]);
        assert_eq!(shape("grep", &words).unwrap().patterns, ["*.rs"]);
        // The roots are still read, so a child that reads no contents is
        // unaffected by the empty globs.
        let words = args(&["-rlZ", "--exclude=*.md", "KEY", "src"]);
        let parsed = shape("grep", &words).unwrap();
        assert_eq!(parsed.roots, ["src"]);
        assert!(parsed.patterns.is_empty());
    }

    #[test]
    fn a_spelling_each_program_reads_differently_is_not_shared() {
        // ripgrep's `-r` is `--replace VALUE`: read as grep's recursive flag it
        // leaves `TODO` as the pattern and `src` as a root, while ripgrep
        // searches for `src` from the working directory.
        assert!(shape("rg", &args(&["-l", "--null", "-r", "x", "TODO", "src"])).is_none());
        assert!(shape("rg", &args(&["-rl", "TODO", "src"])).is_none());
        assert!(shape("rg", &args(&["-l", "-E", "utf-8", "TODO", "src"])).is_none());
        // grep's `-T` is `--initial-tab`, not ripgrep's `--type-not VALUE`.
        assert!(shape("grep", &args(&["-rlT", "TODO", "src"])).is_none());
        assert!(shape("grep", &args(&["-rl", "-T", "TODO", "src"])).is_none());
        assert!(shape("grep", &args(&["-rl", "-t", "ts", "TODO", "src"])).is_none());
        // grep's `--color` carries its value only after an `=`, so the word
        // after the bare flag is the pattern, not the colour setting.
        let words = args(&["-rl", "--color", "TODO", "docs", "src"]);
        assert_eq!(shape("grep", &words).unwrap().roots, ["docs", "src"]);
        let words = args(&["-rl", "--color=never", "TODO", "src"]);
        assert_eq!(shape("grep", &words).unwrap().roots, ["src"]);
        // ripgrep takes the same option's value in the next word.
        let words = args(&["-l", "--color", "never", "TODO", "src"]);
        assert_eq!(shape("rg", &words).unwrap().roots, ["src"]);
    }
}
