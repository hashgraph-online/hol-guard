//! Which words after a checkout subcommand are option values, not operands.
//!
//! The repository of a clone or submodule add is the one word the floor
//! does not screen, so an option's separate value must never be taken for
//! it: `--separate-git-dir ab:c/x` names a directory Git writes, even when
//! it is shaped like a remote.

/// Long options of `git clone` and `git submodule add` that take a value.
const VALUE_OPTIONS: &[&str] = &[
    "branch",
    "bundle-uri",
    "config",
    "depth",
    "filter",
    "jobs",
    "name",
    "origin",
    "ref-format",
    "reference",
    "reference-if-able",
    "revision",
    "separate-git-dir",
    "server-option",
    "shallow-exclude",
    "shallow-since",
    "template",
    "upload-pack",
];
/// Short options that take a value: `-b`, `-c`, `-j`, `-o` and `-u`.
const VALUE_SHORT_OPTIONS: &[char] = &['b', 'c', 'j', 'o', 'u'];

/// Whether `argument`, an option word with no `=`, takes the next word as
/// its value.
pub(super) fn takes_separate_value(argument: &str) -> bool {
    if let Some(name) = argument.strip_prefix("--") {
        // Git accepts any unambiguous prefix of a long option. An ambiguous
        // one fails before anything is written, so every prefix counts.
        return !name.is_empty() && VALUE_OPTIONS.iter().any(|option| option.starts_with(name));
    }
    // Short options cluster (`-qb main`). A value option takes the rest of
    // the cluster as its value, or the next word when it ends the cluster.
    let Some(cluster) = argument.strip_prefix('-') else {
        return false;
    };
    for (offset, flag) in cluster.char_indices() {
        if VALUE_SHORT_OPTIONS.contains(&flag) {
            return offset + flag.len_utf8() == cluster.len();
        }
    }
    false
}
