//! Whether a Git step points its own output at a file that decides what
//! runs next. Split out of `git_read_after_allow` so each file stays within
//! the repository's size guideline; the rules themselves are unchanged.

/// Verbs that read a short `-o` as the file to write.
///
/// Everywhere else the same letter means something that writes nothing:
/// `git ls-files -o` lists untracked files and `git push -o` carries a push
/// option to the remote, so refusing `-o` outright would stop ordinary work.
const SHORT_OUTPUT_VERBS: &[&str] = &["archive", "bundle", "format-patch"];

/// Whether a step points its output at a file that decides what runs next.
///
/// Git's diff options reach every verb that can show a diff, so `log`, `show`,
/// `whatchanged` and `rev-list` all take `--output=<file>` and write wherever
/// it points. Git resolves any unambiguous long-option abbreviation, so every
/// spelling from `--out` up is read as that option; the short form is read as
/// the output file for the verbs that package a tree.
///
/// The file the option names decides the answer. A workspace-relative path
/// Git packages into is the ordinary shape of the option and stays inside an
/// Allow on the Git extension; a path Guard cannot place, or one that names
/// Git's own tree, does not.
pub(super) fn points_output_at_a_protected_file(arguments: &[String]) -> bool {
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return false;
    };
    let Some(operation) = arguments.get(index).map(String::as_str) else {
        return false;
    };
    let short_writes = SHORT_OUTPUT_VERBS.contains(&operation);
    let rest = arguments.get(index + 1..).unwrap_or_default();
    rest.iter().enumerate().any(|(position, argument)| {
        let (value, names_a_file) = match output_option_value(argument, short_writes) {
            Some(value) => (value, true),
            None => match verb_destination_value(operation, argument) {
                Some((value, names_a_file)) => (value, names_a_file),
                None => return false,
            },
        };
        let target = match value {
            Some(value) => Some(value),
            None => rest.get(position + 1).map(String::as_str),
        };
        target.is_none_or(|target| {
            if names_a_file {
                !output_target_is_inert(target)
            } else {
                !output_target_is_placed(target)
            }
        })
    })
}

/// Long options that name where one verb writes, beside the `--output` every
/// diff-showing verb takes.
///
/// `git fast-export --export-marks=<file>` and
/// `git read-tree --index-output=<file>` write a file wherever they are
/// pointed, which is the same escape `git archive -o` keeps its review for.
/// `--object-dir` moves the files `git commit-graph write` and
/// `git multi-pack-index write` produce into another directory.
///
/// The flag says whether the value names a file Git chooses nothing about. A
/// directory Git writes its own fixed names into cannot become the
/// configuration, hook or attribute file a later step runs under, so
/// `--object-dir .git/objects` -- the ordinary spelling -- stays inside the
/// Allow, and only a path that leaves the workspace keeps its review.
const VERB_DESTINATION_OPTIONS: &[(&str, &str, bool)] = &[
    ("commit-graph", "object-dir", false),
    ("fast-export", "export-marks", true),
    ("multi-pack-index", "object-dir", false),
    ("read-tree", "index-output", true),
];

/// The destination a verb-specific long option points at, as
/// [`output_option_value`] reports one, with whether it names a file.
///
/// Git resolves any unambiguous long-option abbreviation, so every spelling
/// from the first letter up is read as that option.
fn verb_destination_value<'a>(
    operation: &str,
    argument: &'a str,
) -> Option<(Option<&'a str>, bool)> {
    let long = argument.strip_prefix("--")?;
    let (name, attached) = match long.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (long, None),
    };
    if name.is_empty() {
        return None;
    }
    VERB_DESTINATION_OPTIONS
        .iter()
        .find(|(verb, option, _)| *verb == operation && option.starts_with(name))
        .map(|(_, _, names_a_file)| (attached, *names_a_file))
}

/// The file a single argument points Git's output at, when it is that option.
///
/// `Some(Some(path))` carries the value in the argument itself,
/// `Some(None)` means the option is there and the next word carries its
/// value, and `None` means the argument is not an output option at all.
///
/// Git's own option parser lets short flags travel in one cluster, so
/// `git format-patch -no ../outside` writes exactly where `-n -o ../outside`
/// would. The letter is therefore read wherever it sits in a single-dash
/// run, not only at its head; a cluster the verb refuses outright fails
/// before it writes anything, so reading one as an output option costs
/// nothing.
fn output_option_value(argument: &str, short_writes: bool) -> Option<Option<&str>> {
    if let Some(rest) = argument.strip_prefix("--out") {
        return Some(rest.split_once('=').map(|(_, value)| value));
    }
    if short_writes {
        let cluster = argument
            .strip_prefix('-')
            .filter(|rest| !rest.starts_with('-'))?;
        let position = cluster.find('o')?;
        let rest = &cluster[position + 'o'.len_utf8()..];
        return Some((!rest.is_empty()).then_some(rest));
    }
    None
}

/// Whether a path Git writes its output to leaves what a later step runs as
/// Guard read it.
///
/// `snapshot.tar` or `patches/0001.patch` below the workspace is what
/// `git archive -o` and `git format-patch -o` are for, and an Allow on the
/// Git extension answers for them. A path that climbs out of the workspace or
/// names `.git` -- `.git/config`, `.git/hooks/pre-commit`, `.gitattributes` --
/// changes the configuration, hook or filter the next Git step runs under, so
/// it keeps its review. A value Guard cannot place, because it is absent,
/// home-relative or still carries a shell expansion, is treated the same way.
fn output_target_is_inert(target: &str) -> bool {
    output_target_is_placed(target)
        && !target
            .split(['/', '\\'])
            .any(|component| component.starts_with(".git"))
}

/// Whether Guard can place a destination below the workspace. A path that
/// climbs out of it, or one that is absolute, home-relative, drive-rooted or
/// still carries a shell expansion, lands where Guard read nothing.
fn output_target_is_placed(target: &str) -> bool {
    if target.is_empty() || target.starts_with('-') || target.starts_with('~') {
        return false;
    }
    if target.starts_with('/') || target.starts_with('\\') || target.contains('$') {
        return false;
    }
    if target.len() > 1 && target.as_bytes()[1] == b':' {
        return false;
    }
    !target.split(['/', '\\']).any(|component| component == "..")
}
