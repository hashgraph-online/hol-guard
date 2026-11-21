//! `tree` operands and flags.
//!
//! `tree` prints a names-only recursive listing, the same output class as
//! `ls -R`, so it proves the same way: every operand must be a directory the
//! walk can clear. Its flag letters are its own, though. `-a` is what asks for
//! hidden names, `-A` selects line-drawing characters rather than ls's
//! almost-all, and `-o` writes the listing to a file instead of standard
//! output. Only the flags named here are understood; anything else leaves the
//! command unproved.

use super::search;

/// Short flags that change nothing a listing can reach. `-R` is not among
/// them: at the `-L` depth limit it builds a fresh `tree` command line that
/// embeds the directory name and the `-H` base reference, writes a
/// `00Tree.html` file into each directory, and hands that string to the
/// shell, so it both writes and runs text a listing never should.
const INERT_SHORT: &str = "adfixqNQpugshDFrtcvUCnASXJ";

/// Short flags that consume a value: depth, match and ignore patterns, and
/// the HTML title and base reference.
const VALUED_SHORT: &str = "LPIHT";

/// Long flags that change nothing a listing can reach.
const INERT_LONG: &[&str] = &[
    "prune",
    "noreport",
    "dirsfirst",
    "filesfirst",
    "si",
    "du",
    "inodes",
    "device",
    "nolinks",
    "matchdirs",
    "gitignore",
    "version",
    "help",
];

/// Long flags that consume a value.
const VALUED_LONG: &[&str] = &["filelimit", "charset", "timefmt", "sort", "scheme"];

/// What one understood argument does to the proof.
#[derive(Default)]
struct Flag {
    /// It asks for hidden names.
    hidden: bool,
    /// It follows symbolic links while descending.
    follows_links: bool,
    /// The next argument is its value.
    takes_next_value: bool,
}

/// Classify one `tree` argument that starts with `-`. `None` is a flag this
/// proof does not understand, or one that writes the listing somewhere.
fn flag(argument: &str) -> Option<Flag> {
    if let Some(name) = argument.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        if INERT_LONG.contains(&name) {
            return Some(Flag::default());
        }
        if VALUED_LONG.contains(&name) {
            // `--opt=value` carries its own value; `--opt value` takes the next.
            return Some(Flag {
                takes_next_value: !argument.contains('='),
                ..Flag::default()
            });
        }
        return None;
    }
    let mut flag = Flag::default();
    let mut characters = argument.chars().skip(1).peekable();
    // A bare `-` is standard input, which is not a directory to walk.
    characters.peek()?;
    while let Some(letter) = characters.next() {
        if VALUED_SHORT.contains(letter) {
            // The rest of the cluster is the value, or the next argument is.
            flag.takes_next_value = characters.peek().is_none();
            return Some(flag);
        }
        match letter {
            'a' => flag.hidden = true,
            'l' => flag.follows_links = true,
            letter if INERT_SHORT.contains(letter) => {}
            // `-o` redirects the listing into a file, which is a write.
            _ => return None,
        }
    }
    Some(flag)
}

/// `absent_recursive` says whether a missing operand stays missing while the
/// walk runs: no peer segment may create a file, directory or link at that
/// name, because the walk descends into whatever appears there.
pub(super) fn safe_tree_segment(
    arguments: &[String],
    context: super::PathContext<'_>,
    absent_recursive: bool,
) -> bool {
    let mut lists_hidden = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut options_ended = false;
    let mut skip_value = false;
    for argument in arguments {
        if skip_value {
            skip_value = false;
            continue;
        }
        if !options_ended && argument == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && argument.starts_with('-') {
            let Some(flag) = flag(argument) else {
                return false;
            };
            // A walk that follows links leaves the directory it was given, so
            // `tree -l` is left for review the way a linked `ls -R` is.
            if flag.follows_links {
                return false;
            }
            lists_hidden |= flag.hidden;
            skip_value = flag.takes_next_value;
            continue;
        }
        // The shell expands a glob before `tree` sees it, and the proof has no
        // quote map here to say which characters were literal.
        if argument.contains(['*', '?', '[']) {
            return false;
        }
        operands.push(argument);
    }
    if skip_value {
        // The final flag's value never arrived.
        return false;
    }
    if operands.is_empty() {
        return search::safe_recursive_listing_target(".", context, lists_hidden);
    }
    operands.iter().all(|operand| {
        // A name that is not there holds no tree to walk, so `tree` prints the
        // same error it prints for any unreadable operand and reads nothing. A
        // `~` is expanded by the shell from its own `HOME`, which this screen
        // reads as the declared home, so a walk is admitted under it only once
        // `shell_home_matches` says the two name one directory.
        search::safe_recursive_listing_target(operand, context, lists_hidden)
            || (absent_recursive
                && (!operand.starts_with('~') || context.shell_home_matches)
                && super::listing_reads::absent_listing_operand(operand, context))
    })
}

#[cfg(test)]
mod tests {
    /// `tree` is a names-only recursive listing, so it proves what `ls -R`
    /// proves: a repository's `.git` is not part of the output until `-a` asks
    /// for it. Depth and pattern flags carry values that are not operands,
    /// `-A` is line-drawing rather than ls's almost-all, `-o` writes the
    /// listing to a file, and `-R` reruns `tree` through the shell at the
    /// depth limit.
    #[test]
    fn a_tree_listing_screens_what_it_can_print() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tree-recursive-hidden")
            .join(std::process::id().to_string());
        let home = root.join("home");
        let project = home.join("work/project");
        let keyed = home.join("work/keyed");
        for directory in [
            project.join("src"),
            project.join(".git/refs"),
            keyed.join("certs"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        for file in [
            project.join("src/app.ts"),
            project.join(".git/config"),
            project.join(".env"),
            keyed.join("certs/service.pem"),
        ] {
            std::fs::write(file, "synthetic\n").unwrap();
        }
        let (home, project) = (
            crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
            crate::runtime_read_paths::canonicalize_text(&project).unwrap(),
        );
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: project.to_str(),
            ..Default::default()
        };
        let keyed = home.join("work/keyed").display().to_string();
        for (command, allowed) in [
            ("tree".to_owned(), true),
            ("tree .".to_owned(), true),
            ("tree -L 2".to_owned(), true),
            ("tree -L2 src".to_owned(), true),
            ("tree -A --dirsfirst .".to_owned(), true),
            ("tree -I 'node_modules|dist' .".to_owned(), true),
            ("tree --filelimit=20 .".to_owned(), true),
            ("tree -a .".to_owned(), false),
            ("tree -aL 2".to_owned(), false),
            ("tree -L 2 -a".to_owned(), false),
            ("tree -l .".to_owned(), false),
            ("tree -R .".to_owned(), false),
            ("tree -RL 2 -H base .".to_owned(), false),
            ("tree -o out.txt .".to_owned(), false),
            ("tree --fromfile .".to_owned(), false),
            ("tree -L".to_owned(), false),
            ("tree src/*".to_owned(), false),
            (format!("tree {keyed}"), false),
            // A root that is not there holds no tree, in the project and beside it.
            ("tree lib".to_owned(), true),
            ("tree -L 2 lib".to_owned(), true),
            (format!("tree {keyed}/missing"), true),
            // Hidden names cannot matter for a root that is not there.
            ("tree -a lib".to_owned(), true),
            (
                format!("tree {home}/.ssh/missing", home = home.display()),
                false,
            ),
        ] {
            let words: Vec<String> = command.split(' ').map(str::to_owned).collect();
            assert_eq!(
                super::safe_tree_segment(&words[1..], context, true),
                allowed,
                "{command}"
            );
        }
        // A peer step could create the missing root before the walk reaches it.
        let words: Vec<String> = "tree lib".split(' ').map(str::to_owned).collect();
        assert!(!super::safe_tree_segment(&words[1..], context, false));
        std::fs::remove_dir_all(root).unwrap();
    }
}
