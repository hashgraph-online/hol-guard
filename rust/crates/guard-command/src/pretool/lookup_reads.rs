//! Command lookups (`type`, `command -v`) that only report how names resolve.
//!
//! Neither builtin runs the program it names. Operands are plain command
//! names, so a path or expansion is never treated as a lookup.

/// Whether a `type` or `command` segment is a lookup of plain names.
///
/// Bash's `type NAME`, `type -a NAME` and `command -V NAME` print the body of a
/// matching shell function. That body is a definition the agent's own shell
/// already holds, and zsh's `which NAME` (`whence -c`) prints the same text, so
/// these forms answer the same question as `which` and are proven the same way.
/// `command` without `-v` or `-V` runs the named program and is not a lookup.
pub(super) fn safe_lookup_arguments(executable: &str, arguments: &[String]) -> bool {
    let letters = match executable {
        "type" => "afpPt",
        "command" => "pvV",
        _ => return false,
    };
    let mut names = 0;
    let mut options = true;
    let mut describes = false;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            if !argument[1..].chars().all(|letter| letters.contains(letter)) {
                return false;
            }
            describes |= argument.contains(['v', 'V']);
        } else if plain_name(argument) {
            options = false;
            names += 1;
        } else {
            return false;
        }
    }
    names > 0 && (executable == "type" || describes)
}

/// A lookup that only prints where a name resolves: `which`, zsh's `whence`,
/// plus the `type` and `command -v`/`-V` forms above. None of them runs the
/// program it names or binds a shell variable.
///
/// zsh's `where` is `whence -ca`, and `whence -f` prints a function in full.
/// Neither is modelled here, so every caller gets the same answer for them,
/// whatever its own question is.
pub(super) fn safe_path_lookup(executable: &str, arguments: &[String]) -> bool {
    let letters = match executable {
        "which" => "as",
        "whence" => "apv",
        _ => return safe_lookup_arguments(executable, arguments),
    };
    let mut names = 0;
    let mut options = true;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            if !argument[1..].chars().all(|letter| letters.contains(letter)) {
                return false;
            }
        } else if plain_name(argument) {
            options = false;
            names += 1;
        } else {
            return false;
        }
    }
    names > 0
}

fn plain_name(argument: &str) -> bool {
    !argument.starts_with('-')
        && argument
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "._+-".contains(letter))
}
