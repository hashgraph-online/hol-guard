//! Command lookups (`type`, `command -v`) that only report how names resolve.
//!
//! Neither builtin runs the program it names. Operands are plain command
//! names, so a path or expansion is never treated as a lookup.

/// Whether a `type` or `command` segment is a lookup of plain names.
///
/// Unqualified `type NAME`, `type -a NAME`, and `command -V NAME` can
/// print a Bash function body. `type -f NAME` and `command -v NAME` can
/// print alias definitions. Neither syntax executes the named command, but
/// neither is a bounded metadata read: a synthetic marker in a function or
/// alias is copied into the output. This classifier does not know the caller's
/// live shell definitions, so those forms must retain review.
///
/// `type -t`, `type -p`, and `type -P` produce only type labels or
/// executable paths. Keep these limited lookup forms proven read-only.
/// `command` with no lookup flags still executes its operand.
pub(super) fn safe_lookup_arguments(executable: &str, arguments: &[String]) -> bool {
    if executable != "type" {
        return false;
    }
    let mut names = 0;
    let mut options = true;
    let mut bounded_output = false;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            if !argument[1..].chars().all(|letter| matches!(letter, 't' | 'p' | 'P')) {
                return false;
            }
            bounded_output = true;
        } else if plain_name(argument) {
            options = false;
            names += 1;
        } else {
            return false;
        }
    }
    names > 0 && bounded_output
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
