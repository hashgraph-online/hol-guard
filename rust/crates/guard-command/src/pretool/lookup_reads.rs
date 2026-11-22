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
            if !argument[1..]
                .chars()
                .all(|letter| matches!(letter, 't' | 'p' | 'P'))
            {
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

/// A path-only lookup. zsh's `which` is a shell builtin that can print
/// a function body or alias expansion, even with `-a` or `-s`. A lexical
/// proof cannot know the caller's active shell definitions, so `which` is
/// never an unconditional Allow. `whence -p` restricts resolution to PATH
/// executables; `whence` without `-p` can expose definitions. The other
/// handled lookups use their own narrowly scoped proofs above.
pub(super) fn safe_path_lookup(executable: &str, arguments: &[String]) -> bool {
    let letters = match executable {
        "which" => return false,
        "whence" => "ap",
        _ => return safe_lookup_arguments(executable, arguments),
    };
    let mut names = 0;
    let mut options = true;
    let mut path_only = false;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            if !argument[1..].chars().all(|letter| letters.contains(letter)) {
                return false;
            }
            path_only |= argument.contains('p');
        } else if plain_name(argument) {
            options = false;
            names += 1;
        } else {
            return false;
        }
    }
    names > 0 && path_only
}

fn plain_name(argument: &str) -> bool {
    !argument.starts_with('-')
        && argument
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "._+-".contains(letter))
}
