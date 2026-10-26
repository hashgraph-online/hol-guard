//! Command lookups (`type`, `command -v`) that only report how names resolve.
//!
//! Neither builtin runs the program it names. `type` may print a shell
//! function's body, which the agent's own shell defined. Operands are plain
//! command names, so a path or expansion is never treated as a lookup.

/// Whether a `type` or `command` segment is a lookup of plain names.
///
/// `type NAME` and `type -a NAME` print a shell function body. `command -V`
/// does too. Those stay under review. `type -t`/`-p`/`-P` and `command -v`
/// print a word or a path.
pub(super) fn safe_lookup_arguments(executable: &str, arguments: &[String]) -> bool {
    let letters = match executable {
        "type" => "afpPt",
        "command" => "pv",
        _ => return false,
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
    // `command` without `-v` runs the named program.
    names > 0
        && (executable != "type" || type_hides_definition(arguments))
        && (executable == "type"
            || crate::parser_wrappers::is_command_lookup(Some(executable), arguments))
}

/// `-t` prints only the type word, including with `-a`. `-p` and `-P` print a
/// path, but `-a` alongside them still prints the function body.
fn type_hides_definition(arguments: &[String]) -> bool {
    let mut type_word = false;
    let mut path_only = false;
    let mut all = false;
    for argument in arguments {
        if argument == "--" {
            break;
        }
        if argument.len() > 1 && argument.starts_with('-') {
            for letter in argument[1..].chars() {
                match letter {
                    't' => type_word = true,
                    'p' | 'P' => path_only = true,
                    'a' => all = true,
                    _ => {}
                }
            }
        }
    }
    type_word || (path_only && !all)
}

fn plain_name(argument: &str) -> bool {
    !argument.starts_with('-')
        && argument
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "._+-".contains(letter))
}
