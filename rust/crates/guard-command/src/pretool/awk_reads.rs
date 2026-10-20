//! `awk` programs that only read their file operands and print.
//!
//! awk can start commands (`system()`, `"cmd" | getline`, `print | "cmd"`),
//! write files (`print > "f"`), read any file or the environment
//! (`getline < "f"`, `ENVIRON`), and swap its own input list (`ARGV`). The
//! screen scans the raw program text, string literals and regular expressions
//! included, so it over-approximates: such a word or symbol anywhere in the
//! program sends the command to review. File operands get the same bounded
//! read proof that `cat` uses.

const MAX_PROGRAM_CHARS: usize = 1024;
const MAX_FILE_TARGETS: usize = 16;

/// Words that run commands, read other files or the environment, change the
/// input list, or load code. gawk's `SYMTAB` and `FUNCTAB` reach any variable
/// or function by a computed name (`SYMTAB["ENV" "IRON"]`), so they are
/// blocked too.
const BLOCKED_WORDS: &[&str] = &[
    "system", "getline", "ENVIRON", "PROCINFO", "ARGV", "ARGC", "SYMTAB", "FUNCTAB",
];

/// Built-in variables a `-v` assignment may set besides lower-case names.
const ASSIGNABLE_BUILTINS: &[&str] = &["FS", "OFS", "RS", "ORS", "SUBSEP", "CONVFMT", "OFMT"];

pub(super) fn safe_awk_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            index += 1;
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            break;
        }
        match argument.as_str() {
            "-F" => index += 1,
            "-v" => {
                index += 1;
                if !arguments
                    .get(index)
                    .is_some_and(|value| safe_assignment(value))
                {
                    return false;
                }
            }
            _ => {
                let attached = argument
                    .strip_prefix("-v")
                    .map(safe_assignment)
                    .unwrap_or_else(|| argument.starts_with("-F"));
                if !attached {
                    return false;
                }
            }
        }
        index += 1;
    }
    let Some(program) = arguments.get(index) else {
        return false;
    };
    let targets = &arguments[index + 1..];
    safe_program(program)
        && (if targets.is_empty() {
            piped_input
        } else {
            targets.len() <= MAX_FILE_TARGETS
                && targets.iter().all(|target| {
                    // `-` is stdin and `name=value` is an assignment, not a file.
                    !target.starts_with('-')
                        && !target.contains('=')
                        && super::safe_reads::command_read_target(target, context, false)
                })
        })
}

fn safe_assignment(value: &str) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return false;
    };
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !BLOCKED_WORDS.contains(&name)
        && (name.chars().any(|character| character.is_ascii_lowercase())
            || ASSIGNABLE_BUILTINS.contains(&name))
}

fn safe_program(program: &str) -> bool {
    if program.is_empty()
        || program.starts_with('-')
        || program.chars().count() > MAX_PROGRAM_CHARS
        // `@include` and `@load` pull in other code.
        || program.contains('@')
        || program.chars().any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return false;
    }
    // Every `|` must be part of a logical `||`; a single `|` or `|&` is a pipe.
    if program.split("||").any(|part| part.contains('|')) {
        return false;
    }
    let mut printed = false;
    let mut word = String::new();
    for character in program.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '_' {
            word.push(character);
            continue;
        }
        if !word.is_empty() {
            if BLOCKED_WORDS.contains(&word.as_str()) {
                return false;
            }
            printed |= matches!(word.as_str(), "print" | "printf");
            word.clear();
        }
        // Inside an unparenthesized `print` a `>` redirects output to a file.
        // A comparison before the first `print` (`length > 100 {print}`) is
        // a pattern; any `>` after one is treated as a redirect.
        if character == '>' && printed {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::safe_program;

    #[test]
    fn program_screen_admits_plain_prints() {
        for program in [
            "{print FNR}",
            "length > 100 {print FILENAME\":\"FNR\": \"length}",
            "NR == 1 || NR == 2 {print $1}",
            "{ total += $2 } END { printf \"%d\\n\", total }",
        ] {
            assert!(safe_program(program), "{program}");
        }
    }

    #[test]
    fn program_screen_rejects_commands_files_and_environment() {
        for program in [
            "BEGIN { system(\"id\") }",
            "{ \"date\" | getline now; print now }",
            "{ print | \"sh\" }",
            "{ print |& \"sh\" }",
            "{ print > \"out.txt\" }",
            "{ print >> \"out.txt\" }",
            "{ printf \"%s\", $0 > \"/tmp/x\" }",
            "BEGIN { while ((getline line < \"/etc/hosts\") > 0) print line }",
            "BEGIN { print ENVIRON[\"HOME\"] }",
            "BEGIN { ARGV[1] = \"/etc/hosts\" } {print}",
            "BEGIN { SYMTAB[\"AR\" \"GV\"][1] = \"/etc/hosts\" } {print}",
            "BEGIN { for (k in SYMTAB[\"ENV\" \"IRON\"]) print k }",
            "@include \"lib.awk\"",
            "",
            "-f",
        ] {
            assert!(!safe_program(program), "{program}");
        }
    }
}
