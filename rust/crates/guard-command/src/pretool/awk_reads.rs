//! `awk` programs that only read their file operands and print.
//!
//! awk can start commands (`system()`, `"cmd" | getline`, `print | "cmd"`),
//! write files (`print > "f"`), read any file or the environment
//! (`getline < "f"`, `ENVIRON`), and swap its own input list (`ARGV`). The
//! blocked words are matched in the raw program text, string literals and
//! regular expressions included, so such a word anywhere sends the command to
//! review. The pipe, redirect and `@` checks read only code: string literals,
//! regular expression literals and comments are blanked first, so
//! `$2 ~ /a|b/` or `print $1 "|" $2` is not mistaken for a pipe. A literal
//! the lexer cannot delimit the way every awk would refuses the program.
//! File operands get the same bounded read proof that `cat` uses.

const MAX_PROGRAM_CHARS: usize = 1024;
const MAX_FILE_TARGETS: usize = 16;

/// Words that run commands, read other files or the environment, change the
/// input list, or load code. gawk's `SYMTAB` and `FUNCTAB` reach any variable
/// or function by a computed name (`SYMTAB["ENV" "IRON"]`), so they are
/// blocked too.
const BLOCKED_WORDS: &[&str] = &[
    "system", "getline", "ENVIRON", "PROCINFO", "ARGV", "ARGC", "SYMTAB", "FUNCTAB",
];

/// Keywords after which awk reads `/` as the start of a regular expression
/// although a name usually ends an operand. A `/` after one is refused.
const OPERAND_KEYWORDS: &[&str] = &[
    "case", "delete", "do", "else", "exit", "getline", "in", "print", "printf", "return",
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
        || program
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
        || words(program).any(|word| BLOCKED_WORDS.contains(&word))
    {
        return false;
    }
    let Some(code) = code_text(program) else {
        return false;
    };
    // `@include` and `@load` pull in other code.
    if code.contains('@') {
        return false;
    }
    // Every `|` must be part of a logical `||`; a single `|` or `|&` is a pipe.
    if code.split("||").any(|part| part.contains('|')) {
        return false;
    }
    // Inside an unparenthesized `print` a `>` redirects output to a file. A
    // comparison before the first `print` (`length > 100 {print}`) is a
    // pattern; any `>` after one is treated as a redirect.
    let first_print = words(&code)
        .find(|word| matches!(*word, "print" | "printf"))
        .and_then(|word| code.find(word));
    !first_print.is_some_and(|start| code[start..].contains('>'))
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
}

/// The program with each string literal, regular expression literal and
/// comment blanked, so the screen reads only code. A string or regular
/// expression that is unterminated or spans a line, and a `/` that awk could
/// read either as division or as the start of a regular expression, refuse
/// the program: misreading one would hide code inside a literal.
fn code_text(program: &str) -> Option<String> {
    let characters: Vec<char> = program.chars().collect();
    let mut code = String::with_capacity(program.len());
    let mut index = 0;
    while let Some(&character) = characters.get(index) {
        match character {
            '"' => {
                index = string_end(&characters, index)?;
                code.push_str("\" \"");
            }
            '/' => match slash(&code)? {
                Slash::Regex => {
                    // A matched regular expression is an operand like a
                    // string, so a `/` left in the code is always division.
                    index = regex_end(&characters, index)?;
                    code.push_str("\" \"");
                }
                Slash::Division => code.push('/'),
            },
            '#' => {
                while characters.get(index + 1).is_some_and(|next| *next != '\n') {
                    index += 1;
                }
            }
            _ => code.push(character),
        }
        index += 1;
    }
    Some(code)
}

enum Slash {
    Regex,
    Division,
}

/// How awk reads a `/` given the code before it. After an operator, an open
/// bracket or a statement boundary it starts a regular expression; after a
/// name, a number, an index or a literal it divides. Anything else is
/// refused: `x++ /` and `print /`, a name on an earlier line, and a `)`,
/// which closes `(a) / 2` but also `if (a) /re/`.
fn slash(code: &str) -> Option<Slash> {
    let before = code.trim_end();
    let Some(last) = before.chars().last() else {
        return Some(Slash::Regex);
    };
    if "~!(,{;}&|?:=<>*%^/".contains(last) {
        return Some(Slash::Regex);
    }
    if code[before.len()..].contains('\n') {
        return None;
    }
    let word = &before[before
        .trim_end_matches(|character: char| character.is_ascii_alphanumeric() || character == '_')
        .len()..];
    if !word.is_empty() {
        return (!OPERAND_KEYWORDS.contains(&word)).then_some(Slash::Division);
    }
    matches!(last, ']' | '"' | '.').then_some(Slash::Division)
}

/// The index of the quote closing the string literal opening at `start`.
fn string_end(characters: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    loop {
        match *characters.get(index)? {
            '"' => return Some(index),
            '\n' => return None,
            '\\' if matches!(characters.get(index + 1), None | Some('\n')) => return None,
            '\\' => index += 2,
            _ => index += 1,
        }
    }
}

/// The index of the `/` closing the regular expression opening at `start`.
/// Some awks end a regular expression at a `/` inside a bracket expression
/// and others do not, so a bracket expression holding `/`, `\` or `[`, or
/// opening with `]`, is refused.
fn regex_end(characters: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    loop {
        match *characters.get(index)? {
            '/' => return Some(index),
            '\n' => return None,
            '\\' if matches!(characters.get(index + 1), None | Some('\n')) => return None,
            '\\' => index += 1,
            '[' => {
                index += 1;
                if characters.get(index) == Some(&'^') {
                    index += 1;
                }
                let open = index;
                loop {
                    match *characters.get(index)? {
                        ']' if index > open => break,
                        '/' | '\\' | '[' | ']' | '\n' => return None,
                        _ => index += 1,
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
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
            "$2 ~ /postgres|db-/ {print}",
            "/a|b/",
            "$0 !~ /x|y/ && /z/ {print}",
            "{print $1 \"|\" $2}",
            "{print $1 \" > \" $2}",
            "{print \"user@example.com\"}",
            "/^[a-z0-9_-]+$/ {print}",
            "/a\\/b/ {print}",
            "{ n = $1 / 2; print n }",
            "NF { print } # skip lines with | or >",
            "split($0, parts, /,/) {print parts[1]}",
            "f&&c<=22{print;c++} /sample\\.test\\.ts/{f=1}",
        ] {
            assert!(safe_program(program), "{program}");
        }
    }

    #[test]
    fn program_screen_rejects_commands_files_and_environment() {
        for program in [
            "BEGIN { system(\"id\") }",
            "{ \"date\" | getline now; print now }",
            "{ print $1 / 2 | \"sh\" }",
            "{ print /\"/ | \"sh\" } # \"",
            "{ x++ /\"/ | \"sh\" } # \"",
            "{ print a / /\"/ | \"sh\" } # \"",
            "{ if ($1) /\"/; print | \"sh\" } # \"",
            "{ while (1) /\"/; print | \"sh\" } # \"",
            "{ y = x\n/\"/ | \"sh\" } # \"",
            "{ print $1 # \"\n | \"sh\" }",
            "{ print $1 \"|\" $2 > \"out.txt\" }",
            "/abc {print}",
            "{ print \"abc }",
            "{ print \"a\nb\" }",
            "/a\\\n/ {print}",
            "/[/]/ {print}",
            "/[]|]/ {print}",
            "/[^]|]/ {print}",
            "/[[:alpha:]/]/ {print}",
            "{ print \"a\" } @load \"x\"",
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
