//! Plain PowerShell `Get-Content` reads on Windows.
//!
//! Windows agents run shell tools through PowerShell, where `cat` is an alias
//! of `Get-Content`. Guard already models `cat`, but the explicit cmdlet name
//! was an unknown executable, so even the required read of
//! `~/.hol-support/SAFETY.md` needed review. A plain read is mapped onto the
//! `cat` model so the same secret-read floors and path proofs decide it. Any
//! other parameter, expression, wildcard or array keeps the original segment.

#[cfg(test)]
thread_local! {
    static FORCE_WINDOWS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `body` as if Guard were evaluating PowerShell commands on Windows.
#[cfg(test)]
pub(crate) fn with_windows_powershell_reads<T>(body: impl FnOnce() -> T) -> T {
    FORCE_WINDOWS.with(|flag| flag.set(true));
    let result = body();
    FORCE_WINDOWS.with(|flag| flag.set(false));
    result
}

pub(crate) fn windows_powershell_reads() -> bool {
    #[cfg(test)]
    if FORCE_WINDOWS.with(std::cell::Cell::get) {
        return true;
    }
    cfg!(windows)
}

const HOME_VARIABLES: [&str; 2] = ["$home", "$env:userprofile"];

/// Returns `cat` operands for `Get-Content [-Raw] [-LiteralPath|-Path] <path>...`.
pub(crate) fn plain_get_content_operands(
    executable: &str,
    arguments: &[String],
    segment_text: &str,
) -> Option<Vec<String>> {
    if !matches!(
        executable.to_ascii_lowercase().as_str(),
        "get-content" | "gc"
    ) {
        return None;
    }
    // POSIX double-quote escapes collapse `\\` and `\"`, while PowerShell
    // keeps every backslash, so Guard would check a different path.
    if segment_text.contains("\\\\") || segment_text.contains("\\\"") {
        return None;
    }
    let mut operands = Vec::new();
    let mut expecting_path = false;
    let mut end_of_parameters = false;
    for argument in arguments {
        let lowered = argument.to_ascii_lowercase();
        if !expecting_path && !end_of_parameters && argument.starts_with('-') {
            match lowered.as_str() {
                "-raw" => {}
                "-literalpath" | "-path" => expecting_path = true,
                "--" => end_of_parameters = true,
                _ => return None,
            }
            continue;
        }
        expecting_path = false;
        operands.push(plain_operand(argument, segment_text)?);
    }
    (!expecting_path && !operands.is_empty()).then_some(operands)
}

fn plain_operand(argument: &str, segment_text: &str) -> Option<String> {
    if argument.is_empty() || argument.starts_with('-') {
        return None;
    }
    let lowered = argument.to_ascii_lowercase();
    if let Some(variable) = HOME_VARIABLES
        .iter()
        .find(|variable| lowered.starts_with(*variable))
    {
        let rest = &argument[variable.len()..];
        if !(rest.starts_with('/') || rest.starts_with('\\'))
            || !home_variable_expands(segment_text, variable)
        {
            return None;
        }
        let rest = &rest[1..];
        return plain_text(rest).then(|| format!("~/{}", rest.replace('\\', "/")));
    }
    plain_text(argument).then(|| argument.to_owned())
}

/// PowerShell expands `$HOME` only outside single quotes and without a
/// backtick escape, so every occurrence must follow a double quote or space.
fn home_variable_expands(segment_text: &str, variable: &str) -> bool {
    let lowered = segment_text.to_ascii_lowercase();
    lowered
        .match_indices(variable)
        .all(|(index, _)| matches!(lowered[..index].chars().next_back(), Some('"' | ' ' | '\t')))
}

/// Rejects PowerShell expressions, arrays, wildcard patterns, UNC paths and
/// any colon outside a drive prefix: `Env:`, `Variable:` and other provider
/// paths, plus alternate data streams, are not ordinary file reads.
fn plain_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_prefix = bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !value.starts_with("//")
        && !value.starts_with("\\\\")
        && value
            .char_indices()
            .all(|(index, character)| character != ':' || (index == 1 && drive_prefix))
        && !value.chars().any(|character| {
            matches!(
                character,
                '$' | '`' | '(' | ')' | '@' | '{' | '}' | ',' | '*' | '?' | '[' | ']'
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands(command: &str) -> Option<Vec<String>> {
        let tokens = crate::parser_segments::shell_tokens(command, false).unwrap();
        plain_get_content_operands(&tokens[0], &tokens[1..], command)
    }

    #[test]
    fn plain_reads_map_to_cat_operands() {
        for (command, expected) in [
            ("Get-Content -Raw 'notes.md'", "notes.md"),
            ("get-content -LiteralPath README.md", "README.md"),
            ("Get-Content -Raw -LiteralPath 'src/a.ts'", "src/a.ts"),
            ("Get-Content -Path README.md -Raw", "README.md"),
            ("gc -Raw -- 'aliases/ordinary.txt'", "aliases/ordinary.txt"),
            ("Get-Content C:/work/notes.md", "C:/work/notes.md"),
            (
                "Get-Content -Raw \"$HOME/.hol-support/SAFETY.md\"",
                "~/.hol-support/SAFETY.md",
            ),
            (
                "Get-Content -LiteralPath \"$env:USERPROFILE/.hol-support/SAFETY.md\" -Raw",
                "~/.hol-support/SAFETY.md",
            ),
        ] {
            assert_eq!(
                operands(command),
                Some(vec![expected.to_owned()]),
                "{command}"
            );
        }
    }

    #[test]
    fn other_parameters_and_expressions_keep_review() {
        for command in [
            "Get-Content",
            "Get-Content -Raw",
            "Get-Content -LiteralPath",
            "Get-Content -Stream secret notes.md",
            "Get-Content -Wait notes.md",
            "Get-Content -Credential x notes.md",
            "Get-Content -Encoding Byte notes.md",
            "Get-Content *.md",
            "Get-Content 'a.md,b.md'",
            "Get-Content a.md,.env",
            "Get-Content \"$PWD/notes.md\"",
            "Get-Content \"$(Get-Item .env)\"",
            "Get-Content '$HOME/.hol-support/SAFETY.md'",
            "Get-Content \"`$HOME/.hol-support/SAFETY.md\"",
            "Get-Content \"$HOMEDRIVE/notes.md\"",
            "Get-Content \"$HOME/$name\"",
            "Get-Content Env:DATABASE_URL",
            "Get-Content -LiteralPath Variable:/token",
            "Get-Content notes.md:hidden",
            "Get-Content C:notes.md",
            "Get-Content \"\\\\server\\share\\notes.md\"",
            "Get-Content //server/share/notes.md",
            "Get-Content \"a\\\"b.md\"",
            "Set-Content notes.md",
            "Get-ChildItem notes.md",
        ] {
            assert_eq!(operands(command), None, "{command}");
        }
    }
}
