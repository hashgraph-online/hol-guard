//! Whether PowerShell and a POSIX shell read a `sh -c` line the same way.
//!
//! A Windows agent hands its command text to PowerShell, and PowerShell and
//! POSIX disagree about some quoting: `''` inside single quotes is one literal
//! quote to PowerShell but closes and reopens the word for POSIX, and `\` is a
//! plain character to PowerShell but an escape to POSIX. Where the text uses
//! none of that, both read the same three words, so the script one of them
//! hands the shell is the script the other one sees.

/// Whether `raw`, a `<shell> -c <script>` line, splits into the same words
/// under PowerShell and POSIX quoting.
///
/// The text holds at most one quoted word, closed at the very end of the line,
/// with no quote or backslash inside it; every unquoted character is a plain
/// word character. Expansions (`$`, backtick) are already refused before this
/// is asked, and PowerShell expands neither inside single quotes. PowerShell
/// also reads the typographic quotes (U+2018 to U+201E) as quotes, so any
/// non-ASCII text stays wrapped.
pub(crate) fn powershell_reads_the_same_words(raw: &str) -> bool {
    if !raw.is_ascii() || raw.contains('\\') {
        return false;
    }
    let quotes: Vec<(usize, char)> = raw
        .char_indices()
        .filter(|(_, character)| matches!(character, '\'' | '"'))
        .collect();
    let unquoted = match quotes.as_slice() {
        [] => raw,
        [(open, first), (close, second)] if first == second && *close == raw.len() - 1 => {
            if !raw[..*open].ends_with(' ') {
                return false;
            }
            &raw[..*open]
        }
        _ => return false,
    };
    unquoted
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || " -._/".contains(character))
}

#[cfg(test)]
mod tests {
    use super::powershell_reads_the_same_words;

    #[test]
    fn plain_quoted_scripts_read_the_same() {
        for raw in [
            "sh -c 'git stash list'",
            "bash -c \"npm run build\"",
            "sh -c 'gh pr merge 17 --repo example/repo --squash'",
            "bash -c 'cd dashboard && npm test; echo done'",
            "sh -c ls",
        ] {
            assert!(powershell_reads_the_same_words(raw), "{raw}");
        }
    }

    #[test]
    fn quoting_the_two_shells_disagree_on_stays_wrapped() {
        for raw in [
            "sh -c 'it''s'",
            "sh -c 'say \"hi\"'",
            "sh -c \"say 'hi'\"",
            "sh -c 'a\\ b'",
            "sh -c 'npm test' ",
            "sh -c x'npm test'",
            "sh -c 'npm test",
            "sh -c {npm,test}",
            "sh -c @args",
            "sh -c a,b",
            "sh -c 'echo hi \u{2019}; Remove-Item x; \u{2019}'",
            "sh -c \u{201c}npm test\u{201d}",
        ] {
            assert!(!powershell_reads_the_same_words(raw), "{raw}");
        }
    }
}
