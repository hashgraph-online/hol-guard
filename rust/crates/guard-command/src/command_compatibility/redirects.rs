//! POSIX output-redirection detection that ignores quoted `>` characters.

/// How a POSIX segment redirects its output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Redirect {
    /// No `>` the shell acts on.
    None,
    /// Only `2>&1` or `2>/dev/null`: no file is written, but whatever the
    /// command reads still reaches the agent's output.
    Stderr,
    /// An output redirection that can write a file.
    Output,
}

/// Classifies the `>` characters the shell would act on: unquoted ones, or any
/// inside a command substitution. An escaped `\>` still counts as output.
pub(super) fn posix_redirect(text: &str) -> Redirect {
    let raw = || {
        if text.contains('>') {
            Redirect::Output
        } else {
            Redirect::None
        }
    };
    let chars: Vec<char> = text.chars().collect();
    let mut quote: Option<char> = None;
    let mut stderr = false;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        let substitution =
            character == '`' || (character == '$' && chars.get(index + 1) == Some(&'('));
        match quote {
            Some('\'') if character == '\'' => quote = None,
            Some('\'') => {}
            Some(_) if character == '\\' => index += 1,
            Some(_) if character == '"' => quote = None,
            // A substitution inside double quotes runs its own redirections.
            Some(_) if substitution => return raw(),
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '>' => {
                let inert =
                    crate::parser_segments::is_stderr_to_stdout_redirect(&chars, index, false)
                        || index.checked_sub(1).is_some_and(|start| {
                            crate::parser_segments::is_stderr_to_null_redirect(&chars, start, false)
                        });
                if !inert {
                    return Redirect::Output;
                }
                stderr = true;
            }
            None if character == '\\' && chars.get(index + 1) == Some(&'>') => {
                return Redirect::Output;
            }
            None if character == '\\' => index += 1,
            None if substitution => return raw(),
            None => {}
        }
        index += 1;
    }
    if stderr {
        Redirect::Stderr
    } else {
        Redirect::None
    }
}

#[cfg(test)]
mod tests {
    use super::{posix_redirect, Redirect};

    #[test]
    fn quoted_characters_are_not_redirects() {
        for text in [
            "gh pr comment 7 --body 'Replace <placeholder> -> value'",
            "gh pr comment 7 --body \"Use <name> => done\"",
            "gh pr comment 7 --body \"x \\\" > y\"",
        ] {
            assert_eq!(posix_redirect(text), Redirect::None, "{text}");
        }
    }

    #[test]
    fn stderr_merges_and_discards_stay_visible() {
        assert_eq!(
            posix_redirect("gh pr comment 7 --body \"a \\` b > c\" 2>&1"),
            Redirect::Stderr
        );
        assert_eq!(posix_redirect("cat .env 2>&1"), Redirect::Stderr);
        // The sink is inert on Unix, and on Windows only while no drive has a
        // `\dev` directory a PowerShell or cmd redirection could write into.
        let null = if crate::parser_segments::stderr_null_sink_is_inert() {
            Redirect::Stderr
        } else {
            Redirect::Output
        };
        assert_eq!(posix_redirect("cat .env 2>/dev/null"), null);
    }

    #[test]
    fn real_and_hidden_redirects_still_count() {
        for text in [
            "gh pr view 7 > .env",
            "gh pr view 7 >> notes.md",
            "gh pr view 7 2> err.log",
            "gh pr view 7 1>&2",
            "gh pr view 7 2>&1>out.log",
            "cat .env 2>&1 > out.log",
            "echo a\\>b",
            "gh pr comment 7 --body \"$(cat x > ~/.netrc)\"",
            "gh pr comment 7 --body \"`cat x > ~/.netrc`\"",
            "gh pr comment 7 --body 'a'>b",
            "cat <(true) >(tee .env)",
        ] {
            assert_eq!(posix_redirect(text), Redirect::Output, "{text}");
        }
    }
}
