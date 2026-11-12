//! How a CI step's command line splits into pipelines and groups, so a
//! credential read is tied to the network stage it actually feeds.

use super::{command_words, reads_credential_file, runs_network_tool, INLINE_SCRIPT};

/// A group the scanner is inside: the character that closes it, whether that
/// is a `}` that closes only in command position, and the quoting to resume
/// after it, as for a `$( … )` inside `"…"`.
struct Open {
    closer: char,
    reserved_word: bool,
    resume: Option<char>,
}

/// True when the `}` at `at` stands where bash reads the reserved word: after
/// a `;`, `&` or newline, and before a word break. In `{ echo build}; …` it is
/// part of `build}` and does not close the group.
fn closes_brace_group(chars: &[char], at: usize) -> bool {
    let before = chars[..at].iter().rev().find(|c| !matches!(c, ' ' | '\t'));
    let after = chars.get(at + 1);
    matches!(before, Some(';' | '&' | '\n' | ')' | '}'))
        && after.is_none_or(|c| c.is_whitespace() || ";|&)<>".contains(*c))
}

/// The scripts `bash -c '...'` or `eval '...'` run where the shell is the
/// command itself, not text an `echo` prints or a comment holds.
pub(super) fn inline_scripts(text: &str) -> Vec<String> {
    INLINE_SCRIPT
        .captures_iter(text)
        .filter(|captures| {
            captures
                .name("shell")
                .is_some_and(|shell| command_position(&text[..shell.start()]))
        })
        .filter_map(|captures| {
            captures
                .name("sq")
                .map(|script| script.as_str().to_owned())
                .or_else(|| {
                    captures
                        .name("dq")
                        .map(|script| script.as_str().replace("\\\"", "\""))
                })
        })
        .collect()
}

/// True when a command word placed after `head` is the command a shell runs:
/// `head` ends outside any quote, and since its last separator holds only
/// assignments, wrappers and clause keywords. A `$( … )` or backtick inside
/// double quotes starts a new command.
fn command_position(head: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut resume: Vec<Option<char>> = Vec::new();
    let mut start = 0;
    let mut previous = None;
    let mut chars = head.char_indices();
    while let Some((at, ch)) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') => quote = None,
            (Some('\''), _) => {}
            (_, '\\') => {
                chars.next();
            }
            (Some('"'), '"') => quote = None,
            (Some('"'), '`') | (Some('"'), '(') if ch == '`' || previous == Some('$') => {
                resume.push(quote.take());
                start = at + 1;
            }
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (None, ')' | '`') if !resume.is_empty() => {
                quote = resume.pop().flatten();
                start = at + 1;
            }
            (None, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`') => start = at + 1,
            _ => {}
        }
        previous = Some(ch);
    }
    quote.is_none() && command_words(&head[start..]).is_empty()
}

/// True when a stage runs a command `test` accepts, directly or inside a
/// `bash -c` script, as in `cat .env | bash -c 'curl -d @- …'`.
fn stage_runs(stage: &str, test: fn(&str) -> bool) -> bool {
    simple_commands(stage).iter().any(|command| test(command))
        || inline_scripts(stage)
            .iter()
            .any(|script| stage_runs(script, test))
}

/// Every simple command in `text`, cut at each separator, pipe and group
/// delimiter. `||` separates commands and `|&` is a pipe.
pub(super) fn simple_commands(text: &str) -> Vec<String> {
    text.replace("||", ";")
        .replace("|&", "|")
        .split(['\n', ';', '&', '(', ')', '`', '|'])
        .map(str::to_owned)
        .collect()
}

/// The pipelines of one command line, cut at `;`, `&&`, `||`, a lone `&` and
/// newlines. A `( … )`, `{ …; }`, `$( … )` or backtick group stays inside the
/// stage it belongs to, so `{ cat .env; } | curl …` is one pipeline, and the
/// `&` of a `2>&1` redirect is not a separator. Also returns the inner text of
/// every top-level group, whose own pipelines are checked separately. Quoted
/// and backslash-escaped text is literal, so `echo "{"` opens nothing.
fn top_level_pipelines(line: &str) -> (Vec<Vec<String>>, Vec<String>) {
    let chars: Vec<char> = line.chars().collect();
    let mut pipelines: Vec<Vec<String>> = Vec::new();
    let mut stages: Vec<String> = Vec::new();
    let mut stage = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut group = String::new();
    let mut closers: Vec<Open> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while let Some(&ch) = chars.get(index) {
        let next = chars.get(index + 1).copied();
        let previous = index.checked_sub(1).map(|at| chars[at]);
        index += 1;
        // Bash still runs `$( … )` and backticks inside double quotes.
        let substitution =
            quote == Some('"') && ((ch == '(' && previous == Some('$')) || ch == '`');
        if !substitution && (quote.is_some() || matches!(ch, '\'' | '"' | '\\')) {
            let mut text = ch.to_string();
            if ch == '\\' && quote != Some('\'') {
                if let Some(escaped) = next {
                    text.push(escaped);
                    index += 1;
                }
            } else if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
            if !closers.is_empty() {
                group.push_str(&text);
            }
            stage.push_str(&text);
            continue;
        }
        let closes = closers.last().is_some_and(|open| {
            open.closer == ch && (!open.reserved_word || closes_brace_group(&chars, index - 1))
        });
        if let Some(open) = closes.then(|| closers.pop()).flatten() {
            quote = open.resume;
            if closers.is_empty() {
                groups.push(std::mem::take(&mut group));
            } else {
                group.push(ch);
            }
            stage.push(ch);
            continue;
        }
        let opens = match ch {
            '(' => Some((')', false)),
            '`' => Some(('`', false)),
            // `{ cmd; }` is a group; `${{ expr }}` and `${VAR}` are not.
            // Inside a group `${HOME}` pairs its own brace, so it cannot
            // close the group.
            '{' if !closers.is_empty() && matches!(previous, Some('$' | '{')) => Some(('}', false)),
            '{' if previous.is_none_or(|p| p.is_whitespace() || ";&|(".contains(p))
                && next.is_none_or(char::is_whitespace) =>
            {
                Some(('}', true))
            }
            _ => None,
        };
        if !closers.is_empty() {
            group.push(ch);
        }
        if let Some((closer, reserved_word)) = opens {
            closers.push(Open {
                closer,
                reserved_word,
                resume: quote.take(),
            });
            stage.push(ch);
            continue;
        }
        if !closers.is_empty() {
            stage.push(ch);
            continue;
        }
        let ends_pipeline = match ch {
            '|' if next == Some('|') => {
                index += 1;
                true
            }
            '|' => {
                if next == Some('&') {
                    index += 1;
                }
                stages.push(std::mem::take(&mut stage));
                continue;
            }
            '&' if next == Some('&') => {
                index += 1;
                true
            }
            '&' if matches!(previous, Some('>' | '<')) || next == Some('>') => false,
            '&' | ';' | '\n' | ')' => true,
            _ => false,
        };
        if ends_pipeline {
            stages.push(std::mem::take(&mut stage));
            pipelines.push(std::mem::take(&mut stages));
        } else {
            stage.push(ch);
        }
    }
    if !closers.is_empty() {
        groups.push(group);
    }
    stages.push(stage);
    pipelines.push(stages);
    (pipelines, groups)
}

/// `cat .env | curl -d @- ...`: a credential read feeds a later network stage
/// of the same pipeline. A read that ends at `&&` or `;` sends nothing.
pub(super) fn pipes_credential_read(line: &str, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let (pipelines, groups) = top_level_pipelines(line);
    pipelines.iter().any(|stages| {
        stages
            .iter()
            .rposition(|stage| stage_runs(stage, runs_network_tool))
            .is_some_and(|network| {
                stages[..network]
                    .iter()
                    .any(|stage| stage_runs(stage, reads_credential_file))
            })
    }) || groups
        .iter()
        .any(|inner| pipes_credential_read(inner, depth + 1))
}
