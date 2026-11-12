//! How a CI step's command line splits into pipelines and groups, so a
//! credential read is tied to the network stage it actually feeds.

use super::{reads_credential_file, runs_network_tool};

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
    let mut closers: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while let Some(&ch) = chars.get(index) {
        let next = chars.get(index + 1).copied();
        let previous = index.checked_sub(1).map(|at| chars[at]);
        index += 1;
        if quote.is_some() || matches!(ch, '\'' | '"' | '\\') {
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
        if closers.last() == Some(&ch) {
            closers.pop();
            if closers.is_empty() {
                groups.push(std::mem::take(&mut group));
            } else {
                group.push(ch);
            }
            stage.push(ch);
            continue;
        }
        let opens = match ch {
            '(' => Some(')'),
            '`' => Some('`'),
            // `{ cmd; }` is a group; `${{ expr }}` and `${VAR}` are not.
            // Inside a group `${HOME}` pairs its own brace, so it cannot
            // close the group.
            '{' if (!closers.is_empty() && matches!(previous, Some('$' | '{')))
                || (previous.is_none_or(|p| p.is_whitespace() || ";&|(".contains(p))
                    && next.is_none_or(char::is_whitespace)) =>
            {
                Some('}')
            }
            _ => None,
        };
        if !closers.is_empty() {
            group.push(ch);
        }
        if let Some(closer) = opens {
            closers.push(closer);
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
            .rposition(|stage| simple_commands(stage).iter().any(|c| runs_network_tool(c)))
            .is_some_and(|network| {
                stages[..network].iter().any(|stage| {
                    simple_commands(stage)
                        .iter()
                        .any(|c| reads_credential_file(c))
                })
            })
    }) || groups
        .iter()
        .any(|inner| pipes_credential_read(inner, depth + 1))
}
