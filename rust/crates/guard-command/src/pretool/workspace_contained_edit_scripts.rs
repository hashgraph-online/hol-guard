//! The script words of an in-place `sed` or `perl` edit.
//!
//! A script such as `s|href={a}|href={b}|g` is not a path, so the workspace
//! wipe screen would take its braces for a root glob. The screen skips the
//! words found here and still reads every other word as a target.
//!
//! A word the shell expands is never a script: an unquoted `*` in the script
//! slot reaches the program as file names, the first of them read as the
//! script and the rest edited by it. Only a word the shell passes through
//! unchanged is skipped.

/// The positions of the script words of an in-place `sed` or `perl` edit
/// that the shell passes to the program as written.
pub(super) fn edit_scripts(segment: &crate::CommandSegmentV1) -> Vec<usize> {
    let mut scripts = script_positions(segment);
    let expanded = expanding_words(&segment.text);
    scripts.retain(|position| {
        segment
            .arguments
            .get(*position)
            .is_some_and(|word| !expanded.contains(word))
    });
    scripts
}

fn script_positions(segment: &crate::CommandSegmentV1) -> Vec<usize> {
    let program = segment
        .executable
        .as_deref()
        .map(super::super::super::executable_basename);
    let arguments = &segment.arguments;
    let mut scripts = Vec::new();
    if program == Some("perl") {
        // `-e` or `-E` at the end of a cluster of value-less switches takes
        // the next word as the program; switches end at `--` or an operand.
        // `-0` and `-l` take octal digits, as in `-0777pe`.
        let loop_flags = |flags: &str| {
            flags
                .bytes()
                .all(|byte| byte.is_ascii_digit() || b"pnlaw".contains(&byte))
        };
        let switch = |(_, word): &(usize, &String)| word.starts_with('-') && *word != "--";
        let mut words = arguments.iter().enumerate();
        while let Some((position, word)) = words.next().filter(switch) {
            if word[1..].strip_suffix(['e', 'E']).is_some_and(loop_flags) {
                scripts.push(position + 1);
                words.next();
            }
        }
    } else if program == Some("sed") {
        // GNU sed reads options anywhere before `--`, and a positional
        // script only when no `-e` or `-f` names one.
        let mut named = false;
        let mut positional = None;
        let mut words = arguments.iter().enumerate().peekable();
        while let Some((position, word)) = words.next() {
            if word == "--" {
                positional = positional.or(words.next().map(|(next, _)| next));
                break;
            }
            if let Some(long) = word.strip_prefix("--") {
                if matches!(long, "expression" | "file") {
                    named = true;
                    scripts.push(position + 1);
                    words.next();
                }
                named |= long.starts_with("expression=") || long.starts_with("file=");
                continue;
            }
            let Some(flags) = word.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
                positional = positional.or(Some(position));
                continue;
            };
            let Some(at) = flags.find(['e', 'f', 'i']) else {
                continue;
            };
            if &flags[at..] == "i" {
                // BSD sed takes the next word as the backup suffix, and
                // `sed -i ''` passes an empty one rather than a script.
                words.next_if(|(_, next)| next.is_empty());
            } else if flags[at..].starts_with(['e', 'f']) {
                named = true;
                if at + 1 == flags.len() {
                    scripts.push(position + 1);
                    words.next();
                }
            }
        }
        scripts.extend(positional.filter(|_| !named));
    }
    scripts
}

/// The words of `text`, with quotes removed, that hold an unquoted glob or
/// brace the shell would expand.
fn expanding_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let (mut word, mut glob, mut quote) = (String::new(), false, None::<char>);
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(open), _) if ch == open => quote = None,
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    if !matches!(next, '"' | '\\' | '$' | '`') {
                        word.push('\\');
                    }
                    word.push(next);
                }
            }
            (Some(_), _) => word.push(ch),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => word.extend(chars.next()),
            (None, _) if ch.is_whitespace() || ";&|()<>".contains(ch) => {
                let done = std::mem::take(&mut word);
                if std::mem::take(&mut glob) {
                    words.push(done);
                }
            }
            (None, _) => {
                glob |= matches!(ch, '*' | '?' | '[' | '{');
                word.push(ch);
            }
        }
    }
    if glob {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::expanding_words;

    #[test]
    fn only_unquoted_globs_and_braces_expand() {
        assert_eq!(
            expanding_words("perl -i -ne * 's|{a}|{b}|' \"x*\" y\\* {a,b}"),
            vec!["*".to_owned(), "{a,b}".to_owned()]
        );
        assert!(expanding_words("sed -i 's|{OLD}|{NEW}|g' src/a.tsx").is_empty());
    }
}
