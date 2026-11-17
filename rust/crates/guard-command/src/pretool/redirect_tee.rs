//! `cmd | tee FILE` writes exactly the file `cmd > FILE` writes, but the
//! `tee` stage keeps its path operand inside the pipeline where the redirect
//! projection never looks at it. The command then carries an unmodelled write
//! and falls through to review, while the same work spelled with `>` is
//! allowed. Rewriting the stage into the redirect it already is puts both
//! spellings on the same target checks.
//!
//! The rewrite is textual: `A | tee P | B` becomes `A > P | B`, which the
//! redirect projection then models as `A | B` with `P` among the written
//! targets, under every check a redirect's target gets.
//!
//! A stage fed both streams, `A 2>&1 | tee P` or `A |& tee P`, writes A's
//! output and its errors to `P`, which is what `A > P 2>&1` writes. The
//! merge moves onto the redirect, so the shell's `2>&1` comes after the
//! target and sends stderr to the same file.
//!
//! Anything the rewrite cannot read exactly — a substitution, a glob, a `$`,
//! an unknown flag, a `-` operand, a heredoc, any other stream merge or
//! duplication, a redirection on the stage itself — leaves the command
//! untouched, so the existing fail-closed path still sees it.

/// `raw` with every plain `| tee PATH...` stage rewritten as the output
/// redirects it performs, or `None` when no stage was rewritten.
pub(super) fn as_redirects(raw: &str) -> Option<String> {
    if !raw.contains("tee") {
        return None;
    }
    // A form the stage scanner below cannot read exactly. A `$` stands for
    // text this scan never reads, wherever it sits. The rest hide text from
    // a plain left-to-right read, or move a stream somewhere the rewrite
    // does not follow. The one merge it does follow is a `2>&1 |` or `|&`
    // that feeds a `tee` stage directly.
    for form in ["$", "`", "<(", ">(", "&>", "<<"] {
        if raw.contains(form) {
            return None;
        }
    }
    if !stream_merges_feed_tee(raw) {
        return None;
    }

    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut rewrote = false;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        if escaped {
            escaped = false;
            out.push(current);
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
                out.push(current);
                index += 1;
                continue;
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                }
                out.push(current);
                index += 1;
                continue;
            }
            Quote::None => {}
        }
        match current {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            '\\' => escaped = true,
            '|' if chars.get(index + 1) == Some(&'|') => {
                out.push_str("||");
                index += 2;
                continue;
            }
            '|' => {
                // A pipe with nothing to its left is not a stage boundary
                // this rewrite can reason about.
                if out.trim().is_empty() {
                    return None;
                }
                let both_streams = chars.get(index + 1) == Some(&'&');
                let stage_start = index + 1 + usize::from(both_streams);
                if let Some(stage) = read_tee_stage(&chars, stage_start) {
                    while out.ends_with(' ') || out.ends_with('\t') {
                        out.pop();
                    }
                    let merged = both_streams || strip_stderr_merge(&mut out);
                    if out.ends_with(">&1") {
                        // A merge this rewrite could not lift off the stage.
                        return None;
                    }
                    for target in &stage.targets {
                        out.push_str(if stage.append { " >> " } else { " > " });
                        out.push_str(target);
                    }
                    if merged {
                        out.push_str(" 2>&1");
                    }
                    rewrote = true;
                    index = stage.end;
                    continue;
                }
                if both_streams {
                    return None;
                }
                if leads_with_tee(&chars, index + 1) {
                    // A `tee` stage this rewrite cannot read exactly keeps
                    // the whole command on the existing path.
                    return None;
                }
            }
            _ => {}
        }
        out.push(current);
        index += 1;
    }
    rewrote.then_some(out)
}

/// Whether every `>&` and `|&` in `raw` is a `2>&1 |` or a `|&` standing
/// directly in front of a `tee` stage. The scan below rewrites exactly those,
/// and any other duplication moves a stream the rewrite does not follow.
fn stream_merges_feed_tee(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        let rest = match &bytes[index..index + 2] {
            b">&" => {
                let merge = index >= 2
                    && matches!(bytes[index - 2], b' ' | b'\t')
                    && bytes[index - 1] == b'2'
                    && bytes.get(index + 2) == Some(&b'1');
                if !merge {
                    return false;
                }
                let after = skip_blank_bytes(bytes, index + 3);
                if bytes.get(after) != Some(&b'|') || bytes.get(after + 1) == Some(&b'|') {
                    return false;
                }
                after + 1
            }
            b"|&" if index == 0 || bytes[index - 1] != b'|' => index + 2,
            b"|&" => return false,
            _ => {
                index += 1;
                continue;
            }
        };
        let word = skip_blank_bytes(bytes, rest);
        if !bytes[word..].starts_with(b"tee") || !matches!(bytes.get(word + 3), Some(b' ' | b'\t'))
        {
            return false;
        }
        index = word;
    }
    true
}

fn skip_blank_bytes(bytes: &[u8], mut index: usize) -> usize {
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    index
}

/// Removes a trailing `2>&1` word from the text before a `tee` stage, so it
/// can follow the redirect that replaces the stage. A `2` the shell joins to
/// the word before it, as in `a\ 2>&1`, is no merge and stays.
fn strip_stderr_merge(out: &mut String) -> bool {
    let Some(before) = out.strip_suffix("2>&1") else {
        return false;
    };
    let mut prefix = before.chars().rev();
    let separated = matches!(prefix.next(), Some(' ' | '\t')) && prefix.next() != Some('\\');
    if !separated {
        return false;
    }
    let keep = before.trim_end_matches([' ', '\t']).len();
    out.truncate(keep);
    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

struct TeeStage {
    targets: Vec<String>,
    append: bool,
    /// The index just past the stage's last operand.
    end: usize,
}

/// Whether the stage starting at `start` runs `tee`, however it spells its
/// operands.
fn leads_with_tee(chars: &[char], start: usize) -> bool {
    let mut index = skip_spaces(chars, start);
    let word_start = index;
    while index < chars.len() && !is_boundary(chars[index]) && !chars[index].is_whitespace() {
        index += 1;
    }
    chars[word_start..index].iter().collect::<String>() == "tee"
}

/// The `tee` stage starting at `start`, when every operand is a literal path
/// this rewrite can turn into a redirect.
fn read_tee_stage(chars: &[char], start: usize) -> Option<TeeStage> {
    if !leads_with_tee(chars, start) {
        return None;
    }
    let mut index = skip_spaces(chars, start);
    index += "tee".len();
    let mut targets: Vec<String> = Vec::new();
    let mut append = false;
    let mut flags_closed = false;
    let mut end = index;
    loop {
        index = skip_spaces(chars, index);
        if index >= chars.len() {
            break;
        }
        if is_boundary(chars[index]) {
            // A redirection on the stage itself moves where `tee` writes,
            // so the targets read here would no longer name the writes.
            //
            // A brace beside an operand is a brace expansion: `tee a{b,c}`
            // writes `ab` and `ac`, while `> a{b,c}` hands the shell two
            // words and is an ambiguous redirect. The operand read here
            // would name neither file.
            if matches!(chars[index], '<' | '>' | '{' | '}') {
                return None;
            }
            break;
        }
        let word_start = index;
        while index < chars.len() && !is_boundary(chars[index]) && !chars[index].is_whitespace() {
            index += 1;
        }
        let word: String = chars[word_start..index].iter().collect();
        end = index;
        if !flags_closed && word == "--" {
            flags_closed = true;
            continue;
        }
        if !flags_closed && (word == "-a" || word == "--append") {
            append = true;
            continue;
        }
        if !literal_path(&word, flags_closed) {
            return None;
        }
        targets.push(word);
    }
    (!targets.is_empty()).then_some(TeeStage {
        targets,
        append,
        end,
    })
}

/// Whether `word` names one file the shell opens without expanding it.
fn literal_path(word: &str, flags_closed: bool) -> bool {
    if word.is_empty() || (!flags_closed && word.starts_with('-')) {
        // `-` is `tee`'s own name for stdout, and an unread flag may change
        // what the stage writes.
        return false;
    }
    !word.contains(['$', '*', '?', '[', ']', '~', '"', '\'', '\\', '=', '!'])
}

/// The characters that end a pipeline stage, so an operand never runs past
/// one.
fn is_boundary(current: char) -> bool {
    matches!(
        current,
        '|' | '&' | ';' | '\n' | '<' | '>' | '(' | ')' | '{' | '}'
    )
}

fn skip_spaces(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && (chars[index] == ' ' || chars[index] == '\t') {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::as_redirects;

    #[test]
    fn rewrites_a_trailing_tee_stage() {
        assert_eq!(
            as_redirects("ls -la | tee notes.log").as_deref(),
            Some("ls -la > notes.log")
        );
    }

    #[test]
    fn keeps_the_stages_around_a_rewritten_tee() {
        assert_eq!(
            as_redirects("npx vitest run --silent | tee out.log | tail -5").as_deref(),
            Some("npx vitest run --silent > out.log | tail -5")
        );
    }

    #[test]
    fn reads_append_and_several_targets() {
        assert_eq!(
            as_redirects("echo hi | tee -a a.log b.log").as_deref(),
            Some("echo hi >> a.log >> b.log")
        );
    }

    #[test]
    fn leaves_a_command_without_tee_alone() {
        assert_eq!(as_redirects("ls -la | tail -5"), None);
        assert_eq!(as_redirects("ls -la > notes.log"), None);
    }

    #[test]
    fn refuses_an_operand_the_shell_would_expand() {
        assert_eq!(as_redirects("ls | tee $OUT"), None);
        assert_eq!(as_redirects("ls | tee out-*.log"), None);
        assert_eq!(as_redirects("ls | tee ~/out.log"), None);
    }

    #[test]
    fn refuses_a_stage_it_cannot_read_exactly() {
        assert_eq!(as_redirects("ls | tee -p out.log"), None);
        assert_eq!(as_redirects("ls | tee -"), None);
        assert_eq!(as_redirects("ls | tee"), None);
        assert_eq!(as_redirects("ls | sudo tee out.log"), None);
        assert_eq!(as_redirects("ls | tee out.log > copy.log"), None);
    }

    #[test]
    fn refuses_an_operand_a_brace_expands() {
        // `tee a{b,c}` writes `ab` and `ac`; the redirect spelling names
        // neither, so the operand read off the stage is not the write.
        assert_eq!(as_redirects("ls | tee a{b,c}"), None);
        assert_eq!(as_redirects("ls | tee out{,.bak}"), None);
        assert_eq!(as_redirects("ls | tee {a,b}.log"), None);
        // A brace that opens its own group still ends the stage at the `;`
        // before it, so the ordinary rewrite is untouched.
        assert_eq!(
            as_redirects("{ ls | tee out.log; }").as_deref(),
            Some("{ ls > out.log; }")
        );
    }

    #[test]
    fn refuses_a_command_carrying_hidden_text() {
        assert_eq!(as_redirects("ls | tee $(date).log"), None);
        assert_eq!(as_redirects("cat <<'EOF' | tee out.log\nbody\nEOF"), None);
        // A `$` stands for text this scan never reads, wherever it sits.
        assert_eq!(
            as_redirects("python3 -m http.server 8080 | tee site.log & pid=$!; kill $pid"),
            None
        );
        assert_eq!(as_redirects("ls $PWD | tee out.log"), None);
    }

    #[test]
    fn moves_a_merged_stderr_stream_onto_the_redirect() {
        // The two spellings name the same pipeline, so they decide alike.
        assert_eq!(
            as_redirects("cargo test 2>&1 | tee out.log").as_deref(),
            Some("cargo test > out.log 2>&1")
        );
        assert_eq!(
            as_redirects("cargo test |& tee out.log").as_deref(),
            Some("cargo test > out.log 2>&1")
        );
        assert_eq!(
            as_redirects("gh run view 1 --log 2>&1 | tee run.log | rg -n FAILED").as_deref(),
            Some("gh run view 1 --log > run.log 2>&1 | rg -n FAILED")
        );
        assert_eq!(
            as_redirects("make 2>&1 | tee -a a.log b.log").as_deref(),
            Some("make >> a.log >> b.log 2>&1")
        );
        assert_eq!(
            as_redirects("make 2>&1| tee out.log").as_deref(),
            Some("make > out.log 2>&1")
        );
        // Only the stage the merge feeds carries it.
        assert_eq!(
            as_redirects("ls 2>&1 | tee a.log | sort | tee b.log").as_deref(),
            Some("ls > a.log 2>&1 | sort > b.log")
        );
    }

    #[test]
    fn refuses_a_stream_merge_it_does_not_follow() {
        // A merge that feeds another program, or any other duplication.
        assert_eq!(as_redirects("npm run build &> all.log | tee out.log"), None);
        assert_eq!(as_redirects("make 2>&1 | sort | tee out.log"), None);
        assert_eq!(as_redirects("make |& sort | tee out.log"), None);
        assert_eq!(as_redirects("make 1>&2 | tee out.log"), None);
        assert_eq!(as_redirects("make 3>&1 | tee out.log"), None);
        assert_eq!(as_redirects("make 2>&1 || tee out.log"), None);
        assert_eq!(as_redirects("ls | tee out.log 2>&1"), None);
        assert_eq!(as_redirects("make 2>&1 | tee out.log >&2"), None);
        assert_eq!(as_redirects("make 2>&1 | teeth out.log"), None);
        assert_eq!(as_redirects("make 2>&1 | tee -p out.log"), None);
        // A `2` joined to the word before it is an argument, not a merge.
        assert_eq!(as_redirects("echo a\\ 2>&1 | tee out.log"), None);
    }

    #[test]
    fn leaves_tee_inside_quotes_alone() {
        assert_eq!(as_redirects("echo 'a | tee b.log'"), None);
        assert_eq!(as_redirects("grep -r \"| tee x\" src"), None);
    }

    #[test]
    fn keeps_an_or_list_whole() {
        assert_eq!(
            as_redirects("make build || ls | tee out.log").as_deref(),
            Some("make build || ls > out.log")
        );
    }

    #[test]
    fn rewrites_every_tee_stage_in_a_pipeline() {
        assert_eq!(
            as_redirects("ls | tee a.log | sort | tee b.log").as_deref(),
            Some("ls > a.log | sort > b.log")
        );
    }
}
