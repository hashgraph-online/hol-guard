//! Brace expansion of a search glob, the way bash would expand the word
//! before `grep`, `rg` or `fd` ever see it.

/// The one brace pair bash would expand next, as `(open, close)` byte
/// offsets. Bash pairs a `}` with the nearest `{` to its left, so an opening
/// brace that never closes is skipped rather than swallowing the pair that
/// follows it: `{x/{.gnupg,b}` is `{x/.gnupg {x/b`, and the component
/// `.gnupg` is exactly what a sensitive-path check has to see. Pairing the
/// first `{` with the first `}` instead produced `x/{.gnupg`, which matches
/// no marker. A `}` with no `{` anywhere to its left is literal text to bash,
/// which still expands the pair after it (`}{.env,x}` is `}.env }x`), so such
/// a brace is passed over rather than ending the search for a pair.
fn innermost_brace_pair(candidate: &str) -> Option<(usize, usize)> {
    candidate
        .match_indices('}')
        .find_map(|(close, _)| candidate[..close].rfind('{').map(|open| (open, close)))
}

/// The same candidate with the `}` at `close` taken as the literal text an
/// escaped brace leaves behind. Bash carries the pair on to the next `}`, so
/// this reading exists only when a comma and a later `}` follow, and only
/// when the next character is not itself a `}`: a brace that closes straight
/// into another one is the inner half of a nested pair such as a Go template
/// `{{.Names}},{{.Status}}`, not an escape. `None` otherwise, which is the
/// ordinary case.
fn escaped_close_reading(candidate: &str, close: usize) -> Option<String> {
    if candidate[close + 1..].starts_with('}') {
        return None;
    }
    let comma = candidate[close + 1..].find(',')? + close + 1;
    candidate[comma..].find('}')?;
    Some(format!(
        "{}{}",
        &candidate[..close],
        &candidate[close + 1..]
    ))
}

pub(super) fn expand_brace_globs(pattern: &str) -> Option<Vec<String>> {
    // The flag beside each candidate records whether it still carries the
    // braces of the word as written. Only such a candidate can have held the
    // backslash the tokenizer dropped, and a comma expansion hands that
    // standing on to every part it produces.
    let mut expanded = vec![(pattern.to_owned(), true)];
    for _ in 0..8 {
        // A brace with no `}` after it expands to nothing: bash leaves `a{b`
        // and a search pattern such as `json({ error` as the literal text it
        // was written as. Reading that shape as a glob nobody could expand
        // refused every search whose pattern held an unbalanced brace, so a
        // candidate ends the pass unless one of its braces could still open
        // an alternative.
        let Some(index) = expanded
            .iter()
            .position(|(candidate, _)| innermost_brace_pair(candidate).is_some())
        else {
            return Some(
                expanded
                    .into_iter()
                    .map(|(candidate, _)| candidate)
                    .collect(),
            );
        };
        let (candidate, as_written) = expanded.swap_remove(index);
        let (open, close) = innermost_brace_pair(&candidate)?;
        let choices: Vec<&str> = candidate[open + 1..close].split(',').collect();
        // A brace with no comma and no `..`, such as Git's `HEAD^{commit}`,
        // `@{u}` or a Go template `{{.Server.Version}}`, is literal text to the
        // shell and a single alternative to a glob, so it is checked as its
        // inner text: `{.env}` and `{{.env}}` still name `.env`. A `..`
        // sequence such as `.en{v..v}` expands in bash, so it keeps failing
        // closed.
        if choices.len() == 1 && !choices[0].contains("..") {
            let trimmed = choices[0].trim_start_matches('{');
            if !trimmed.contains('{') {
                let nested_braces = choices[0].len() - trimmed.len();
                let closing = "}".repeat(nested_braces);
                let suffix = candidate[close + 1..]
                    .strip_prefix(closing.as_str())
                    .unwrap_or(&candidate[close + 1..]);
                // The tokenizer drops a backslash before it reaches here, so
                // `z{prefix/{x\},.env}` arrives as `z{prefix/{x},.env}`. To
                // bash that `}` was literal text, which left the pair opening
                // further left and the words `z{prefix/x}` and `z{prefix/.env`.
                // Reading only the inner pair would hide that second word, so
                // the spelling with this brace taken as literal is carried
                // alongside and screened too. Only the word as written can
                // have carried the backslash, so a candidate this branch has
                // already rewritten yields no further reading; generating one
                // from every rewrite makes an ordinary multi-part template
                // outgrow the budget below and fail closed.
                if as_written {
                    if let Some(escaped) = escaped_close_reading(&candidate, close) {
                        expanded.push((escaped, false));
                    }
                }
                expanded.push((format!("{}{trimmed}{suffix}", &candidate[..open],), false));
                continue;
            }
        }
        if choices.len() < 2 || expanded.len() + choices.len() > 16 {
            return None;
        }
        for choice in choices {
            expanded.push((
                format!(
                    "{}{}{}",
                    &candidate[..open],
                    choice,
                    &candidate[close + 1..]
                ),
                as_written,
            ));
        }
    }
    None
}
