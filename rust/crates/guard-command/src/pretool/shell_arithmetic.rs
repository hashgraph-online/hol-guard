//! Arithmetic expansion (`$((...))`, `$[...]`) in a step's text, and whether
//! it can change shell state that a later step reads.

/// Whether the text runs an arithmetic expansion (`$((...))` or `$[...]`),
/// which can assign a variable. Text inside single quotes or behind a
/// backslash is printed as written and runs nothing; double quotes still
/// expand. ANSI-C quoting (`$'...'`) escapes its own quotes, so text with
/// it is read whole.
#[cfg(test)]
fn runs_arithmetic(text: &str) -> bool {
    any_arithmetic_body(text, |_| true)
}

/// Whether arithmetic in `text` can assign (`$((PATH=10))`, `$((i++))`), so
/// a later step sees it. A plain expansion such as `$(( (1 + 1) * 2 ))` only
/// computes.
pub(super) fn arithmetic_assigns(text: &str) -> bool {
    any_arithmetic_body(text, body_assigns)
}

/// Whether `reads` accepts the body of any arithmetic expansion the shell
/// runs in `text`. Each expansion is read only to its own close, so text
/// after it -- a later `git log --oneline`, a `--format=%H` -- is left to
/// the step that owns it.
fn any_arithmetic_body(text: &str, reads: impl Fn(&str) -> bool) -> bool {
    let bytes = text.as_bytes();
    let quoted = !text.contains("$'");
    let (mut single, mut double, mut index) = (false, false, 0);
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if quoted && !double => single = !single,
            b'"' if quoted && !single => double = !double,
            b'\\' if quoted && !single => index += 1,
            b'$' if !single => {
                if let Some((open, body)) = arithmetic_body(&text[index..]) {
                    if reads(body) {
                        return true;
                    }
                    index += open + body.len();
                }
            }
            _ => {}
        }
        index += 1;
    }
    false
}

/// The arithmetic expansion opening `rest`: the width of its opener and the
/// body up to its own close. `$((` counts parentheses, so a nested `(1 + 1)`
/// does not end it; an unclosed expansion reads to the end of the text.
fn arithmetic_body(rest: &str) -> Option<(usize, &str)> {
    if let Some(inner) = rest.strip_prefix("$((") {
        let mut depth = 2usize;
        for (offset, character) in inner.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((3, &inner[..offset]));
                    }
                }
                _ => {}
            }
        }
        return Some((3, inner));
    }
    let inner = rest.strip_prefix("$[")?;
    match inner.find(']') {
        Some(end) => Some((2, &inner[..end])),
        None => Some((2, inner)),
    }
}

/// Whether an arithmetic body can assign: an `=` that is not a comparison
/// (`==`, `!=`, `<=`, `>=`, while `<<=` and `>>=` do assign), an increment
/// or decrement, or anything but numbers and operators. Bash evaluates the
/// value a name holds (`$((x))`) or an expansion yields (`$(($x))`) as an
/// expression in turn, so `x=PATH=10` assigns through it.
fn body_assigns(body: &str) -> bool {
    if !body
        .bytes()
        .all(|byte| byte.is_ascii_digit() || b" \t\n+-*/%()<>=!&|^~?:,".contains(&byte))
    {
        return true;
    }
    let bytes = body.as_bytes();
    (0..bytes.len()).any(|index| {
        let before = |back: usize| index.checked_sub(back).map(|at| bytes[at]);
        match bytes[index] {
            b'+' | b'-' => bytes.get(index + 1) == Some(&bytes[index]),
            b'=' => {
                bytes.get(index + 1) != Some(&b'=')
                    && !matches!(before(1), Some(b'=' | b'!'))
                    && !(matches!(before(1), Some(b'<' | b'>')) && before(2) != before(1))
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    /// Arithmetic runs where the shell expands it: bare or in double quotes, not
    /// in single quotes or behind a backslash.
    #[test]
    fn arithmetic_is_read_where_the_shell_runs_it() {
        for text in [
            "echo $((PATH=10))",
            "echo \"$((PATH=10))\"",
            "echo $[PATH=10]",
            "echo \"it's\" $((PATH=10))",
            "echo $'\\'' $((PATH=10))",
        ] {
            assert!(super::runs_arithmetic(text), "{text}");
        }
        for text in ["echo '$((PATH=10))'", "echo \\$((PATH=10))", "echo $PATH"] {
            assert!(!super::runs_arithmetic(text), "{text}");
        }
    }

    /// Only a body of numbers and operators leaves a later step alone. The
    /// body ends at its own close, so an option or a `name=value` in the rest of
    /// the step is the step's own text, not arithmetic.
    #[test]
    fn only_assigning_arithmetic_changes_later_steps() {
        for text in [
            "cat package.json $((PATH=10))",
            "echo $((x+=1))",
            "echo $((i++))",
            "echo $[PATH=10]",
            "echo $((x<<=1))",
            "echo $((1 == 2)) $((PATH=10))",
            "echo $((x)) done",
            "echo $(($x))",
            "echo $[x]",
            "echo $(($(id -u) + 1))",
        ] {
            assert!(super::arithmetic_assigns(text), "{text}");
        }
        for text in [
            "sleep $(( (1 + 1) * 2 ))",
            "echo $((1 == 2)) $((3 <= 4)) $((5 != 6)) $[7 >= 8]",
            "echo '$((PATH=10))'",
            "timeout $((60 * 2)) git fetch --all",
            "git log -n $((5)) --format=%H",
        ] {
            assert!(!super::arithmetic_assigns(text), "{text}");
        }
    }
}
