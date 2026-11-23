//! Docstrings, which document code rather than name what it opens.
//!
//! The host-reach screen reads every string literal of a program fed on
//! standard input, and of the local modules it imports, as a path the
//! program might open. Libraries document themselves in reStructuredText,
//! whose directives start with `..` (`.. deprecated:: 1.0`, `.. [1]`), so
//! the screen read `..` as a path climbing out of the workspace and held any
//! probe that imported such a module. A docstring's value is never used as
//! a path unless the program asks for it, so the screen skips docstrings:
//! a plain string (no `f` prefix, whose fields would run) that is the first
//! statement of a module or of a block, alone on its line, outside any
//! bracket. When the program or any module it loads reads `__doc__` or
//! calls `getdoc`, every string stays in the scan.

use std::sync::LazyLock;

use regex::Regex;

/// A statement that only copies one docstring onto another
/// (`wrapper.__doc__ = wrapped.__doc__`): the value stays a docstring.
static DOC_COPY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*[\w.]+\.__doc__[ \t]*=[ \t]*[\w.]+\.__doc__[ \t]*$").unwrap()
});

/// Whether `code` reads docstrings back as values, other than to copy one
/// onto another.
pub(in crate::pretool) fn read(code: &str) -> bool {
    let code = DOC_COPY.replace_all(code, "");
    code.contains("__doc__") || code.contains("getdoc")
}

/// `items` without the docstrings of `code`. `span` gives each item's
/// literal as a byte range of `code`, in source order. The screen finds
/// literals without knowing about comments, so one may start inside a
/// comment; it is kept, and when it runs on past the comment the brackets
/// can no longer be counted, so no later string is skipped either.
pub(super) fn without<T>(code: &str, items: Vec<T>, span: impl Fn(&T) -> (usize, usize)) -> Vec<T> {
    let bytes = code.as_bytes();
    let (mut at, mut depth, mut line_start, mut last) = (0usize, 0i64, true, None::<u8>);
    let mut lost = false;
    let mut kept = Vec::with_capacity(items.len());
    for item in items {
        let (start, end) = span(&item);
        lost |= start > end || end > code.len();
        if lost || start < at {
            kept.push(item);
            continue;
        }
        while at < start {
            match bytes[at] {
                b'#' => {
                    at += code[at..].find('\n').unwrap_or(code.len() - at);
                    continue;
                }
                b'\n' => line_start = last != Some(b'\\'),
                b' ' | b'\t' | b'\r' | b'\x0c' => {}
                byte => {
                    match byte {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => depth -= 1,
                        _ => {}
                    }
                    line_start = false;
                    last = Some(byte);
                }
            }
            at += 1;
        }
        if at > start {
            // Inside a comment.
            lost |= end > at;
            kept.push(item);
            continue;
        }
        let docstring = depth == 0
            && line_start
            && matches!(last, None | Some(b':'))
            && code[start..end]
                .trim_start_matches(['r', 'R', 'u', 'U', 'b', 'B'])
                .starts_with(['"', '\''])
            && code[end..].split('\n').next().is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.is_empty() || rest.starts_with('#')
            });
        if !docstring {
            kept.push(item);
        }
        at = end;
        line_start = false;
        last = Some(b'"');
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::{read, without};

    fn strings(code: &str) -> Vec<String> {
        let spans: Vec<(usize, usize)> =
            regex::Regex::new(r#"(?s)\w*(?:"""(.*?)"""|'''(.*?)'''|"[^"\n]*"|'[^'\n]*')"#)
                .unwrap()
                .find_iter(code)
                .map(|found| (found.start(), found.end()))
                .collect();
        without(code, spans, |span| *span)
            .into_iter()
            .map(|(start, end)| code[start..end].to_owned())
            .collect()
    }

    #[test]
    fn docstrings_are_skipped() {
        for code in [
            "\"\"\"Module.\n\n.. [1] see the docs\n\"\"\"\nimport json\n",
            "def f():\n    \"\"\"Wrap it.\n\n    .. deprecated:: 11.0\n    \"\"\"\n    return 1\n",
            "class A:\n    r'''Raw ../doc'''  # note\n",
            "def f(\n    a,  # (\n):\n    '..'\n",
            "x = 1  # (\"a\" b)\n\ndef f():\n    '..'\n",
        ] {
            let found = strings(code);
            assert!(
                !found.iter().any(|found| found.contains("..")),
                "{code}: {found:?}"
            );
        }
    }

    #[test]
    fn strings_the_program_uses_are_kept() {
        for (code, kept) in [
            ("def f():\n    return '..'\n", "'..'"),
            ("x = (\n    '/etc/passwd'\n)\n", "'/etc/passwd'"),
            ("open(  # )\n    '/etc/passwd'\n)\n", "'/etc/passwd'"),
            ("if x:\n    f'{open(\"/etc/passwd\")}'\n", "\"/etc/passwd\""),
            ("def f():\n    '/etc/passwd'.join(x)\n", "'/etc/passwd'"),
            ("def f():\n    pass\n'/etc/passwd'\n", "'/etc/passwd'"),
            ("x = \\\n    '/etc/passwd'\n", "'/etc/passwd'"),
            ("d = {'k':\n    '/etc/passwd'}\n", "'/etc/passwd'"),
            ("if x: '/etc/passwd'\n", "'/etc/passwd'"),
            (
                "# say \"\"\" here\nx = 1\n\"\"\"\ndef f():\n    '/etc/passwd'\n",
                "'/etc/passwd'",
            ),
        ] {
            assert!(
                strings(code)
                    .iter()
                    .any(|found| found.contains(kept.trim_matches(['\'', '"']))),
                "{code}: {:?}",
                strings(code)
            );
        }
    }

    #[test]
    fn copying_a_docstring_is_not_reading_it() {
        assert!(!read("wrapper.__doc__ = _wrapped.__doc__\n"));
        for code in [
            "print(open(f.__doc__).read())\n",
            "a.__doc__ = b.__doc__\nopen(a.__doc__)\n",
            "import inspect\ninspect.getdoc(f)\n",
        ] {
            assert!(read(code), "{code}");
        }
    }
}
