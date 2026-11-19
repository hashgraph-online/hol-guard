//! Python source a text scan can read when the program holds non-ASCII text.
//!
//! The checks on a program fed to Python read its text for names such as
//! `import`, `exec`, a host or a path. Python folds non-ASCII identifiers with
//! NFKC, so `ｅｘｅｃ` names `exec`; those checks need the code they read to be
//! ASCII. Agents still write `print('café')` or `# ✓ done`, and that held the
//! whole program.
//!
//! Text inside a comment or a plain string literal is never an identifier, so
//! here each non-ASCII character there becomes `?`, which joins no name.
//! Non-ASCII anywhere else keeps the program held: in code, and inside an
//! f-string or t-string, whose braces hold code.

/// `source` with each non-ASCII character inside a comment or a plain string
/// literal replaced by `?`. `None` when non-ASCII sits in code or in an
/// f-string or t-string, or when a string is left open.
pub(super) fn ascii_view(source: &str) -> Option<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    while at < chars.len() {
        match chars[at] {
            '#' => {
                while at < chars.len() && chars[at] != '\n' {
                    out.push(masked(chars[at]));
                    at += 1;
                }
            }
            '\'' | '"' => at = string(&chars, at, template(&chars[..at]), &mut out)?,
            character if !character.is_ascii() => return None,
            character => {
                out.push(character);
                at += 1;
            }
        }
    }
    Some(out)
}

fn masked(character: char) -> char {
    if character.is_ascii() {
        character
    } else {
        '?'
    }
}

/// Whether the letters right before a quote may make it an f-string or a
/// t-string. Any `f` or `t` among them counts, so a keyword such as
/// `return'x'` is read the careful way.
fn template(before: &[char]) -> bool {
    before
        .iter()
        .rev()
        .take_while(|character| character.is_ascii_alphabetic())
        .any(|character| matches!(character, 'f' | 'F' | 't' | 'T'))
}

/// Copies the string literal opening at `start` and returns the index just
/// past its closing quote.
fn string(chars: &[char], start: usize, template: bool, out: &mut String) -> Option<usize> {
    let quote = chars[start];
    let closes = |at: usize, width: usize| (at..at + width).all(|i| chars.get(i) == Some(&quote));
    let width = if closes(start, 3) { 3 } else { 1 };
    out.extend(std::iter::repeat_n(quote, width));
    let mut at = start + width;
    loop {
        let character = *chars.get(at)?;
        if closes(at, width) {
            out.extend(std::iter::repeat_n(quote, width));
            return Some(at + width);
        }
        if width == 1 && character == '\n' {
            return None;
        }
        // A backslash keeps the next character in the string, raw or not.
        let step = if character == '\\' { 2 } else { 1 };
        for &inner in chars.get(at..at + step)? {
            if template && !inner.is_ascii() {
                return None;
            }
            out.push(masked(inner));
        }
        at += step;
    }
}

#[cfg(test)]
mod tests {
    use super::ascii_view;

    #[test]
    fn text_in_comments_and_plain_strings_is_masked() {
        for (source, view) in [
            ("print('café')\n", "print('caf?')\n"),
            ("# ✓ done\nx = 1\n", "# ? done\nx = 1\n"),
            ("s = \"a → b\"  # — note\n", "s = \"a ? b\"  # ? note\n"),
            ("d = '''\nnaïve\n'''\n", "d = '''\nna?ve\n'''\n"),
            ("r = r'\\é'\n", "r = r'\\?'\n"),
            ("e = 'it\\'s é'\n", "e = 'it\\'s ?'\n"),
            ("b = rb'x' + u'ü'\n", "b = rb'x' + u'?'\n"),
            ("empty = '' + 'é'\n", "empty = '' + '?'\n"),
            ("print(f'{x}') # é\n", "print(f'{x}') # ?\n"),
        ] {
            assert_eq!(ascii_view(source).as_deref(), Some(view), "{source:?}");
        }
    }

    #[test]
    fn non_ascii_code_or_templates_stay_held() {
        for source in [
            // NFKC folds this identifier to `exec`.
            "ｅｘｅｃ('print(1)')\n",
            "café = 1\n",
            "print(f'{ｅｘｅｃ}')\n",
            "print(f'café')\n",
            "print(t'é')\n",
            "print(rf'é')\n",
            "x = 1\u{a0}+ 1\n",
            "\u{feff}print(1)\n",
            // A string left open swallows what follows.
            "print('é\n",
            "s = '''é\n",
        ] {
            assert_eq!(ascii_view(source), None, "{source:?}");
        }
    }

    #[test]
    fn ascii_source_is_unchanged() {
        let source = "import json\nprint(json.dumps({'a': \"b\"}))  # ok\n";
        assert_eq!(ascii_view(source).as_deref(), Some(source));
    }
}
