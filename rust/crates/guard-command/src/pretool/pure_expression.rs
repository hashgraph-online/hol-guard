//! Constant numeric expressions and plain strings have no file, network,
//! import or process effects.

struct Expression<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Expression<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn expression(&mut self, depth: usize) -> bool {
        if !self.term(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                return true;
            }
            self.position += 1;
            if !self.term(depth) {
                return false;
            }
        }
    }

    fn term(&mut self, depth: usize) -> bool {
        if !self.atom(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'*' | b'/' | b'%')) {
                return true;
            }
            self.position += 1;
            if !self.atom(depth) {
                return false;
            }
        }
    }

    fn atom(&mut self, depth: usize) -> bool {
        self.whitespace();
        if depth >= 8 {
            return false;
        }
        if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
            self.position += 1;
            return self.atom(depth + 1);
        }
        if self.bytes.get(self.position) == Some(&b'(') {
            self.position += 1;
            if !self.expression(depth + 1) {
                return false;
            }
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b')') {
                return false;
            }
            self.position += 1;
            return true;
        }
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position += 1;
        }
        (1..=9).contains(&(self.position - start))
    }
}

pub(super) fn safe_inline_expression(executable: &str, arguments: &[String]) -> bool {
    let [flag, script] = arguments else {
        return false;
    };
    let (flag_expected, prefix) = if matches!(executable, "python" | "python3") {
        ("-c", "print(")
    } else {
        ("-e", "console.log(")
    };
    if flag != flag_expected || script.len() > 256 {
        return false;
    }
    let Some(source) = script
        .trim()
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    let arguments = top_level_arguments(source);
    // A Python string print stays under review. The text can be a quoted
    // command, and this proof does not attest the interpreter or its startup.
    let strings_are_data = matches!(executable, "node" | "nodejs" | "bun");
    arguments.len() <= 8
        && arguments.iter().all(|argument| {
            numeric_source(argument)
                || (strings_are_data && plain_string_literal(argument))
                || runtime_fact(executable, argument)
        })
}

/// Splits a print argument list at commas outside string literals. A plain
/// literal holds no quote, so the quote state is exact for every argument the
/// checks below accept.
fn top_level_arguments(source: &str) -> Vec<&str> {
    let mut arguments = Vec::new();
    let mut quote = None;
    let mut start = 0;
    for (index, character) in source.char_indices() {
        match (quote, character) {
            (None, '"' | '\'') => quote = Some(character),
            (Some(open), _) if open == character => quote = None,
            (None, ',') => {
                arguments.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    arguments.push(&source[start..]);
    arguments
}

/// Read-only runtime identity properties. Nothing can redefine them before the
/// inline program starts unless a preload runs, which the caller excludes.
fn runtime_fact(executable: &str, source: &str) -> bool {
    let source = source.trim();
    let javascript = matches!(
        source,
        "process.version" | "process.versions.node" | "process.platform" | "process.arch"
    );
    match executable {
        "node" | "nodejs" => javascript,
        "bun" => javascript || matches!(source, "Bun.version" | "Bun.revision"),
        _ => false,
    }
}

fn numeric_source(source: &str) -> bool {
    let mut parser = Expression {
        bytes: source.as_bytes(),
        position: 0,
    };
    if !parser.expression(0) {
        return false;
    }
    parser.whitespace();
    parser.position == parser.bytes.len()
}

/// A quoted literal with no escapes, interpolation prefix, or line breaks.
fn plain_string_literal(source: &str) -> bool {
    let source = source.trim();
    let Some(quote) = source.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
        return false;
    };
    source.len() >= 2
        && source.len() <= 202
        && source.ends_with(quote)
        && source[1..source.len() - 1]
            .chars()
            .all(|c| (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\'' && c != '\\')
}

fn call_argument<'a>(statement: &'a str, callee: &str) -> Option<&'a str> {
    statement
        .trim()
        .strip_prefix(callee)?
        .strip_prefix('(')?
        .strip_suffix(')')
}

/// Python `print(<number expression | plain string>)` lines and comments only.
pub(super) fn python_print_program(code: &str) -> bool {
    // Python treats a lone CR as a line break that `lines()` does not split on.
    if code.contains('\r') {
        return false;
    }
    let lines: Vec<&str> = code
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    code.len() <= 1024
        && !lines.is_empty()
        && lines.len() <= 16
        && lines.iter().all(|line| {
            call_argument(line, "print")
                .is_some_and(|arg| numeric_source(arg) || plain_string_literal(arg))
        })
}

/// One JavaScript expression statement: a number expression, a plain string,
/// or `console.log` of one of those.
pub(super) fn javascript_pure_program(code: &str) -> bool {
    let code = code.trim().trim_end_matches(';').trim();
    code.len() <= 256
        && (numeric_source(code)
            || plain_string_literal(code)
            || call_argument(code, "console.log")
                .is_some_and(|arg| numeric_source(arg) || plain_string_literal(arg)))
}
