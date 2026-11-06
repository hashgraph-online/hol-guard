//! The literal ports a Node server names. A port may be a literal, a name
//! bound to one once, or an environment variable that falls back to one,
//! optionally read through `Number(...)` or `parseInt(..., 10)`, as in
//! `port = Number(process.env.PORT ?? 3000)`. Only the literal is granted:
//! the sandbox refuses every other port, so a value read at run time that
//! differs fails to bind rather than opening another port.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

/// `NAME =`: a declaration, a parameter default or an assignment.
static BINDING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=").unwrap());
/// `NAME +=`, `NAME++` or `++NAME`: an update, which is another binding.
static UPDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)=|\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)",
    )
    .unwrap()
});
/// Every declaration of a name, any of which may rebind or shadow it.
static DECLARATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|let|var|function|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b").unwrap()
});
/// `${...}` in a template literal.
static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{([^{}`]*)\}").unwrap());
static ENVIRONMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^process\s*\.\s*env\s*\.\s*[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static RADIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s*,\s*10\s*$").unwrap());

/// The names `masked` (the source with its strings blanked) binds to a port
/// expression exactly once, with `const` or as a parameter or destructuring
/// default, and declares nowhere else. A name also bound with `let`, `var`
/// or a plain assignment, or bound twice, is left out, so a `listen` on it
/// keeps the review.
pub(super) fn port_constants(masked: &str) -> BTreeMap<String, u16> {
    let mut declared = BTreeMap::<&str, usize>::new();
    for declaration in DECLARATION.captures_iter(masked) {
        let name = declaration.get(1).map_or("", |name| name.as_str());
        *declared.entry(name).or_default() += 1;
    }
    let mut bound = BTreeMap::<&str, Vec<Option<(u16, bool)>>>::new();
    for binding in BINDING.captures_iter(masked) {
        let (Some(whole), Some(name)) = (binding.get(0), binding.get(1)) else {
            continue;
        };
        let rest = &masked[whole.end()..];
        if rest.starts_with(['=', '>']) {
            continue;
        }
        let head = masked[..name.start()].trim_end();
        // A property, as in `options.port = 3000`, is not the name.
        if head.ends_with(['.', '?']) {
            continue;
        }
        let constant = head.ends_with("const") && !word_char_before(head, "const");
        let default = head.ends_with(['(', ',', '{']);
        let entry = bound.entry(name.as_str()).or_default();
        entry.push(
            (constant || default)
                .then(|| literal_port(expression(rest)))
                .flatten()
                .map(|port| (port, constant)),
        );
    }
    for update in UPDATE.captures_iter(masked) {
        let Some(name) = update
            .get(1)
            .or_else(|| update.get(2))
            .or_else(|| update.get(3))
        else {
            continue;
        };
        bound.entry(name.as_str()).or_default().push(None);
    }
    bound
        .into_iter()
        .filter_map(|(name, bindings)| match bindings.as_slice() {
            [Some((port, constant))] => {
                let expected = usize::from(*constant);
                (declared.get(name).copied().unwrap_or(0) == expected)
                    .then(|| (name.to_owned(), *port))
            }
            _ => None,
        })
        .collect()
}

fn word_char_before(head: &str, word: &str) -> bool {
    head[..head.len() - word.len()]
        .chars()
        .next_back()
        .is_some_and(|c| c == '_' || c == '$' || c.is_ascii_alphanumeric())
}

/// `code` with each `${...}` that reads as a port, a bound name or a port
/// expression, replaced by the literal. Any other expansion is left for the
/// caller to refuse.
pub(super) fn expand_templates(code: &str, constants: &BTreeMap<String, u16>) -> String {
    TEMPLATE
        .replace_all(code, |expansion: &regex::Captures| {
            let inner = expansion[1].trim();
            constants
                .get(inner)
                .copied()
                .or_else(|| literal_port(inner))
                .map_or_else(|| expansion[0].to_owned(), |port| port.to_string())
        })
        .into_owned()
}

/// The first argument or initializer at the start of `text`: everything up
/// to a `,`, `;`, line break or closing bracket outside any brackets.
pub(super) fn expression(text: &str) -> &str {
    let mut depth = 0usize;
    for (at, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return &text[..at],
            ')' | ']' | '}' => depth -= 1,
            ',' | ';' | '\n' if depth == 0 => return &text[..at],
            _ => {}
        }
    }
    text
}

/// The literal port `expression` reads as, when it is one: a literal, or an
/// environment variable with a literal fallback (`||` or `??`), either one
/// optionally converted with `Number(...)` or `parseInt(...)`.
pub(super) fn literal_port(expression: &str) -> Option<u16> {
    let expression = expression.trim();
    if (1..=5).contains(&expression.len()) && expression.bytes().all(|b| b.is_ascii_digit()) {
        return expression.parse().ok();
    }
    if let Some(inner) = converted(expression) {
        return literal_port(inner);
    }
    let (value, fallback) = fallback(expression)?;
    environment(value).then(|| literal_port(fallback)).flatten()
}

/// Whether `value` reads an environment variable, directly or converted.
fn environment(value: &str) -> bool {
    let value = value.trim();
    ENVIRONMENT.is_match(value) || converted(value).is_some_and(environment)
}

/// The argument of a `Number(...)` or `parseInt(...)` call spanning all of
/// `expression`, less a `parseInt` radix of 10.
fn converted(expression: &str) -> Option<&str> {
    let (inner, radix) = if let Some(rest) = expression.strip_prefix("Number") {
        (rest, false)
    } else {
        (expression.strip_prefix("parseInt")?, true)
    };
    let inner = inner.trim_start().strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0usize;
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return None,
            ')' => depth -= 1,
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    match RADIX.find(inner) {
        Some(found) if radix => Some(&inner[..found.start()]),
        _ => Some(inner),
    }
}

/// `value || fallback` or `value ?? fallback`, split at the first such
/// operator outside parentheses.
fn fallback(expression: &str) -> Option<(&str, &str)> {
    let bytes = expression.as_bytes();
    let mut depth = 0usize;
    for at in 0..bytes.len() {
        match bytes[at] {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1)?,
            b'|' | b'?' if depth == 0 && bytes.get(at + 1) == Some(&bytes[at]) => {
                return Some((&expression[..at], &expression[at + 2..]));
            }
            _ => {}
        }
    }
    None
}
