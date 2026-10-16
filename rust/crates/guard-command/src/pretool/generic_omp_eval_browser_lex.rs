//! Tokens, option tables and the loopback URL check for the browser eval
//! parser in `generic_omp_eval_browser.rs`.

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Token {
    Ident(String),
    Str(String),
    Num,
    Punct(char),
}

fn escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, quote: char) -> Option<char> {
    match chars.next()? {
        '\\' => Some('\\'),
        'n' => Some('\n'),
        't' => Some('\t'),
        c if c == quote || matches!(c, '\'' | '"' | '`') => Some(c),
        _ => None,
    }
}

pub(super) fn tokenize(code: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = code.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
        } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let mut ident = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                    ident.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Ident(ident));
        } else if c.is_ascii_digit() {
            let mut seen_dot = false;
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() || (c == '.' && !seen_dot) {
                    seen_dot |= c == '.';
                    chars.next();
                } else {
                    break;
                }
            }
            if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                return None;
            }
            tokens.push(Token::Num);
        } else if matches!(c, '\'' | '"' | '`') {
            chars.next();
            let mut value = String::new();
            loop {
                match chars.next()? {
                    '\\' => value.push(escape(&mut chars, c)?),
                    '$' if c == '`' && chars.peek() == Some(&'{') => return None,
                    '\n' | '\r' if c != '`' => return None,
                    ch if ch == c => break,
                    ch if ch.is_control() && !matches!(ch, '\n' | '\t' | '\r') => return None,
                    ch => value.push(ch),
                }
            }
            tokens.push(Token::Str(value));
        } else if "(){}[],;:.=!<>+-*%&|?".contains(c) {
            chars.next();
            tokens.push(Token::Punct(c));
        } else {
            // `/` starts comments, regular expressions and division, which a
            // token scan cannot tell apart; it and anything else non-ASCII or
            // unmodeled leave the program reviewed.
            return None;
        }
    }
    Some(tokens)
}

/// Names a program may not bind, because the bridge or Node gives them a
/// meaning this parser does not model.
pub(super) const RESERVED: &[&str] = &[
    "async",
    "await",
    "browser",
    "class",
    "console",
    "const",
    "delete",
    "display",
    "eval",
    "exports",
    "false",
    "fetch",
    "function",
    "globalThis",
    "import",
    "let",
    "log",
    "module",
    "new",
    "null",
    "process",
    "require",
    "return",
    "this",
    "tool",
    "true",
    "typeof",
    "undefined",
    "var",
    "void",
    "yield",
    "Bun",
    "Deno",
    "Function",
    "JSON",
    "Promise",
];

/// Names a page function may not use: requests, navigation, markup, style
/// and element sinks that load URLs, code evaluation, property writers, and
/// handles to the global object that would reach any of them by another name.
const PAGE_SINKS: &[&str] = &[
    "EventSource",
    "Function",
    "Image",
    "Proxy",
    "Reflect",
    "SharedWorker",
    "WebSocket",
    "Worker",
    "XMLHttpRequest",
    "__proto__",
    "action",
    "assign",
    "background",
    "backgroundImage",
    "click",
    "constructor",
    "contentWindow",
    "cookie",
    "createElement",
    "cssText",
    "data",
    "defaultView",
    "defineProperties",
    "defineProperty",
    "dispatchEvent",
    "eval",
    "fetch",
    "formAction",
    "frames",
    "globalThis",
    "history",
    "href",
    "import",
    "importScripts",
    "innerHTML",
    "insertAdjacentHTML",
    "insertRule",
    "location",
    "navigation",
    "navigator",
    "open",
    "opener",
    "outerHTML",
    "parent",
    "ping",
    "postMessage",
    "poster",
    "prototype",
    "requestSubmit",
    "self",
    "sendBeacon",
    "serviceWorker",
    "setAttribute",
    "setInterval",
    "setProperty",
    "setPrototypeOf",
    "setTimeout",
    "src",
    "srcdoc",
    "srcset",
    "submit",
    "this",
    "top",
    "window",
    "with",
    "write",
    "writeln",
];

/// Whether page-function body token `index` is allowed. Property access must
/// be by name or by a number index, so a sink name cannot be assembled from
/// strings, and `=` may only initialize a new local, so the function cannot
/// write a URL into the page.
pub(super) fn page_token(tokens: &[Token], index: usize) -> bool {
    let at = |offset: isize| {
        index
            .checked_add_signed(offset)
            .and_then(|position| tokens.get(position))
    };
    match &tokens[index] {
        Token::Ident(name) => !PAGE_SINKS.contains(&name.as_str()),
        Token::Str(text) => !text.contains("://") && !text.starts_with("//"),
        Token::Punct('[') => {
            !matches!(
                at(-1),
                Some(Token::Ident(_) | Token::Str(_) | Token::Punct(')' | ']'))
            ) || matches!((at(1), at(2)), (Some(Token::Num), Some(Token::Punct(']'))))
        }
        Token::Punct('=') => {
            matches!(at(1), Some(Token::Punct('=' | '>')))
                || matches!(at(-1), Some(Token::Punct('=' | '!' | '<' | '>')))
                || (matches!(at(-1), Some(Token::Ident(_)))
                    && matches!(at(-2), Some(Token::Ident(word)) if matches!(word.as_str(), "const" | "let" | "var")))
        }
        _ => true,
    }
}

/// Tab methods that read or reset the page when called with no arguments.
pub(super) const NO_ARGUMENT_METHODS: &[&str] = &[
    "title",
    "url",
    "reload",
    "observe",
    "screenshot",
    "errors",
    "console",
    "close",
];

/// Option keys the tab methods below accept, all presentation or timing.
pub(super) const OPTION_KEYS: &[&str] = &[
    "annotate",
    "clear",
    "compact",
    "exact",
    "format",
    "fullPage",
    "hidden",
    "ifChanged",
    "includeAll",
    "level",
    "limit",
    "quality",
    "selector",
    "silent",
    "since",
    "threshold",
    "timeout",
    "viewportOnly",
    "visible",
    "waitUntil",
];

/// `browser.open` keys that only shape a headless page. `app`, `cdp_url`,
/// `init_scripts`, `downloads`, `allow_file_access`, `persist`,
/// `user_agent`, `ignore_https_errors` and `allowed_domains` are absent.
pub(super) const OPEN_KEYS: &[&str] = &[
    "dialogs",
    "headed",
    "name",
    "timeout",
    "url",
    "viewport",
    "wait_until",
];

/// An `http(s)` URL whose host is the loopback interface, with no userinfo.
pub(super) fn loopback_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    if !rest.is_ascii()
        || rest
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || matches!(c, '\\' | '@'))
    {
        return false;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let (host, port) = match authority.strip_prefix("[::1]") {
        Some(port) => ("[::1]", port),
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    let port_ok = port.is_empty()
        || port.strip_prefix(':').is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 5 && digits.bytes().all(|b| b.is_ascii_digit())
        });
    port_ok
        && matches!(
            host.to_ascii_lowercase().as_str(),
            "localhost" | "127.0.0.1" | "[::1]"
        )
}
