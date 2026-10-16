//! Assignment values that are code, not secret material.
//!
//! Reading source that handles a credential (`let auth_token = request.header("x");`,
//! `auth_token: Option<String>,`, `auth_token: &str,`, a docs line such as
//! `auth_token: the bearer credential`) matches the credential assignment
//! rule on the identifier alone. The value that follows is a call, a typed
//! declaration, a lowercase identifier or prose, none of which a secret looks
//! like. A quoted literal, a bare token with digits or punctuation (dotenv
//! style `AUTH_TOKEN=sk-live-...`) and anything with a long quoted literal on
//! the rest of the line are never treated as code here.

use regex::Regex;
use std::sync::LazyLock;

/// A call: a path of identifiers up to its opening parenthesis.
static CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*!?\((?:(?:[&*]?[a-z_][a-z_.]*(?:,\s?[&*]?[a-z_][a-z_.]*)*)?\)[?;,)]*)?$")
        .expect("call rule must compile")
});

/// A member or module path closed by a statement end (`req.headers.token;`,
/// `self.load()?`). Without the terminator a dotted value stays flagged; with
/// it, an upper-case key or a segment that looks encoded still does.
static PATH_STATEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)+(?:\?;?|;)$")
        .expect("path statement rule must compile")
});

/// Type annotations: references, generics and bare primitive type names.
static TYPE_ANNOTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^&$|^&(?:'[a-z_]+|mut|[A-Za-z_][A-Za-z0-9_:]*)[,;)>]*$",
        r"|^[A-Z][A-Za-z0-9_]*<[A-Za-z0-9_<>:&',\[\]]*$",
        r"|^(?:string|number|boolean|str|String|bytes|Bytes|bool|u8|u16|u32|u64|usize|i32|i64|Vec<u8>|PathBuf|Path)[,;)>|]+$",
    ))
    .expect("type annotation rule must compile")
});

/// A snake_case identifier with at least one underscore, as in a variable
/// passed along (`"X-Guard-Token": auth_token}`).
static SNAKE_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z]+(?:_[a-z]+)+[;,)?]*$").expect("identifier rule must compile")
});

/// A documentation lead word, as in `auth_token: the bearer credential`. A
/// passphrase of ordinary words (`password: correct horse battery staple`)
/// does not start with one, so it stays flagged.
static PROSE_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:the|a|an|your|this|that|its|their|optional|required|used|set|see|same)$")
        .expect("prose word rule must compile")
});

static PROSE_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s+[a-z]{2,}(?:[ ,]+[a-z]{2,})+").expect("prose tail rule must compile")
});

/// A quoted literal long enough to be a credential.
static LONG_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`][^"'`\s]{12,}["'`]"#).expect("long literal rule must compile")
});

/// Whether a credential assignment match carries code or prose rather than a
/// secret value. `rest_of_line` is the text after the match on the same line.
pub(crate) fn is_code_value(matched: &str, rest_of_line: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let value = matched[index + 1..].trim();
    if value.is_empty() || value.starts_with(['"', '\'']) {
        return false;
    }
    if CALL.is_match(value) {
        // Environment lookups carry their default as a second literal. An
        // upper-case dotenv key holds data, so `DB_PASSWORD=wrap(value)` stays
        // a credential.
        return !environment_style_key(&matched[..index])
            && !value.to_ascii_lowercase().contains("env")
            && rest_of_line.matches(['"', '\'', '`']).count() <= 2
            && !LONG_LITERAL.is_match(rest_of_line);
    }
    if PATH_STATEMENT.is_match(value) {
        // `AUTH_TOKEN=eyJ...;` is a shell assignment of a token, not a path.
        return !environment_style_key(&matched[..index])
            && !value
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(encoded_segment);
    }
    if SNAKE_IDENTIFIER.is_match(value) {
        // `DB_PASSWORD=super_secret_pass` or `password: my_pass_phrase` is a
        // value; a variable passed along ends a code expression.
        return !environment_style_key(&matched[..index])
            && (value.ends_with([';', ',', ')', '?'])
                || rest_of_line
                    .trim_start()
                    .starts_with([';', ',', ')', '}', ']']));
    }
    if TYPE_ANNOTATION.is_match(value) {
        return !LONG_LITERAL.is_match(rest_of_line);
    }
    PROSE_WORD.is_match(value)
        && !environment_style_key(&matched[..index])
        && matched[..index]
            .trim_end_matches(['"', '\''])
            .ends_with(|c: char| c != ' ')
        && PROSE_TAIL.is_match(rest_of_line)
}

/// A path segment long enough to be encoded material and shaped like it:
/// digits or mixed case, as in each part of a JWT.
fn encoded_segment(segment: &str) -> bool {
    segment.len() >= 16
        && (segment.chars().any(|c| c.is_ascii_digit())
            || (segment.chars().any(|c| c.is_ascii_uppercase())
                && segment.chars().any(|c| c.is_ascii_lowercase())))
}

/// An upper-case key such as `DB_PASSWORD` in a dotenv or shell assignment,
/// whose value is data rather than code.
fn environment_style_key(key: &str) -> bool {
    let key = key
        .trim()
        .trim_matches(['"', '\''])
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    key.chars().any(|c| c.is_ascii_uppercase())
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn flagged(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn identifiers_in_code_and_docs_are_not_credentials() {
        for text in [
            "let auth_token = request.header(\"x\");",
            "let auth_token = request.header(\"x\")?;",
            "let auth_token = self.load_auth_token(&home)?;",
            "auth_token = get_token(user)",
            "def refresh(auth_token: str, other: int):",
            "pub struct S {\n    pub auth_token: Option<String>,\n}",
            "    auth_token: Option<String>,",
            "fn run(auth_token: &str, home: &Path) {",
            "fn run(&self, auth_token: &'a str) {",
            "auth_token = os.environ[\"AUTH_TOKEN\"]",
            "let auth_token = std::env::var(\"AUTH_TOKEN\")?;",
            "headers = {\"X-Guard-Token\": auth_token}",
            "const authToken = req.headers.authorization;",
            "Set auth_token in your config.",
            "- auth_token: the bearer credential used by clients",
        ] {
            assert!(!flagged(text), "{text:?}");
        }
    }

    #[test]
    fn real_looking_values_are_still_credentials() {
        let github = ["ghp", "_abcdefghijklmnopqrstuvwxyz0123456789"].concat();
        let live = ["sk-", "live-abcdefghijklmnop1234"].concat();
        let sample = ["a1b2c3d4", "e5f6g7h8i9j0"].concat();
        let jwt = ["eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"].concat();
        for text in [
            format!("auth_token = \"{github}\""),
            format!("let auth_token = \"{github}\";"),
            format!("AUTH_TOKEN={live}"),
            format!("auth_token = '{sample}'"),
            format!("AUTH_TOKEN={sample}"),
            "password = hunter2production".to_string(),
            "DB_PASSWORD=super_secret_pass".to_string(),
            "password: my_pass_phrase".to_string(),
            "password: correct horse battery staple".to_string(),
            "auth_token = decode(c2VjcmV0dG9rZW4xMjM0NQ)".to_string(),
            format!("auth_token = get_token(\"{sample}\")"),
            format!("auth_token: &str = \"{sample}\""),
            format!("auth_token = {jwt}"),
            format!("auth_token = {jwt};"),
            format!("token={jwt};"),
            format!("export AUTH_TOKEN={jwt}; curl https://example.test"),
            "AUTH_TOKEN=config.session.value;".to_string(),
            "DB_PASSWORD=wrap(value)".to_string(),
        ] {
            assert!(flagged(&text), "{text:?}");
        }
    }
}
