//! File-tool writes that put a live credential into a file.
//!
//! A key, token or password written into source, configuration or notes is
//! out of the user's hands from then on: it is committed, synced, pasted into
//! a review or read back by another tool. Guard reviews such a write instead
//! of treating it as an ordinary workspace edit.
//!
//! A credential is recognised by its own shape (a private key body, a JWT, a
//! vendor token prefix, credentials inside a URL, an `otpauth` secret) or by
//! a random-looking value placed next to a credential name
//! (`client_secret = "…"`, `--keystore-password …`, `?access_token=…`).
//! Placeholders, references, identifiers and English words next to the same
//! names are left alone; see [`value::looks_random`].

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

#[path = "literal_secret_pairs.rs"]
mod pairs;
#[path = "literal_secret_value.rs"]
mod value;

use value::{decode_base64, looks_random, pair_score, placeholder, placeholder_within};

/// Text beyond this many characters of one body is not scanned; a write
/// with a longer body is reviewed as a whole instead.
pub(super) const SCAN_LIMIT: usize = 512 * 1024;
const BODY_KEYS: [&str; 4] = ["content", "contents", "new_string", "newString"];

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("literal secret pattern compiles")
}

macro_rules! patterns {
    ($($name:ident = $source:expr;)*) => {
        $(static $name: LazyLock<Regex> = LazyLock::new(|| pattern($source));)*
    };
}

patterns! {
    PRIVATE_KEY_BODY = r#"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\s|\\n|["+])*MII[A-Za-z0-9+/]{37,}|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----\s*(?:\\n)?\s*[A-Za-z0-9+/]{40,}"#;
    JWT = r"eyJ[A-Za-z0-9_\-]{8,}={0,2}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}";
    PGP_BODY = r"\n\s*[A-Za-z0-9+/]{40,}";
    NESTED = r#"(?i)["']?[A-Za-z_]*(?:token|secret|passw(?:or)?d|api_?key)["']?\s*[:=]\s*"\{(.{0,400}?)\}""#;
    NESTED_TOKEN = r"[A-Za-z0-9]{16,}";
    BASIC = r"\bBasic\s+([A-Za-z0-9+/]{6,}={0,2})";
    PREFIXED = r"(?:glsa_|glc_|key-|AKIA)[A-Za-z0-9_\-+/=]{14,}";
    PREFIX_SHAPE = r"^(?:glsa_[A-Za-z0-9]{20,}|glc_[A-Za-z0-9+/=]{20,}|key-[a-z0-9]{32}|AKIA[A-Z0-9]{16})";
    URL_CREDENTIAL = r#"(?i)[a-z][a-z0-9+.\-]*://([^\s:/@"']{1,64}):(?P<v>[^\s@/"']{3,128})@[^\s"']+"#;
    URL_LETTERS = r"^[a-z_]{4,10}$";
    ASSIGN = r#"(?ix)
        (?P<k>[A-Za-z0-9_.\-]*?(?:secret|token|passw(?:or)?d|passwd|pwd|pass|api[_-]?key|apikey|access[_-]?key|auth|credential|private[_-]?key|client[_-]?secret|key)[A-Za-z0-9_\-]*)["']?\s*(?::=|=>|=|:)\s*
        (?:[@$]?["'`](?P<v>[^"'`\s]{6,200})["'`]|(?P<b>[^\s"'`,;\#{}()\[\]<>]{8,200}))"#;
    NOT_A_SECRET_NAME = r"(?i)(?:public|keyid|key_?id\b|expir|env_?key|_path|path$|keycode|keyalgo|keyusage|keypolic|fake|dummy|example|sample|mock|placeholder|^keys$|resourcekey|desc_prefix|authoriz|_url$|url$|tokenizer|credentials$|_name$|name$|type$)";
}

/// Shapes whose captured `v` is a credential once it is not a placeholder.
static SHAPED: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        pattern(r#"otpauth://[^\s"']*[?&]secret=(?P<v>[A-Z2-7]{16,})"#),
        pattern(r"\b(?P<v>wx[0-9a-f]{16})\b"),
        pattern(r"\b(?P<v>(?:AROA|ASIA|AIDA|ANPA|AGPA|AIPA)[A-Z0-9]{16,})\b"),
    ]
});
/// Shapes whose captured `v` is a credential when it also looks random.
static NAMED: LazyLock<[Regex; 9]> = LazyLock::new(|| {
    [
        pattern(
            r#"(?i)--?[a-z\-]*(?:password|passwd|passphrase|token|secret)[a-z\-]*["']?\s*[,=]?\s*["']?(?P<v>[A-Za-z0-9+/_\-]{6,})"#,
        ),
        pattern(r"(?i)\bIDENTIFIED\s+BY\s+(?P<v>[A-Za-z0-9_]{6,})"),
        pattern(r"(?i)\bBasic\s+(?P<v>[A-Za-z0-9+/]{8,}={0,2})"),
        pattern(
            r#"(?i)[?&#](?:refresh_?token|access_?token|token|auth_?key|user_credentials|formkey|oauth_token|oauth_verifier|api_?key|secret)=(?P<v>[^&\s"'#<>]{8,})"#,
        ),
        pattern(r"\bBearer\s+(?P<v>[A-Za-z0-9._~+/\-]{16,}=*)"),
        pattern(r#"-pass(?:in|out)?\s+pass:(?P<v>[^\s"']{4,})"#),
        pattern(r#"(?i)\bIDENTIFIED\s+BY\s+(?:PASSWORD\s+)?["'](?P<v>[^"'\n]{4,64})["']"#),
        pattern(r"(?i)\bPASSWORD\s+'(?P<v>[^'\n]{4,64})'"),
        pattern(
            r#"(?i)(?:getenv|environ\.get|env\.get|ENV\.fetch)\(\s*["'][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|KEY)[A-Za-z0-9_]*["']\s*,\s*["'](?P<v>[^"'\s]{6,})["']"#,
        ),
    ]
});

fn basic_credentials(encoded: &str) -> bool {
    decode_base64(encoded)
        .is_some_and(|text| text.contains(':') && !text.chars().any(char::is_control))
}

fn url_password(found: &regex::Captures<'_>) -> bool {
    let secret = &found["v"];
    let user = &found[1];
    let digit_and_letter = secret.chars().count() >= 3
        && secret.bytes().any(|byte| byte.is_ascii_digit())
        && secret.bytes().any(|byte| byte.is_ascii_alphabetic());
    !placeholder_within(secret)
        && secret != user
        && (looks_random(secret)
            || (URL_LETTERS.is_match(secret) && pair_score(&secret.replace('_', "")) < -4.3)
            || digit_and_letter
            || secret.chars().count() >= 8)
}

/// Whether `text` holds a credential that looks real.
pub(super) fn holds_literal_secret(text: &str) -> bool {
    let text = match text.char_indices().nth(SCAN_LIMIT) {
        Some((end, _)) => &text[..end],
        None => text,
    };
    // `\u0041\u004b...` in a JSON or source string is the same key once the
    // file is read back.
    if let Some(decoded) = unicode_unescaped(text) {
        if holds_spelled_secret(&decoded) {
            return true;
        }
    }
    holds_spelled_secret(text)
}

/// `text` with its `\uXXXX` escapes decoded, when it has any.
fn unicode_unescaped(text: &str) -> Option<String> {
    if !text.contains("\\u") {
        return None;
    }
    let mut decoded = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(at) = rest.find("\\u") {
        decoded.push_str(&rest[..at]);
        let hex = rest.get(at + 2..at + 6);
        match hex
            .filter(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32)
        {
            Some(character) => {
                decoded.push(character);
                rest = &rest[at + 6..];
                changed = true;
            }
            None => {
                decoded.push_str("\\u");
                rest = &rest[at + 2..];
            }
        }
    }
    decoded.push_str(rest);
    changed.then_some(decoded)
}

fn holds_spelled_secret(text: &str) -> bool {
    if PRIVATE_KEY_BODY.is_match(text)
        || JWT.is_match(text)
        || guard_scanner::holds_live_payment_key(text)
    {
        return true;
    }
    if text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") && PGP_BODY.is_match(text) {
        return true;
    }
    if SHAPED.iter().any(|shape| {
        shape
            .captures_iter(text)
            .any(|found| !placeholder(&found["v"]))
    }) {
        return true;
    }
    let named = NAMED.iter().enumerate().any(|(index, shape)| {
        shape.captures_iter(text).any(|found| {
            let whole = found.get(0).expect("match");
            // A Basic credential runs to the end of its base64 text.
            let cut_short = index == 2 && text[whole.end()..].starts_with('=');
            !cut_short && !placeholder(&found["v"]) && looks_random(&found["v"])
        })
    });
    if named {
        return true;
    }
    if NESTED.captures_iter(text).any(|found| {
        NESTED_TOKEN
            .find_iter(&found[1])
            .any(|token| looks_random(token.as_str()))
    }) {
        return true;
    }
    if BASIC
        .captures_iter(text)
        .any(|found| basic_credentials(&found[1]))
    {
        return true;
    }
    if PREFIXED.find_iter(text).any(|found| {
        let boundary = text[..found.start()]
            .chars()
            .next_back()
            .is_none_or(|before| !(before.is_ascii_alphanumeric() || before == '_'));
        boundary && PREFIX_SHAPE.is_match(found.as_str()) && !found.as_str().contains("EXAMPLE")
    }) {
        return true;
    }
    if URL_CREDENTIAL
        .captures_iter(text)
        .any(|found| url_password(&found))
    {
        return true;
    }
    ASSIGN.captures_iter(text).any(|found| {
        let whole = found.get(0).expect("match");
        let value = found.name("v").or_else(|| found.name("b"));
        !text[whole.end()..].starts_with('(')
            && !NOT_A_SECRET_NAME.is_match(&found["k"])
            && value.is_some_and(|value| looks_random(value.as_str()))
    })
}

/// The rows a patch adds: a Codex `apply_patch` body in `command`, or an Oh
/// My Pi hashline edit in `input`. Removed (`-`) rows are left out, and a
/// hashline row Oh My Pi keeps without its `+` is read as added text.
fn added_rows(patch: &str) -> Option<String> {
    // Oh My Pi accepts the Codex `*** Begin Patch` opening line too, so the
    // format is told by the file headers: a Codex patch names its files with
    // `*** Add|Update|Delete File:` and has no hashline `[path#hash]` header.
    let codex_header = |row: &str| {
        ["*** Add File:", "*** Update File:", "*** Delete File:"]
            .iter()
            .any(|header| row.starts_with(header))
    };
    let hashline_header = |row: &str| {
        let row = row.trim_end();
        row.starts_with('[') && row.ends_with(']') && row.contains('#')
    };
    let hashline = !patch.lines().any(codex_header) || patch.lines().any(hashline_header);
    let rows: Vec<&str> = patch
        .lines()
        .filter_map(|row| match row.strip_prefix('+') {
            Some(added) => Some(added),
            None if hashline && !row.starts_with('-') => Some(row),
            None => None,
        })
        .collect();
    (!rows.is_empty()).then(|| rows.join("\n"))
}

/// The text a file tool writes: a Write body, an Edit replacement, each
/// replacement of a MultiEdit, or the rows a patch adds.
pub(super) fn written_bodies(input: &serde_json::Map<String, Value>) -> Vec<Cow<'_, str>> {
    let mut bodies: Vec<Cow<'_, str>> = BODY_KEYS
        .iter()
        .filter_map(|key| input.get(*key).and_then(Value::as_str))
        .map(Cow::Borrowed)
        .collect();
    if let Some(edits) = input.get("edits").and_then(Value::as_array) {
        bodies.extend(edits.iter().filter_map(|edit| {
            BODY_KEYS
                .iter()
                .find_map(|key| edit.get(*key).and_then(Value::as_str))
                .map(Cow::Borrowed)
        }));
    }
    let patch = input.get("input").and_then(Value::as_str).or_else(|| {
        input
            .get("command")
            .and_then(Value::as_str)
            .filter(|command| command.trim_start().starts_with("*** Begin Patch"))
    });
    bodies.extend(patch.and_then(added_rows).map(Cow::Owned));
    bodies
}

/// The text a file tool writes, joined per destination file: the call's own
/// body and every replacement aimed at the same file read as one text, since
/// a MultiEdit can split one passage across its replacements. A replacement
/// that names its own file is kept apart from files it does not name; one
/// that names the call's own file, or none, joins the call's own text.
pub(super) fn written_text_by_file(input: &serde_json::Map<String, Value>) -> Vec<String> {
    fn named(object: &serde_json::Map<String, Value>) -> Option<String> {
        ["file_path", "filePath", "path"]
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str))
            .map(lexical_file)
    }
    fn add(files: &mut Vec<(Option<String>, String)>, file: Option<String>, body: &str) {
        let at = match files.iter().position(|(name, _)| match (name, &file) {
            (Some(name), Some(file)) => same_file(name, file),
            (name, file) => name.is_none() && file.is_none(),
        }) {
            Some(at) => at,
            None => {
                files.push((file, String::new()));
                files.len() - 1
            }
        };
        let text = &mut files[at].1;
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(body);
    }
    let top = named(input);
    let mut files: Vec<(Option<String>, String)> = vec![(top.clone(), String::new())];
    for body in BODY_KEYS
        .iter()
        .filter_map(|key| input.get(*key).and_then(Value::as_str))
    {
        add(&mut files, top.clone(), body);
    }
    for edit in input
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(body) = BODY_KEYS
            .iter()
            .find_map(|key| edit.get(*key).and_then(Value::as_str))
        else {
            continue;
        };
        let file = edit.as_object().and_then(named).or_else(|| top.clone());
        add(&mut files, file, body);
    }
    files
        .into_iter()
        .map(|(_, text)| text)
        .filter(|text| !text.is_empty())
        .collect()
}

/// A file path spelled the way it resolves lexically, so `/w/./notes.md`
/// and `/w/notes.md` name one file: `.` segments and repeated separators
/// dropped, `..` applied, `\` read as `/`.
fn lexical_file(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if absolute => {}
            part => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Whether two lexical paths can name one file: equal, or one is relative
/// and the other ends with it (`notes.md` and `/w/notes.md`).
fn same_file(one: &str, other: &str) -> bool {
    one == other
        || [(one, other), (other, one)].iter().any(|(long, short)| {
            !short.starts_with('/')
                && !short.starts_with("..")
                && long
                    .strip_suffix(short)
                    .is_some_and(|head| head.ends_with('/'))
        })
}

/// Whether a file-tool write carries more text than the content screens
/// read, in one body or across the replacements made to one file, so a
/// credential or instruction past the limit would go unseen.
pub(super) fn writes_unscreened_body(input: &Map<String, Value>) -> bool {
    written_bodies(input)
        .iter()
        .any(|body| body.char_indices().nth(SCAN_LIMIT).is_some())
        || written_text_by_file(input)
            .iter()
            .any(|text| text.char_indices().nth(SCAN_LIMIT).is_some())
}

/// Whether a file-tool write puts a live-looking credential into a file.
pub(super) fn writes_literal_secret(input: &Map<String, Value>) -> bool {
    written_bodies(input)
        .iter()
        .any(|body| holds_literal_secret(body))
}

/// A command that spells out a live-looking key, token or password is
/// reviewed even when every program in it is safe: the value lands in the
/// transcript and shell history, and in whatever the command hands it to.
/// The review uses the ordinary command reason, so a user's explicit
/// extension Allow still settles it.
pub(super) fn review_command(
    request: &crate::CommandModelRequestV1,
    decision: super::PreToolDecisionV1,
) -> super::PreToolDecisionV1 {
    if decision.minimum_action != "allow" || !holds_literal_secret(&request.command) {
        return decision;
    }
    super::pretool_decision(
        decision.command_model,
        "review",
        "native_command_review_required",
        "This command spells out what looks like a real key, token or password. Once it runs, the value is in the transcript, the shell history and whatever the command sends it to.",
    )
}

#[cfg(test)]
#[path = "literal_secrets_tests.rs"]
mod tests;
