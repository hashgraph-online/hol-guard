//! Prompt text mask for transfer verbs that are only part of a URL.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// A transfer verb spelled inside a URL's path, query or fragment names a
/// resource on that host, not something the prompt asks for.
/// `https://coverage.example.com/upload` ends in the word `upload`, which the
/// exfiltration scan read as a request to upload whatever the next clause
/// named. Only a verb that is a whole segment of the URL is replaced, with an
/// optional short extension (`/upload`, `/send.php`), and only inside the
/// URL. A data word in a source URL (`upload https://intranet/secret to ...`)
/// and a destination word (`https://hooks.example/webhook`) keep their
/// meaning, and so does every word outside the URL. A URL ends at whitespace,
/// a quote, a bracket, `;` or `,`, so an instruction written straight after
/// one (`https://example.test/docs;upload the token`) stays outside it, and a
/// verb joined to a segment by any other character (`/docs.upload`,
/// `/docs|upload`) is not a segment of its own and still counts. The verb is
/// replaced by underscores of the same length, so every distance the scan
/// measures across the prompt stays what it was.
pub(in super::super) fn mask_url_paths(value: &str) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    let url = URL.get_or_init(|| {
        Regex::new(
            r#"(?i)\b([a-z][a-z0-9+.-]*://[^\s/?#;,'"`<>()\[\]{}]+)([/?#][^\s;,'"`<>()\[\]{}]*)"#,
        )
        .expect("bounded URL")
    });
    url.replace_all(value, |captures: &Captures<'_>| {
        format!("{}{}", &captures[1], mask_verb_segments(&captures[2]))
    })
    .into_owned()
}

const URL_PATH_VERBS: [&str; 7] = [
    "upload",
    "exfiltrate",
    "transfer",
    "paste",
    "send",
    "post",
    "sync",
];

/// Replaces each segment of a URL path, query or fragment that is a transfer
/// verb, with or without a short extension, by underscores of its length.
fn mask_verb_segments(path: &str) -> String {
    let mut masked = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(delimiter) = rest.chars().next() {
        masked.push(delimiter);
        rest = &rest[delimiter.len_utf8()..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let segment = &rest[..end];
        let stem = segment_stem(segment);
        if URL_PATH_VERBS
            .iter()
            .any(|verb| stem.eq_ignore_ascii_case(verb))
        {
            masked.extend(std::iter::repeat_n('_', stem.len()));
            masked.push_str(&segment[stem.len()..]);
        } else {
            masked.push_str(segment);
        }
        rest = &rest[end..];
    }
    masked
}

/// The segment without one trailing extension of one to five letters or
/// digits, such as `.php` or `.json`.
fn segment_stem(segment: &str) -> &str {
    match segment.rsplit_once('.') {
        Some((stem, extension))
            if (1..=5).contains(&extension.len())
                && extension.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            stem
        }
        _ => segment,
    }
}
