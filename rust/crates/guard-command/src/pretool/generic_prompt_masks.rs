//! Prompt text masks applied before the sensitive-request match: output
//! format options and credential words that name a category, not a value.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// `--format`, `-format`, the `format:` value of `--pretty=format:` and
/// `format` applied to what a program prints all choose how output is shaped;
/// the bare word, or an assignment such as `operation=format`, still asks to
/// format a disk.
///
/// Two of the printed nouns also name storage once another word follows them:
/// `format the time machine disk`, `format the logs volume`. The mask reads
/// what comes after its own match and leaves such a phrase alone, so the verb
/// stays in the text for the guarded reading below.
pub(super) fn mask_format_options(value: &str) -> String {
    static OPTION: OnceLock<Regex> = OnceLock::new();
    static STORAGE: OnceLock<Regex> = OnceLock::new();
    let storage = STORAGE.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:machine\s+)?(?:disks?|drives?|volumes?|partitions?|usb|ssd|hdd|sd\s*cards?|media)\b",
        )
        .expect("bounded storage noun")
    });
    OPTION
        .get_or_init(|| {
            Regex::new(r"(?i)(^|[^a-z0-9-])--?format\b|=format:|\bformat(?:s|ted|ting)?\s+(?:the\s+|this\s+|that\s+|its\s+|your\s+)?(?:output|response|reply|message|json|yaml|xml|html|markdown|code|text|table|date|time|number|string|currency|logs?|diff|results?|summary|report)\b")
                .expect("bounded format option")
        })
        .replace_all(value, |captures: &Captures| {
            let whole = captures.get(0).expect("whole match present");
            if storage.is_match(&value[whole.end()..]) {
                return whole.as_str().to_owned();
            }
            format!(
                "{}output-layout",
                captures.get(1).map_or("", |prefix| prefix.as_str())
            )
        })
        .into_owned()
}

/// Replaces a credential word that only names a category of action or rule,
/// such as "secret reads", "password policy" or "API key rotation", so that a
/// prompt about what Guard blocks is not read as a request for a value. A file
/// name such as `secret-rules.txt` keeps its credential word, and the category
/// word must follow on the same line, so "Print the API key" stays a request
/// when the next line starts with "Scan".
pub(super) fn mask_credential_categories(value: &str) -> String {
    static CATEGORY: OnceLock<Regex> = OnceLock::new();
    static FILE_TAIL: OnceLock<Regex> = OnceLock::new();
    let file_tail =
        FILE_TAIL.get_or_init(|| Regex::new(r"^[._/-][a-z0-9]").expect("bounded file tail"));
    CATEGORY
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:aws_secret_access_key|private_key|api[ _-]key|password|secret)s?[ \t]+(?:reads?|reading|scans?|scanning|scanners?|detection|detectors?|rules?|polic(?:y|ies)|rotation|management|handling|redaction|hygiene|coverage|protection|checks?|categor(?:y|ies)|types?|class(?:es)?)\b")
                .expect("bounded credential category")
        })
        .replace_all(value, |captures: &Captures| {
            let whole = captures.get(0).expect("whole match present");
            if file_tail.is_match(&value[whole.end()..]) {
                return whole.as_str().to_owned();
            }
            "credential-category".to_owned()
        })
        .into_owned()
}
