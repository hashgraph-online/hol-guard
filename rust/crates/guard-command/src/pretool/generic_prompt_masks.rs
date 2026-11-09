//! Prompt text masks applied before the sensitive-request match: output
//! format options and credential words that name a category, not a value.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// A storage word, numbered device names (`disk0`, `disk2s1`, `nvme0n1`)
/// and device paths (`/dev/sda1`, `/dev/mmcblk0p1`) included.
const STORAGE_NOUN: &str = r"(?:\b(?:disks?|disk\d+(?:s\d+)?|drives?|volumes?|partitions?|usb|ssd|hdd|nvme\w*|sd\s*cards?|media)\b|/dev/\w)";

/// `--format`, `-format`, the `format:` value of `--pretty=format:` and
/// `format` applied to what a program prints or to a piece of code (`format
/// the value`, `format methods`) all choose how output is shaped; the bare
/// word, or an assignment such as `operation=format`, still asks to format a
/// disk.
///
/// Two of the printed nouns also name storage once another word follows them:
/// `format the time machine disk`, `format the logs volume`. The mask reads
/// what comes after its own match and leaves such a phrase alone, so the verb
/// stays in the text for the guarded reading below. After `format` and a
/// noun, the storage word may come after a list or other words (`format the
/// values and logs volumes`, `format the logs and my backup disk`, `format the
/// values and D: drive`), so any storage word later in the same sentence keeps
/// the verb, however long the sentence. A dot ends the sentence only before a
/// space or the end of the text, not inside `2.5-inch` or `backup.img`, and
/// a storage word right after such a dot (`backup.disk0`) still counts. An
/// option such as `--format json` names how a command prints, whatever it
/// lists, so only a storage word right after it does.
pub(super) fn mask_format_options(value: &str) -> String {
    static OPTION: OnceLock<Regex> = OnceLock::new();
    static NEXT: OnceLock<Regex> = OnceLock::new();
    static SENTENCE: OnceLock<Regex> = OnceLock::new();
    let next = NEXT.get_or_init(|| {
        Regex::new(&format!(r"(?i)^\s*(?:machine\s+)?{STORAGE_NOUN}"))
            .expect("bounded storage noun")
    });
    let sentence = SENTENCE.get_or_init(|| {
        Regex::new(&format!(r"(?i)^(?:[^.;!?\n]|\.\S)*?\.?{STORAGE_NOUN}"))
            .expect("bounded storage sentence")
    });
    OPTION
        .get_or_init(|| {
            Regex::new(r"(?i)(^|[^a-z0-9-])--?format\b|=format:|\bformat(?:s|ted|ting)?\s+(?:the\s+|this\s+|that\s+|its\s+|your\s+)?(?:output|response|reply|message|json|yaml|xml|html|markdown|code|text|table|date|time|number|string|currency|logs?|diff|results?|summary|report|values?|methods?|functions?|helpers?|calls?|spec(?:ifier)?s?|strings|fields?|names?|sizes?|templates?|placeholders?|widths?|headers?|errors?|exceptions?|tracebacks?|lines?|columns?|rows?|entries|entry|records?|items?|labels?)\b")
                .expect("bounded format option")
        })
        .replace_all(value, |captures: &Captures| {
            let whole = captures.get(0).expect("whole match present");
            let rest = &value[whole.end()..];
            let verb = (whole.as_str().get(..6)).is_some_and(|w| w.eq_ignore_ascii_case("format"));
            if next.is_match(rest) || (verb && sentence.is_match(rest)) {
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
