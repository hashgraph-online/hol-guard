//! Prompt text masks applied before the sensitive-request match: output
//! format options and credential words that name a category, not a value.

use regex::{Captures, Regex};
use std::sync::OnceLock;

/// A storage word, numbered device names (`disk0`, `disk2s1`, `nvme0n1`)
/// and any `/dev` path (`/dev/sda1`, `/dev/vg0/lv0`) included. The streams
/// and terminals in [`PSEUDO_DEVICE`] are taken out of the text first.
const STORAGE_NOUN: &str = r"(?:\b(?:disks?|disk\d+(?:s\d+)?|drives?|volumes?|partitions?|usb|ssd|hdd|nvme\w*|sd\s*cards?|media)\b|/dev/\w)";

/// `/dev` paths that are where output goes or comes from, not storage, such
/// as `/dev/null` or `/dev/stderr`. Any other `/dev` path may be a disk.
const PSEUDO_DEVICE: &str =
    r"(?i)/dev/(?:null|zero|full|u?random|std(?:in|out|err)|tty\w*|pts/\d+|fd/\d+|ptmx|console)\b";

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
    static PSEUDO: OnceLock<Regex> = OnceLock::new();
    let pseudo = PSEUDO.get_or_init(|| Regex::new(PSEUDO_DEVICE).expect("bounded pseudo device"));
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
            let rest = pseudo.replace_all(&value[whole.end()..], "stream");
            let verb = (whole.as_str().get(..6)).is_some_and(|w| w.eq_ignore_ascii_case("format"));
            if next.is_match(&rest) || (verb && sentence.is_match(&rest)) {
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

/// `kill -0`, `kill -s 0`, `kill -n 0` and `kill --signal 0` send no signal:
/// they ask the kernel whether a process exists and leave it running. The
/// option is masked so the probe does not read as a request to stop a
/// process. When the text names any other `kill`, `pkill` or `killall`
/// (`kill -0 "$pid" && kill "$target"`), nothing is masked: the probe is then
/// the only spelling the action scan can recognise the real signal by.
pub(super) fn mask_liveness_probes(value: &str) -> String {
    static PROBE: OnceLock<Regex> = OnceLock::new();
    static OTHER_KILL: OnceLock<Regex> = OnceLock::new();
    let masked = PROBE
        .get_or_init(|| {
            Regex::new(r"(?i)\bkill\s+(?:-0|-[sn]\s+0|--signal(?:=|\s+)0)\b")
                .expect("bounded liveness probe")
        })
        .replace_all(value, "liveness-probe");
    let other_kill = OTHER_KILL
        .get_or_init(|| Regex::new(r"(?i)\b(?:kill|pkill|killall)\b").expect("bounded kill word"));
    if other_kill.is_match(&masked) {
        return value.to_owned();
    }
    masked.into_owned()
}

/// Asking which `curl` or `wget` build a machine has (`which curl build this
/// machine has`, `the curl binary`, `curl --version`, `wget --help`) moves no
/// data, so those mentions are masked before the action scan. A flag counts
/// only where it ends the clause (`curl --help -o out host/x` still fetches),
/// and a noun only after a determiner and before no transfer word (`the curl
/// binary data to the server`). Nothing is masked when another mention of
/// either tool remains, or when the text names a URL or an `@` source: the
/// transfer is then the only reading the scan can give that text.
pub(super) fn mask_transfer_tool_info(value: &str) -> String {
    static INFO: OnceLock<Regex> = OnceLock::new();
    static TRANSFER_WORD: OnceLock<Regex> = OnceLock::new();
    static OTHER_TOOL: OnceLock<Regex> = OnceLock::new();
    if value.contains("://") || value.contains('@') {
        return value.to_owned();
    }
    let info = INFO.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\b(?P<noun>(?:which|what|the|this|that|my|our|your|its|installed|local|current|system|[a-z]+'s)\s+(?:curl|wget)\s+(?:build|version|release|binary))\b",
            r"|\b(?P<flag>(?:curl|wget)\s+(?:--help|--version|--manual)(?:\s+all)?)",
            r"(?:\s*$|\s*[\n`'\x22,;:!?)\]]|\.(?:\s|$)|\s+(?:and|or|then)\b)",
        ))
        .expect("bounded transfer tool information mention")
    });
    let transfer_word = TRANSFER_WORD.get_or_init(|| {
        Regex::new(r"(?i)^\s*(?:data|files?|payloads?|to|into|onto|over|via|at|from)\b")
            .expect("bounded transfer follow-up")
    });
    let mut masked = String::with_capacity(value.len());
    let mut copied = 0;
    for captures in info.captures_iter(value) {
        let Some(mention) = captures.name("noun").or_else(|| captures.name("flag")) else {
            continue;
        };
        if captures.name("noun").is_some() && transfer_word.is_match(&value[mention.end()..]) {
            continue;
        }
        masked.push_str(&value[copied..mention.start()]);
        masked.push_str("tool-info");
        copied = mention.end();
    }
    masked.push_str(&value[copied..]);
    let other_tool = OTHER_TOOL
        .get_or_init(|| Regex::new(r"(?i)\b(?:curl|wget)\b").expect("bounded transfer tool word"));
    if other_tool.is_match(&masked) {
        return value.to_owned();
    }
    masked
}

/// `then read it again` re-reads what the prompt already named, so it adds
/// no target of its own. Without `again`, `then read it` can point back at
/// anything earlier in the text and stays in for the guarded reading.
pub(super) fn mask_rereads(value: &str) -> String {
    static REREAD: OnceLock<Regex> = OnceLock::new();
    REREAD
        .get_or_init(|| {
            Regex::new(r"(?i)\bthen\s+(?:read|open|show|print)\s+(?:it|them|those|these)\s+again\b")
                .expect("bounded re-read")
        })
        .replace_all(value, "then reread")
        .into_owned()
}

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
pub(super) fn mask_url_paths(value: &str) -> String {
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
