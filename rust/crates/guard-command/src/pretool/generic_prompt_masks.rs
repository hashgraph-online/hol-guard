//! Prompt text masks applied before the sensitive-request match: output
//! format options and credential words that name a category, not a value.

use regex::{Captures, Regex};
use std::sync::OnceLock;

#[path = "generic_prompt_url_masks.rs"]
mod url_masks;
pub(super) use url_masks::mask_url_paths;

/// A storage word, numbered device names (`disk0`, `disk2s1`, `nvme0n1`),
/// filesystems and mount points, and any `/dev`, `/mnt`, `/media` or
/// `/Volumes` path (`/dev/sda1`, `/mnt/archive`) included. The streams
/// and terminals in [`PSEUDO_DEVICE`] are taken out of the text first.
const STORAGE_NOUN: &str = r"(?:\b(?:disks?|disk\d+(?:s\d+)?|drives?|volumes?|partitions?|usb|ssd|hdd|nvme\w*|sd\s*cards?|media|file\s*systems?|mount\s*points?|mounted)\b|/(?:dev|mnt|media|volumes)/\w)";

/// `/dev` paths that are where output goes or comes from, not storage, such
/// as `/dev/null` or `/dev/stderr`. Any other `/dev` path may be a disk.
const PSEUDO_DEVICE: &str =
    r"(?i)/dev/(?:null|zero|full|u?random|std(?:in|out|err)|tty\w*|pts/\d+|fd/\d+|ptmx|console)\b";

/// `--format`, `-format`, the `format:` value of `--pretty=format:` and
/// `format` applied to what a program prints or to a piece of code (`format
/// the value`, `format methods`) all choose how output is shaped. Any other
/// `format` is then read by [`mask_layout_nouns`].
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
/// lists, so only a storage word right after it does. So does a code
/// formatter named before `format`, as in `ruff format --check .` or a
/// `ruff-format` step: it rewrites source files, not storage, unless a
/// storage word or a drive letter (`ruff format C:`) follows in the same
/// sentence.
pub(super) fn mask_format_options(value: &str) -> String {
    static OPTION: OnceLock<Regex> = OnceLock::new();
    static NEXT: OnceLock<Regex> = OnceLock::new();
    static SENTENCE: OnceLock<Regex> = OnceLock::new();
    static PSEUDO: OnceLock<Regex> = OnceLock::new();
    static TOOL_SENTENCE: OnceLock<Regex> = OnceLock::new();
    let pseudo = PSEUDO.get_or_init(|| Regex::new(PSEUDO_DEVICE).expect("bounded pseudo device"));
    let tool_sentence = TOOL_SENTENCE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)^(?:[^.;!?\n]|\.\S)*?(?:\.?{STORAGE_NOUN}|(?:^|[^a-z0-9])[a-z]:(?:[\\/]|\s|$))"
        ))
        .expect("bounded formatter storage sentence")
    });
    let next = NEXT.get_or_init(|| {
        Regex::new(&format!(r"(?i)^\s*(?:machine\s+)?{STORAGE_NOUN}"))
            .expect("bounded storage noun")
    });
    let sentence = SENTENCE.get_or_init(|| {
        Regex::new(&format!(r"(?i)^(?:[^.;!?\n]|\.\S)*?\.?{STORAGE_NOUN}"))
            .expect("bounded storage sentence")
    });
    let masked = OPTION
        .get_or_init(|| {
            Regex::new(r"(?i)(^|[^a-z0-9-])--?format\b|=format:|\b(?P<tool>ruff|cargo|dart|deno|dotnet|terraform|tofu|biome|taplo|stylua|prettier|swift|zig|clang|(?:npm|pnpm|yarn|bun)(?:[ \t]+run)?)[ \t-]+format\b|\bformat(?:s|ted|ting)?\s+(?:the\s+|this\s+|that\s+|its\s+|your\s+)?(?:output|response|reply|message|json|yaml|xml|html|markdown|code|text|table|date|time|number|string|currency|logs?|diff|results?|summary|report|values?|methods?|functions?|helpers?|calls?|spec(?:ifier)?s?|strings|fields?|names?|sizes?|templates?|placeholders?|widths?|headers?|errors?|exceptions?|tracebacks?|lines?|columns?|rows?|entries|entry|records?|items?|labels?)\b")
                .expect("bounded format option")
        })
        .replace_all(value, |captures: &Captures| {
            let whole = captures.get(0).expect("whole match present");
            let rest = pseudo.replace_all(&value[whole.end()..], "stream");
            let tool = captures.name("tool").is_some();
            let verb = (whole.as_str().get(..6)).is_some_and(|w| w.eq_ignore_ascii_case("format"));
            if next.is_match(&rest)
                || (verb && sentence.is_match(&rest))
                || (tool && tool_sentence.is_match(&rest))
            {
                return whole.as_str().to_owned();
            }
            format!(
                "{}output-layout",
                captures.get(1).map_or("", |prefix| prefix.as_str())
            )
        });
    mask_layout_nouns(&masked)
}

/// `format` names a layout far more often than a disk operation: a `## Response
/// format` heading, `the date format`, `the JSON format described below`. A
/// `format` is masked only when it reads as a noun: a word such as `the`,
/// `JSON` or `response` comes right before it, its line is a Markdown heading,
/// or a word such as `of`, `is` or `described` comes right after it. A
/// sentence that names storage (a disk word, a filesystem or mount point, a
/// `/dev` path that is not a stream, a `/mnt` path, a drive letter such as
/// `C:`) keeps every `format`, and so does `the format command`. A `format`
/// after `run the`, `a` or `quick`, or up to three words after `run` or a
/// like verb with no `in` or `as` between, names the operation and is never
/// masked. Every other `format` stays a request. A sentence ends
/// at `!`, `?`, `;`, a line break, or a dot before a space or the end of the
/// text, and each sentence is scanned for storage once.
fn mask_layout_nouns(value: &str) -> String {
    static WORD: OnceLock<Regex> = OnceLock::new();
    static STORAGE: OnceLock<Regex> = OnceLock::new();
    static LEAD: OnceLock<Regex> = OnceLock::new();
    static TAIL: OnceLock<Regex> = OnceLock::new();
    static ACT: OnceLock<Regex> = OnceLock::new();
    static PSEUDO: OnceLock<Regex> = OnceLock::new();
    let word = WORD.get_or_init(|| Regex::new(r"(?i)\bformat\b").expect("bounded format word"));
    let storage = STORAGE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i){STORAGE_NOUN}|(?:^|[^a-z0-9])[a-z]:(?:[\\/]|\s|$)"
        ))
        .expect("bounded storage target")
    });
    let lead = LEAD.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^a-z0-9-])(?:the|this|that|these|those|which|what|its|their|our|your|my|same|new|default|preferred|expected|required|desired|output|input|response|reply|answer|report|date|time|datetime|timestamp|number|currency|file|data|json|yaml|toml|csv|xml|html|markdown|text|string|message|log|commit|citation|export|table|wire|image|video|audio|serialization|display)[\s*_`]*$")
            .expect("bounded format lead")
    });
    let tail = TAIL.get_or_init(|| {
        Regex::new(r"(?i)^[\s*_`]*(?:(of|is|are|was|were|described|below|above)|(command|tool|utility|operation))(?:[^a-z0-9]|$)")
            .expect("bounded format tail")
    });
    let act = ACT.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^a-z0-9-])(?:a|an|quick|full|low-level|secure|clean|fresh|run|do|perform|start|execute|trigger|launch|begin|redo|finish|complete|schedule)(?:\s+(?:the|a|an|this|that|quick|full|low-level|secure|clean|fresh))*[\s*_`]*$")
            .expect("bounded format action lead")
    });
    let pseudo = PSEUDO.get_or_init(|| Regex::new(PSEUDO_DEVICE).expect("bounded pseudo device"));
    let bytes = value.as_bytes();
    let ends = |index: usize| {
        matches!(bytes[index], b'!' | b'?' | b';' | b'\n')
            || (bytes[index] == b'.' && bytes.get(index + 1).is_none_or(u8::is_ascii_whitespace))
    };
    let mut output = String::with_capacity(value.len());
    let mut start = 0;
    while start < value.len() {
        let end = (start..value.len())
            .find(|&index| ends(index))
            .map_or(value.len(), |index| index + 1);
        let sentence = &value[start..end];
        if !word.is_match(sentence) || storage.is_match(&pseudo.replace_all(sentence, "stream")) {
            output.push_str(sentence);
            start = end;
            continue;
        }
        let heading = sentence.trim_start().starts_with('#');
        let masked = word.replace_all(sentence, |captures: &Captures| {
            let whole = captures.get(0).expect("whole match present");
            let before = &sentence[..whole.start()];
            let window = before.len().saturating_sub(48);
            let window = (window..=before.len())
                .find(|&index| before.is_char_boundary(index))
                .unwrap_or(before.len());
            let after = &sentence[whole.end()..];
            let after = &after[..(0..=after.len().min(24))
                .rev()
                .find(|&index| after.is_char_boundary(index))
                .unwrap_or(0)];
            let follows = tail.captures(after);
            let tool = follows.as_ref().is_some_and(|found| found.get(2).is_some());
            let lead_text = &before[window..];
            let noun = !act.is_match(lead_text)
                && !verb_leads(lead_text)
                && (heading
                    || lead.is_match(lead_text)
                    || follows.is_some_and(|found| found.get(1).is_some()));
            if noun && !tool {
                "layout".to_owned()
            } else {
                whole.as_str().to_owned()
            }
        });
        output.push_str(&masked);
        start = end;
    }
    output
}

/// A strong action verb up to three words before `format` names the
/// operation, as in `run the same format on it` or `perform for me the
/// format`. It does not when a relation word introduces the phrase that ends
/// in `format`, as in `run tests in JSON format` or `in a consistent format`:
/// no pronoun follows the relation word, and a determiner may only come right
/// after it. Relation words and pronouns do not count toward the three words.
fn verb_leads(lead_text: &str) -> bool {
    const VERBS: [&str; 13] = [
        "run", "do", "perform", "execute", "trigger", "launch", "redo", "schedule", "start",
        "begin", "finish", "complete", "initiate",
    ];
    const RELATIONS: [&str; 14] = [
        "in", "as", "with", "using", "into", "to", "for", "from", "via", "per", "by", "at", "on",
        "of",
    ];
    const PRONOUNS: [&str; 7] = ["me", "us", "you", "them", "him", "her", "it"];
    const DETERMINERS: [&str; 12] = [
        "the", "a", "an", "this", "that", "these", "those", "its", "their", "our", "your", "my",
    ];
    let words = lead_text
        .split_whitespace()
        .map(|word| word.trim_matches(|c| matches!(c, '*' | '_' | '`' | ',' | ';' | ':')))
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let has = |list: &[&str], word: &String| list.contains(&word.as_str());
    let introduces = |after: &[String]| {
        after
            .iter()
            .enumerate()
            .all(|(index, word)| !has(&PRONOUNS, word) && (index == 0 || !has(&DETERMINERS, word)))
    };
    let operates = |between: &[String]| {
        between
            .iter()
            .all(|word| word.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
            && !(0..between.len())
                .any(|index| has(&RELATIONS, &between[index]) && introduces(&between[index + 1..]))
            && between
                .iter()
                .filter(|word| !has(&RELATIONS, word) && !has(&PRONOUNS, word))
                .count()
                <= 3
    };
    (0..=7).any(|gap| {
        let Some(at) = words.len().checked_sub(gap + 1) else {
            return false;
        };
        let verb = words[at].trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
        VERBS.contains(&verb) && operates(&words[at + 1..])
    })
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
/// the only spelling the action scan can recognise the real signal by. Both
/// signal options must sit in one command line for the text to be left as is.
pub(super) fn mask_liveness_probes(value: &str) -> String {
    static PROBE: OnceLock<Regex> = OnceLock::new();
    static OTHER_KILL: OnceLock<Regex> = OnceLock::new();
    static MULTI_SIGNAL: OnceLock<Regex> = OnceLock::new();
    let multi_signal = MULTI_SIGNAL.get_or_init(|| {
        Regex::new(r"(?i)\bkill\b[^;&|\r\n]*(?:-[sn][ \t]+|--signal(?:=|[ \t]+))\S+[^;&|\r\n]*(?:-[sn][ \t]+|--signal(?:=|[ \t]+))\S+")
            .expect("bounded multiple signal options")
    });
    if multi_signal.is_match(value) {
        return value.to_owned();
    }
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
    static TRANSFER_CONTEXT: OnceLock<Regex> = OnceLock::new();
    static INFO_QUESTION: OnceLock<Regex> = OnceLock::new();
    // Never erase the only transfer-tool mention when another clause asks for
    // a network action. A scheme-less host is a valid curl/wget operand too.
    let transfer_context = TRANSFER_CONTEXT.get_or_init(|| {
        Regex::new(r"(?i)\b(?:fetch|download|upload|send|post|transfer|grab|pull|retrieve|request|stage)(?:s|ed|ing)?\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/[^\s]*|(?:^|\s)-(?:o|d|F)(?:\s|$)|(?:^|\s)--(?:output|data|form|upload-file)\b")
            .expect("bounded transfer-action context")
    });
    // Do not treat an explicit prohibition such as "Do not request approval"
    // as a network request. An affirmative request in the next clause remains.
    let affirmative = super::mask_negated_clauses(value);
    if value.contains("://")
        || value.contains('@')
        || transfer_context.is_match(&affirmative)
        || transfer_outlives_negation(value, transfer_context)
    {
        return value.to_owned();
    }
    // A noun is merely descriptive only in an explicit information question.
    // "Use the local curl build with -F ..." must keep its curl word.
    let info_question = INFO_QUESTION.get_or_init(|| {
        Regex::new(r"(?i)\b(?:which|what|how|whether)\b")
            .expect("bounded tool-information question")
    });
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
        if captures.name("noun").is_some() {
            let clause_start = value[..mention.start()]
                .rfind(['.', '?', '!', ';', '\n'])
                .map_or(0, |offset| offset + 1);
            if !info_question.is_match(&value[clause_start..mention.end()])
                || transfer_word.is_match(&value[mention.end()..])
            {
                continue;
            }
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

/// Whether a transfer the negation mask hid is one the prohibition does not
/// cover. A negation names the verbs it forbids: the one right after it, an
/// item after `or` or `nor`, and an item after a comma in a list that an `or`
/// or `nor` closes ("do not change the command, request approval, or change
/// policy"). Any other transfer verb in that clause is not forbidden: it is
/// the object of a verb the prohibition does not name ("do not delay
/// downloading"), or a separate instruction ("do not pause, fetch ...",
/// "do not wait and download ..."). A host or output option counts as
/// forbidden only as the operand of a forbidden verb before it.
fn transfer_outlives_negation(value: &str, transfer_context: &Regex) -> bool {
    static VERB: OnceLock<Regex> = OnceLock::new();
    static LIST_HEAD: OnceLock<Regex> = OnceLock::new();
    static LIST_CLOSE: OnceLock<Regex> = OnceLock::new();
    static CLAUSE_END: OnceLock<Regex> = OnceLock::new();
    static FOLLOWUP_ACTION: OnceLock<Regex> = OnceLock::new();
    let verb = VERB.get_or_init(|| {
        Regex::new(r"(?i)\b(?:fetch|download|upload|send|post|transfer|grab|pull|retrieve|request|stage)(?:s|ed|ing)?\b")
            .expect("bounded transfer verb")
    });
    let list_head = LIST_HEAD.get_or_init(|| {
        Regex::new(r"(?i)(?:\b(?:not|never|don't|dont|cannot|can't|won't|or|nor)|(?P<comma>,))\s*$")
            .expect("bounded negated list head")
    });
    let list_close = LIST_CLOSE
        .get_or_init(|| Regex::new(r"(?i),\s*(?:or|nor)\b").expect("bounded comma-led list close"));
    let clause_end =
        CLAUSE_END.get_or_init(|| Regex::new(r"[.!?;](?:\s|$)|\n").expect("bounded clause end"));
    transfer_context.find_iter(value).any(|found| {
        let start = clause_end
            .find_iter(&value[..found.start()])
            .last()
            .map_or(0, |end| end.end());
        let before = &value[start..found.start()];
        if !verb.is_match(found.as_str()) {
            // A following imperative starts a separate instruction. An option
            // after `, use -o` is not an operand of `do not request approval`.
            let followup = FOLLOWUP_ACTION.get_or_init(|| {
                Regex::new(r"(?i)(?:,\s*|\b(?:and|then|also|but)\s+)(?:(?:and|then|also|but|just|instead|rather|simply)\s+)*(?:use|run|execute|invoke|call|apply|set|write|save|copy|fetch|download|upload|send|post|transfer|stage|request)\b")
                    .expect("bounded transfer follow-up instruction")
            });
            return !verb.is_match(before) || followup.is_match(before);
        }
        let Some(head) = list_head.captures(before) else {
            return true;
        };
        if head.name("comma").is_none() {
            return false;
        }
        let tail = &value[found.end()..];
        let end = clause_end.find(tail).map_or(tail.len(), |end| end.start());
        !list_close.is_match(&tail[..end])
    })
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
