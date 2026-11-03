//! Whether a leaf inside the repository's own hidden tree names a secret
//! store. Most of that answer is the name, which `guard-secure-fs` already
//! holds; the part that cannot be settled by the name is here.

use std::path::Path;

/// The stems a secret store and an ordinary project document share. A
/// checkout keeps its tooling settings under exactly these names --
/// `.circleci/config.yml`, `.changeset/config.json`, `.cargo/config.toml` --
/// so refusing the name on its own held back the most ordinary documents a
/// repository has, while `cat` of the same file ran contained. The name is
/// therefore read together with the file: a configuration document carrying
/// no credential is the checkout's own content, and one carrying a registry
/// token keeps its review.
const SHARED_CONFIGURATION_STEMS: [&str; 3] = ["config", "configuration", "settings"];

/// The largest configuration document this rule reads. A file past it is no
/// hand-written configuration, and scanning it would put an unbounded read in
/// front of the decision.
const CONFIGURATION_READ_LIMIT: u64 = 256 * 1024;

/// Whether `leaf` names a file a secret is normally written to. A stem that
/// only describes the file's job is read against the document itself; a key
/// suffix or an `id_` prefix names the material whatever the stem says, and
/// those names carry no document extension, so they never reach this rule in
/// the first place.
pub(super) fn leaf_names_a_secret_store(canonical: &Path, leaf: &str) -> bool {
    let bare = leaf.trim_start_matches('.');
    if !guard_secure_fs::credential_store_names::secret_bearing_file_name(bare) {
        return false;
    }
    let stem = bare.split('.').next().unwrap_or(bare);
    !(SHARED_CONFIGURATION_STEMS.contains(&stem)
        && configuration_document_is_clean(canonical, bare))
}

/// Whether `canonical` is a bounded text document the secret detector finds
/// nothing in. A file this cannot read, cannot decode or finds a credential in
/// keeps its review, so every answer short of a clean read is the guarded one.
fn configuration_document_is_clean(canonical: &Path, name: &str) -> bool {
    if !std::fs::symlink_metadata(canonical)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= CONFIGURATION_READ_LIMIT)
    {
        return false;
    }
    let Some(text) = bounded_document_text(canonical) else {
        return false;
    };
    if names_a_credential_value(&text) {
        return false;
    }
    // The real name can make the detector stricter as well as more lenient,
    // so both readings have to come back clean.
    ["", name].iter().all(|label| {
        guard_scanner::secret_detection::scan_secret_text(&text, label, "hidden-document", None, 1)
            .findings
            .is_empty()
    })
}

/// The document's text, read under the limit whatever the file does after its
/// size was taken. A file that grew past the limit in between is no longer the
/// bounded document this rule reads, so it keeps its review.
fn bounded_document_text(canonical: &Path) -> Option<String> {
    use std::io::Read;

    let file = std::fs::File::open(canonical).ok()?;
    let mut text = String::new();
    let read = file
        .take(CONFIGURATION_READ_LIMIT + 1)
        .read_to_string(&mut text)
        .ok()?;
    (read as u64 <= CONFIGURATION_READ_LIMIT).then_some(text)
}

/// The words a credential is written under, spelled without separators.
const CREDENTIAL_WORDS: [&str; 8] = [
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "credential",
    "privatekey",
    "passphrase",
];

/// The openers a placeholder is written with, each beside the delimiter that
/// closes it.
const PLACEHOLDER_DELIMITERS: [(&str, &str); 3] = [("${{", "}}"), ("{{", "}}"), ("${", "}")];

/// The byte width of the placeholder that opens here, if one does. A CI
/// expression and a template hole carry braces of their own, so they are
/// recognised before a line is split on its braces.
///
/// `absent` carries the closing delimiters already looked for and not found.
/// A line is read from its start, so a delimiter missing from one position is
/// missing from every later one, and the search is not repeated: without that
/// record, a line of openers that never close is searched to its end once per
/// opener, and a long line holds the read up for seconds.
fn placeholder_width(
    rest: &str,
    absent: &mut [bool; PLACEHOLDER_DELIMITERS.len()],
) -> Option<usize> {
    for (index, (open, close)) in PLACEHOLDER_DELIMITERS.iter().enumerate() {
        let Some(body) = rest.strip_prefix(open) else {
            continue;
        };
        if absent[index] {
            continue;
        }
        match body.find(close) {
            Some(end) => return Some(open.len() + end + close.len()),
            None => absent[index] = true,
        }
    }
    let name = rest.strip_prefix('$')?;
    let width = name
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(char::len_utf8)
        .sum::<usize>();
    (width > 0).then_some(1 + width)
}

/// The stand-in a placeholder leaves behind. It is a character no
/// configuration document writes, so a literal written right after a
/// placeholder cannot join it into one longer word: `${{ secrets.A }}abc123`
/// masks to the sentinel followed by `abc123`, and the value is then not the
/// hole alone.
const PLACEHOLDER_MASK: &str = "\u{0}";

/// One line with every placeholder replaced by the sentinel, so that
/// splitting the line on its braces cannot tear a CI expression into pieces
/// that read as a literal.
fn mask_placeholders(line: &str) -> String {
    let mut masked = String::with_capacity(line.len());
    let mut absent = [false; PLACEHOLDER_DELIMITERS.len()];
    let mut index = 0;
    while index < line.len() {
        let rest = &line[index..];
        if let Some(width) = placeholder_width(rest, &mut absent) {
            masked.push_str(PLACEHOLDER_MASK);
            index += width;
            continue;
        }
        let character = rest.chars().next().expect("a non-empty remainder");
        masked.push(character);
        index += character.len_utf8();
    }
    masked
}

/// The key and value of one `key = value` pair, with the dashes and
/// separators a configuration document writes around them taken off. The
/// value keeps its quoting, because a quoted word is a literal where the bare
/// word of the same spelling is not: `null` writes down that there is nothing
/// here, and `"null"` is a four-character password.
fn credential_pair(segment: &str) -> Option<(String, &str)> {
    let (key, value) = segment.split_once(['=', ':'])?;
    let key = key
        .trim()
        .trim_start_matches(['-', ' '])
        .trim_matches(['"', '\''])
        .to_ascii_lowercase()
        .replace(['-', '_', '.'], "");
    Some((key, value.trim().trim_end_matches(',').trim()))
}

/// Whether a value holds no credential of its own. An empty value holds none,
/// and a hole the shell or the CI system fills in later names none — but only
/// while the hole is the whole value, so a literal written right after one
/// still names a credential. The bare words a document writes for "nothing
/// here" hold none either, and only while they are bare: quoted, each is a
/// literal like any other.
///
/// A value that opens a multiline literal holds its credential on the lines
/// that follow, and this scan reads a line at a time: the opening line shows
/// an empty value, and the value line carries no key to find it by. The
/// opener therefore answers for the whole literal and keeps the review.
fn holds_no_credential(value: &str) -> bool {
    if value.starts_with("\"\"\"") || value.starts_with("'''") {
        return false;
    }
    let bare = value.trim_matches(['"', '\'']).trim();
    if bare.is_empty() || bare == PLACEHOLDER_MASK {
        return true;
    }
    !written_in_quotes(value) && matches!(bare, "{}" | "[]" | "null" | "~" | "true" | "false")
}

/// Whether the value is written inside quotes of its own.
fn written_in_quotes(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(
        (characters.next(), characters.next_back()),
        (Some('"'), Some('"')) | (Some('\''), Some('\''))
    )
}

/// Whether a line writes a literal value under one of those words. The
/// detector answers for material it recognises by shape, and a short password
/// has no shape to recognise, so the word beside it carries the answer, and
/// `holds_no_credential` settles which values carry none.
///
/// A line can carry more than one pair — an inline table, a flow mapping, a
/// document written on one line — so every pair on it is read, and the word
/// is looked for anywhere in the key rather than at its end: `secret_key` and
/// `aws_secret_access_key` name a credential as plainly as `secret` does.
fn names_a_credential_value(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    lines.iter().enumerate().any(|(index, raw)| {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with("//") {
            return false;
        }
        mask_placeholders(line)
            .split([',', '{', '}'])
            .any(|segment| {
                let Some((key, value)) = credential_pair(segment) else {
                    return false;
                };
                if !CREDENTIAL_WORDS.iter().any(|word| key.contains(word)) {
                    return false;
                }
                if !holds_no_credential(value) {
                    return true;
                }
                value.is_empty() && carries_an_indented_value(&lines, index)
            })
    })
}

/// Whether the key on this line leaves its value for the line below. A
/// mapping writes its value on the next line, indented deeper, and that line
/// carries no key of its own to find it by, so the key's line answers for it:
/// `password:` over an indented `hunter2` names the credential that
/// `password:` alone does not.
fn carries_an_indented_value(lines: &[&str], index: usize) -> bool {
    let indent = indent_width(lines[index]);
    for line in lines.iter().skip(index + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        return indent_width(line) > indent && !opens_a_mapping(trimmed);
    }
    false
}

/// The spaces and tabs a line is written behind.
fn indent_width(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

/// Whether a deeper line is a mapping of its own rather than the value the
/// key above it left empty. A mapping names a plain word and a colon;
/// anything else written there is that value.
fn opens_a_mapping(line: &str) -> bool {
    let Some((key, _)) = line.split_once(':') else {
        return false;
    };
    let key = key.trim().trim_start_matches(['-', ' ']);
    !key.is_empty()
        && key.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}
