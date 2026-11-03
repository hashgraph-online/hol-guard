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

/// Whether a line writes a literal value under one of those words. The
/// detector answers for material it recognises by shape, and a short password
/// has no shape to recognise, so the word beside it carries the answer. A
/// value the shell or the CI system fills in later names no credential of its
/// own, and an empty one holds none.
fn names_a_credential_value(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with("//") {
            return false;
        }
        let Some((key, value)) = line.split_once(['=', ':']) else {
            return false;
        };
        let key = key
            .trim()
            .trim_start_matches(['-', ' '])
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .replace(['-', '_', '.'], "");
        if !CREDENTIAL_WORDS.iter().any(|word| key.ends_with(word)) {
            return false;
        }
        let value = value
            .trim()
            .trim_end_matches(',')
            .trim_matches(['"', '\''])
            .trim();
        !value.is_empty()
            && !value.contains('$')
            && !value.contains("{{")
            && !matches!(value, "{}" | "[]" | "null" | "~" | "true" | "false")
    })
}
