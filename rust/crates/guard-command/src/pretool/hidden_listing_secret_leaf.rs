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
    let Ok(text) = std::fs::read_to_string(canonical) else {
        return false;
    };
    // The real name can make the detector stricter as well as more lenient,
    // so both readings have to come back clean.
    ["", name].iter().all(|label| {
        guard_scanner::secret_detection::scan_secret_text(&text, label, "hidden-document", None, 1)
            .findings
            .is_empty()
    })
}
