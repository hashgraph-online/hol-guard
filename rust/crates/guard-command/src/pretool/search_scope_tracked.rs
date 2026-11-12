//! Whether a sensitive-named file reached by a content search is a tracked
//! fixture rather than a secret: the repository's own index lists it, it is a
//! small regular file outside every credential-store directory, and Guard's
//! secret detector finds no credential-shaped value in it. Untracked and
//! ignored files, links, and anything unreadable keep the review.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 256 * 1024;
/// Content one walk may read and scan across all of its fixtures.
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ANCESTORS: usize = 64;
const STORE_DIRECTORIES: &[&str] = &[
    ".aws", ".ssh", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".config", ".npm",
];

#[path = "tracked_credential_names.rs"]
pub(super) mod names;

/// The text a credential-word write screen outside this module reads for
/// `segment`: its own text, without the words that name tracked documents
/// when every credential-named word does.
pub(crate) fn screen(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    cwd: Option<&str>,
) -> String {
    names::segment_screen_text(model, segment, None, cwd)
}

/// Whether `target`, a path as a tool envelope spells it, resolves to a
/// document the name screens accept as a tracked project file of the
/// session's repository or of a linked worktree of the same repository. The
/// output review after a tool runs rechecks the resolved target; it needs the
/// same proof PreToolUse used, or a committed catalog entry such as
/// `command.kubernetes-secrets.json` is admitted for an edit and then has the
/// edit's result withheld.
pub fn proven_project_document(target: &str, cwd: Option<&str>) -> bool {
    names::resolves_to_tracked(target, cwd)
}

/// What the walk's tracked-file proof found for one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tracked {
    /// Not a small committed file outside a store, or the detector flagged it.
    Unproven,
    /// A small committed file the detector finds clean.
    Clean,
    /// A committed manifest declaring a Kubernetes `Secret`: its values are
    /// base64 the detector does not flag, so it is never clean.
    SecretManifest,
}

#[derive(Default)]
pub(super) struct TrackedFiles {
    indexes: HashMap<PathBuf, Option<HashSet<Vec<u8>>>>,
    spent: u64,
}

impl TrackedFiles {
    pub(super) fn non_secret(&mut self, path: &Path) -> bool {
        self.classify(path) == Tracked::Clean
    }

    pub(super) fn classify(&mut self, path: &Path) -> Tracked {
        let Some((length, rendered)) = self.tracked(path, MAX_FILE_BYTES) else {
            return Tracked::Unproven;
        };
        // Past the budget the scope stays unproven and the search is reviewed.
        self.spent += length;
        if self.spent > MAX_TOTAL_BYTES {
            return Tracked::Unproven;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return Tracked::Unproven;
        };
        let text = String::from_utf8_lossy(&bytes);
        // A Kubernetes `Secret` holds base64 values the detector does not
        // flag, so a manifest that declares one is never a fixture, whether
        // a tool names it or a recursive search walks into it.
        if names::secret_object(&text) {
            return Tracked::SecretManifest;
        }
        if clean(&text, &rendered) {
            Tracked::Clean
        } else {
            Tracked::Unproven
        }
    }

    /// Whether `path` is a PNG image the repository tracks, outside every
    /// credential store, that holds pixels and nothing a search could print
    /// as a secret. Screenshots are named for the screen they show
    /// (`auth-desktop-login.png`). Without `-a` grep and rg print no line
    /// from a binary file, but with it they print whatever bytes the file
    /// holds, and any chunk can hold plain text: a stored deflate block in
    /// `IDAT`, a palette, an `sPLT` name. So the chunk layout must be one the
    /// format defines, with nothing after `IEND`, and then every byte of the
    /// file is scanned the way a fixture is. The whole file counts against
    /// the walk's budget, which is checked before it is read. Text the walk
    /// cannot read, a compressed `zTXt` or `iTXt`, keeps the review.
    pub(super) fn tracked_image(&mut self, path: &Path) -> bool {
        let png = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("png"));
        if !png {
            return false;
        }
        let remaining = MAX_TOTAL_BYTES.saturating_sub(self.spent);
        let Some((length, rendered)) = self.tracked(path, remaining) else {
            return false;
        };
        self.spent += length;
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        // A file that grew after its length was checked is not the file the
        // budget allowed.
        bytes.len() as u64 == length
            && plain_png(&bytes)
            && clean(&printable_runs(&bytes), &rendered)
    }

    /// The length of `path` and its name in the repository index, when it is
    /// a regular file of at most `limit` bytes that the nearest repository
    /// tracks outside every credential store.
    fn tracked(&mut self, path: &Path, limit: u64) -> Option<(u64, Vec<u8>)> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() || metadata.len() > limit {
            return None;
        }
        let repository = path
            .ancestors()
            .skip(1)
            .take(MAX_ANCESTORS)
            .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())?;
        let relative = path.strip_prefix(repository).ok()?;
        // The directories are judged by the directory rule, not the file-name
        // rule: `auth-evidence/` names a feature, while `secrets/` and
        // `api-tokens/` name a store and keep the review.
        // A repository kept inside a store, such as a dotfiles checkout under
        // `.config`, is a store too.
        let store_part = |directory: &Path| {
            directory.components().any(|part| {
                part.as_os_str().to_str().is_none_or(|part| {
                    STORE_DIRECTORIES.contains(&part.to_ascii_lowercase().as_str())
                })
            })
        };
        let in_store = relative.parent().is_some_and(|parent| {
            store_part(parent) || guard_secure_fs::credential_directory_path(parent)
        });
        if in_store
            || store_part(repository)
            || guard_secure_fs::credential_directory_path(repository)
        {
            return None;
        }
        let rendered = relative
            .components()
            .map(|part| part.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join("/").into_bytes())?;
        self.indexes
            .entry(repository.to_path_buf())
            .or_insert_with(|| read_index(repository))
            .as_ref()
            .is_some_and(|names| names.contains(&rendered))
            .then_some((metadata.len(), rendered))
    }
}

/// Whether Guard's secret detector finds nothing in `text`. The real name
/// can make the detector stricter (`.env`) but also more lenient (tests/,
/// docs/); both readings must be clean.
fn clean(text: &str, rendered: &[u8]) -> bool {
    let name = String::from_utf8_lossy(rendered);
    ["", name.as_ref()].iter().all(|label| {
        guard_scanner::secret_detection::scan_secret_text(text, label, "search", None, 1)
            .findings
            .is_empty()
    })
}

/// The shortest run of text in a binary file worth scanning, as `strings`
/// reads one. No credential the detector flags is shorter.
const MIN_PRINTABLE_RUN: usize = 4;

/// The runs of printable ASCII in `bytes`, one per line. A credential a
/// text-mode search could print from a binary file is such a run; the bytes
/// between runs are compressed pixels the detector would only slow down on.
fn printable_runs(bytes: &[u8]) -> String {
    let printable = |byte: &u8| matches!(byte, b'\t' | b'\n' | b'\r' | b' '..=b'~');
    let mut text = String::new();
    for run in bytes.split(|byte| !printable(byte)) {
        if run.len() >= MIN_PRINTABLE_RUN {
            // Every byte of the run is ASCII.
            text.extend(run.iter().map(|byte| char::from(*byte)));
            text.push('\n');
        }
    }
    text
}

/// Chunks the PNG format defines, other than `IEND` and `iTXt`.
const PNG_CHUNKS: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP",
    b"mDCv", b"cLLi", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"acTL", b"fcTL", b"fdAT",
    b"iDOT", b"tEXt", b"eXIf",
];
const MAX_PNG_CHUNKS: usize = 8192;

/// Whether `bytes` lay out a plain PNG: the signature, then only chunks the
/// format defines, an uncompressed `iTXt` where there is one, and nothing
/// after `IEND`.
fn plain_png(bytes: &[u8]) -> bool {
    let Some(mut rest) = bytes.strip_prefix(b"\x89PNG\r\n\x1a\n") else {
        return false;
    };
    for _ in 0..MAX_PNG_CHUNKS {
        let Some((kind, data, after)) = png_chunk(rest) else {
            return false;
        };
        match kind {
            b"IEND" => return data.is_empty() && after.is_empty(),
            // An `iTXt` keyword ends at a NUL, then a compression flag.
            b"iTXt" => {
                let flag = data
                    .iter()
                    .position(|byte| *byte == 0)
                    .and_then(|keyword| data.get(keyword + 1));
                if flag != Some(&0) {
                    return false;
                }
            }
            _ if PNG_CHUNKS.contains(&kind) => {}
            _ => return false,
        }
        rest = after;
    }
    false
}

/// The first chunk of `bytes`: its type, its data and what follows its CRC.
fn png_chunk(bytes: &[u8]) -> Option<(&[u8; 4], &[u8], &[u8])> {
    let size = usize::try_from(be32(bytes, 0)?).ok()?;
    let kind: &[u8; 4] = bytes.get(4..8)?.try_into().ok()?;
    let end = size.checked_add(8)?;
    let data = bytes.get(8..end)?;
    let after = bytes.get(end.checked_add(4)?..)?;
    Some((kind, data, after))
}

/// The index of the repository at `directory`, or a linked worktree's own.
fn read_index(directory: &Path) -> Option<HashSet<Vec<u8>>> {
    let dot_git = directory.join(".git");
    let git_dir = if std::fs::symlink_metadata(&dot_git).ok()?.is_dir() {
        dot_git
    } else {
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
        let target = Path::new(target);
        if target.is_absolute() {
            target.to_path_buf()
        } else {
            directory.join(target)
        }
    };
    let index = git_dir.join("index");
    let metadata = std::fs::symlink_metadata(&index).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_INDEX_BYTES {
        return None;
    }
    parse_index(&std::fs::read(index).ok()?)
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Entry paths of a version 2, 3 or 4 index. Anything else is unproven.
fn parse_index(bytes: &[u8]) -> Option<HashSet<Vec<u8>>> {
    if bytes.get(..4)? != b"DIRC" {
        return None;
    }
    let version = be32(bytes, 4)?;
    let count = be32(bytes, 8)? as usize;
    if !(2..=4).contains(&version) || count > bytes.len() {
        return None;
    }
    let mut names = HashSet::with_capacity(count);
    let mut at = 12_usize;
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let flags = u16::from_be_bytes(bytes.get(at + 60..at + 62)?.try_into().ok()?);
        let mut fixed = 62;
        if version >= 3 && flags & 0x4000 != 0 {
            fixed += 2;
        }
        let name_at = at + fixed;
        if version == 4 {
            let mut strip = 0_usize;
            let mut cursor = name_at;
            loop {
                let byte = *bytes.get(cursor)?;
                cursor += 1;
                strip = (strip << 7) | usize::from(byte & 0x7f);
                if byte & 0x80 == 0 {
                    break;
                }
                strip = strip.checked_add(1)?;
            }
            let end = cursor + bytes.get(cursor..)?.iter().position(|byte| *byte == 0)?;
            previous.truncate(previous.len().checked_sub(strip)?);
            previous.extend_from_slice(&bytes[cursor..end]);
            names.insert(previous.clone());
            at = end + 1;
        } else {
            let end = name_at + bytes.get(name_at..)?.iter().position(|byte| *byte == 0)?;
            names.insert(bytes[name_at..end].to_vec());
            at += (fixed + (end - name_at) + 8) & !7;
        }
    }
    Some(names)
}
