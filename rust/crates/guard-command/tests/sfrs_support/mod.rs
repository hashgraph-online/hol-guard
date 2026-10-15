//! Replay support for the request-classification parity vectors: loading,
//! materializing the recorded directories, and rewriting recorded roots and
//! path-dependent digests.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const TOKEN: &str = "<SFRS_ROOT>";

/// One recorded call, rewritten to the replay root.
///
/// Inputs (`args`, `env`, `evaluation`) are fully resolved. The expected
/// result is resolved by [`ReplayVector::expected`] once the classifier has
/// produced its output, because the resident-computed shell-context hashes
/// are bound from that output and the digests derived from them follow.
pub struct ReplayVector {
    pub id: String,
    /// Absolute path of the materialized test directory.
    pub dir: PathBuf,
    pub args: Value,
    pub env: Value,
    pub evaluation: Value,
    /// Results that embed host-specific identities are not compared.
    pub host_dependent: bool,
    raw_result: Value,
    digests: Vec<(String, String, Vec<usize>)>,
    input_natives: BTreeMap<usize, String>,
    root: String,
}

impl ReplayVector {
    /// Expected result for the classifier output `actual`.
    ///
    /// Hash positions that the Python implementation took from the resident
    /// are bound to the value found at the same position in `actual`, so the
    /// comparison proves that every such hash is present, well formed and
    /// used consistently, while the digests derived from them are recomputed
    /// from the rewritten pre-images.
    pub fn expected(&self, actual: &Value) -> Value {
        let mut natives = self.input_natives.clone();
        bind_natives(&self.raw_result, actual, &mut natives);
        resolve(&self.raw_result, &self.digests, &natives, &self.root)
    }
}

struct ReplayRoot {
    path: PathBuf,
}

impl ReplayRoot {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp dir");
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = base.join(format!(
            "sfrs-conformance-{}-{serial}-{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create replay root");
        Self { path }
    }
}

impl Drop for ReplayRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn gunzip_json(bytes: &[u8]) -> Value {
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_string(&mut decoded)
        .expect("gunzip vectors");
    serde_json::from_str(&decoded).expect("parse vectors")
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn native_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"<NATIVE_HASH:(\d+)>").expect("native token pattern"))
}

fn bind_natives(template: &Value, actual: &Value, natives: &mut BTreeMap<usize, String>) {
    match (template, actual) {
        (Value::String(text), Value::String(found)) if text.contains("<NATIVE_HASH:") => {
            let mut pattern = String::from("^");
            let mut order = Vec::new();
            let mut cursor = 0;
            for token in native_pattern().captures_iter(text) {
                let whole = token.get(0).expect("token");
                pattern.push_str(&regex::escape(&text[cursor..whole.start()]));
                pattern.push_str("([0-9a-f]{64})");
                order.push(token[1].parse::<usize>().expect("token index"));
                cursor = whole.end();
            }
            pattern.push_str(&regex::escape(&text[cursor..]));
            pattern.push('$');
            let Ok(matcher) = Regex::new(&pattern) else {
                return;
            };
            if let Some(captured) = matcher.captures(found) {
                for (offset, index) in order.iter().enumerate() {
                    natives
                        .entry(*index)
                        .or_insert_with(|| captured[offset + 1].to_owned());
                }
            }
        }
        (Value::Object(expected), Value::Object(found)) => {
            for (key, value) in expected {
                if let Some(other) = found.get(key) {
                    bind_natives(value, other, natives);
                }
            }
        }
        (Value::Array(expected), Value::Array(found)) => {
            for (value, other) in expected.iter().zip(found) {
                bind_natives(value, other, natives);
            }
        }
        _ => {}
    }
}

fn substitute_natives(text: &str, natives: &BTreeMap<usize, String>) -> String {
    native_pattern()
        .replace_all(text, |captures: &regex::Captures| {
            let index: usize = captures[1].parse().expect("token index");
            natives
                .get(&index)
                .cloned()
                .unwrap_or_else(|| captures[0].to_owned())
        })
        .into_owned()
}

/// Rewrite `value` below `root`: bind the native hashes, recompute every
/// digest whose pre-image is fully known and substitute old for new.
fn resolve(
    value: &Value,
    digests: &[(String, String, Vec<usize>)],
    natives: &BTreeMap<usize, String>,
    root: &str,
) -> Value {
    let replacements = digest_replacements(digests, natives, root);
    let text = substitute_natives(&value.to_string(), natives);
    let text = apply_replacements(&text, &replacements);
    serde_json::from_str(&text).expect("reparse resolved value")
}

/// Replace every `old` with its `new`, longest `old` first so a short prefix
/// never rewrites part of a longer digest.
fn apply_replacements(text: &str, replacements: &[(String, String)]) -> String {
    let mut ordered: Vec<&(String, String)> = replacements.iter().collect();
    ordered.sort_by_key(|(old, _)| std::cmp::Reverse(old.len()));
    let mut rewritten = text.to_owned();
    for (old, new) in ordered {
        rewritten = rewritten.replace(old.as_str(), new.as_str());
    }
    rewritten
}

/// Recompute the path-dependent digests below `root` and return the
/// old-to-new pairs, including truncated prefix forms. A digest whose
/// pre-image still holds an unbound native hash is left out.
fn digest_replacements(
    digests: &[(String, String, Vec<usize>)],
    natives: &BTreeMap<usize, String>,
    root: &str,
) -> Vec<(String, String)> {
    let mut replacements: Vec<(String, String)> = Vec::new();
    for (old, preimage, prefix_lengths) in digests {
        let rewritten = substitute_natives(&preimage.replace(TOKEN, root), natives);
        if rewritten.contains("<NATIVE_HASH:") {
            continue;
        }
        let rewritten = apply_replacements(&rewritten, &replacements);
        let new = sha256_hex(&rewritten);
        let mut lengths = prefix_lengths.clone();
        lengths.push(old.len());
        lengths.sort_unstable();
        lengths.dedup();
        for length in lengths {
            replacements.push((old[..length].to_owned(), new[..length].to_owned()));
        }
    }
    replacements
}

fn materialize(snapshot: &Value, dir: &Path) {
    fs::create_dir_all(dir).expect("create vector directory");
    let Some(entries) = snapshot["entries"].as_array() else {
        return;
    };
    for entry in entries {
        let relative = entry["path"].as_str().expect("snapshot path");
        let target = dir.join(relative);
        match entry["kind"].as_str().expect("snapshot kind") {
            "dir" => fs::create_dir_all(&target).expect("create directory"),
            "symlink" => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).expect("create parent");
                }
                symlink(entry["target"].as_str().expect("symlink target"), &target)
                    .expect("create symlink");
            }
            _ => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).expect("create parent");
                }
                if let Some(text) = entry["text"].as_str() {
                    fs::write(&target, text).expect("write file");
                } else {
                    use base64::Engine as _;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(entry["base64"].as_str().expect("file payload"))
                        .expect("decode file");
                    fs::write(&target, bytes).expect("write file");
                }
                let mode = entry["mode"].as_u64().unwrap_or(0o644) as u32;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                    .expect("set permissions");
            }
        }
    }
}

fn digest_entries(vector: &Value) -> Vec<(String, String, Vec<usize>)> {
    vector["digests"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|item| {
            let lengths = item["prefix_lengths"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_u64().map(|length| length as usize))
                        .collect()
                })
                .unwrap_or_default();
            (
                item["digest"].as_str().expect("digest").to_owned(),
                item["preimage"].as_str().expect("preimage").to_owned(),
                lengths,
            )
        })
        .collect()
}

fn build_vector(vector: &Value, root: &Path) -> ReplayVector {
    let root_text = root.to_str().expect("utf-8 root").to_owned();
    let digests = digest_entries(vector);
    let with_root = |value: &Value| -> Value {
        serde_json::from_str(&value.to_string().replace(TOKEN, &root_text)).expect("reparse")
    };
    let args = with_root(&vector["args"]);
    let env = with_root(&vector["env"]);
    let evaluation = with_root(&vector["evaluation"]);
    // Resident hashes that arrive as inputs are bound to stable dummies so
    // the builder under test sees concrete values; the rest are bound from
    // the classifier output.
    let mut input_natives = BTreeMap::new();
    for source in [&args, &env, &evaluation] {
        for token in native_pattern().captures_iter(&source.to_string()) {
            let index: usize = token[1].parse().expect("token index");
            input_natives
                .entry(index)
                .or_insert_with(|| sha256_hex(&format!("sfrs-native-input:{index}")));
        }
    }
    let resolve_input = |value: &Value| resolve(value, &digests, &input_natives, &root_text);
    ReplayVector {
        id: vector["id"].as_str().expect("vector id").to_owned(),
        dir: root.join(vector["dir"].as_str().expect("vector dir")),
        args: resolve_input(&args),
        env: resolve_input(&env),
        evaluation: resolve_input(&evaluation),
        host_dependent: vector["host_dependent"].as_bool().unwrap_or(false),
        raw_result: with_root(&vector["result"]),
        digests,
        input_natives,
        root: root_text,
    }
}

/// Load one entry's vectors, materialize their directories below a fresh root
/// and return them rewritten to that root. The root is removed when the
/// returned guard drops.
pub fn replay_vectors(entries: &[(&str, &[u8])], entry: &str) -> (Vec<ReplayVector>, impl Drop) {
    let bytes = entries
        .iter()
        .find(|(name, _)| *name == entry)
        .unwrap_or_else(|| panic!("unknown entry {entry}"))
        .1;
    let file = gunzip_json(bytes);
    assert_eq!(file["schema"], "sfrs-vectors.v1");
    assert_eq!(file["root_token"], TOKEN);
    let root = ReplayRoot::new(entry);
    let mut vectors = Vec::new();
    for raw in file["vectors"].as_array().expect("vectors") {
        let vector = build_vector(raw, &root.path);
        let snapshot = serde_json::from_str::<Value>(
            &raw["snapshot"]
                .to_string()
                .replace(TOKEN, root.path.to_str().expect("utf-8 root")),
        )
        .expect("reparse snapshot");
        materialize(&snapshot, &vector.dir);
        vectors.push(vector);
    }
    (vectors, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_hashes_bind_from_the_output_and_feed_dependent_digests() {
        let root = Path::new("/tmp/sfrs-synthetic");
        let vector = json!({
            "id": "synthetic-0",
            "dir": "v0",
            "args": {},
            "env": {},
            "evaluation": null,
            "host_dependent": false,
            "result": {
                "hash": "sha256:<NATIVE_HASH:0>",
                "id": format!("tool:{}", "0".repeat(64)),
            },
            "digests": [{
                "digest": "0".repeat(64),
                "preimage": "{\"ctx\":\"sha256:<NATIVE_HASH:0>\",\"cwd\":\"<SFRS_ROOT>/v0\"}",
                "prefix_lengths": [64],
            }],
        });
        let replay = build_vector(&vector, root);
        let bound = "ab".repeat(32);
        let expected = replay.expected(&json!({ "hash": format!("sha256:{bound}") }));
        assert_eq!(expected["hash"], format!("sha256:{bound}"));
        let preimage = format!("{{\"ctx\":\"sha256:{bound}\",\"cwd\":\"/tmp/sfrs-synthetic/v0\"}}");
        assert_eq!(expected["id"], format!("tool:{}", sha256_hex(&preimage)));
    }

    #[test]
    fn input_hashes_bind_to_stable_values_before_the_call() {
        let root = Path::new("/tmp/sfrs-synthetic");
        let vector = json!({
            "id": "synthetic-1",
            "dir": "v1",
            "args": { "request": { "shell_execution_context_hash": "sha256:<NATIVE_HASH:0>" } },
            "env": {},
            "evaluation": null,
            "host_dependent": false,
            "result": { "metadata": { "shell_execution_context_hash": "sha256:<NATIVE_HASH:0>" } },
            "digests": [],
        });
        let replay = build_vector(&vector, root);
        let supplied = replay.args["request"]["shell_execution_context_hash"].clone();
        assert!(supplied
            .as_str()
            .is_some_and(|value| value.len() == "sha256:".len() + 64));
        let expected = replay.expected(&Value::Null);
        assert_eq!(
            expected["metadata"]["shell_execution_context_hash"],
            supplied
        );
    }
}
