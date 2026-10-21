//! The guarded-instruction Codex attachment artifact
//! (`_codex_prompt_attachment_artifact`): the prompt names a file under the
//! harness's managed attachment root, and that file's text carries
//! instructions Guard holds for review.
//!
//! Python sends the prompt text, the home directory the managed root sits
//! under and the configuration path. Everything between — which tokens name an
//! attachment, whether the path stays inside the root without a link in the
//! way, the streaming decode and digest, and the prompt classification of each
//! overlapping window — runs here. The Python scan asked the resident to
//! classify every window over a separate call; the whole stream is now one.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use fancy_regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::codex_prompt_credential_file::{
    compile, has_read_verb, FINGERPRINT_LENGTH, PATH_TOKEN_PATTERN,
};
use crate::prompt_analysis::{
    extract_prompt_requests, trailing_secret_read_state, GuardRunPromptArtifact,
};

/// `_trailing_secret_read_state`'s answer carried from one window to the next:
/// how many sentences back the read intent sits, and whether it was a positive
/// one. `None` is a window that ends with no read intent to carry.
type TrailingReadState = Option<(u8, bool)>;

/// `_ATTACHMENT_SCAN_CHUNK_BYTES`.
const CHUNK_BYTES: usize = 64 * 1024;
/// `_ATTACHMENT_SCAN_MAX_BYTES`.
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// `_ATTACHMENT_SCAN_OVERLAP_CHARS`.
const OVERLAP_CHARS: usize = 4 * 1024;
/// `_GUARDED_ATTACHMENT_CLASSES`.
const GUARDED_CLASSES: [&str; 4] = [
    "prompt_injection_intent",
    "guard_bypass_intent",
    "exfil_intent",
    "secret_read",
];
/// Longest streaming-scan budget the op grants, whatever the caller asks for.
const MAX_DEADLINE_MS: u64 = 60_000;

/// `_CODEX_ATTACHMENT_PATH_TOKEN_PATTERN`: the managed attachment prefix, then
/// the ordinary prompt path tokens.
static ATTACHMENT_PATH_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?<![\w/.-])(?:\./)?\.codex/attachments/[^\s'"`<>|;(){{}}\[\]]{{1,512}}|{PATH_TOKEN_PATTERN}"#
    ))
});

/// `_codex_prompt_attachment_artifact`.
pub(crate) fn review_prompt_attachment(
    ctx: &Ctx,
    prompt_text: &str,
    home_dir: &str,
    config_path: &str,
    deadline_ms: u64,
) -> Option<GuardRunPromptArtifact> {
    if !has_read_verb(prompt_text) {
        return None;
    }
    let deadline = Instant::now() + Duration::from_millis(deadline_ms.min(MAX_DEADLINE_MS));
    let home = PyPath::new(home_dir);
    let attachment_root = home.join(".codex").join("attachments");
    let root_text = attachment_root.to_string();
    // `Path.resolve(strict=True)`: a root that is not there is not a scan
    // failure, it is a harness with no managed attachments.
    let resolved_root = ctx.host.real_path(&root_text)?;
    if !ctx.host.is_directory(&resolved_root) {
        return None;
    }
    for found in ATTACHMENT_PATH_TOKEN.find_iter(prompt_text) {
        let Ok(found) = found else {
            // Every other way this walk can fail to read an attachment ends in
            // the unscanned artifact, and a pattern that gives up part-way
            // through the prompt is no different: the tokens past that point
            // were never looked at, so the prompt is not known to be clean.
            return Some(scan_failure(
                "<prompt>",
                "Guard could not verify the Codex attachment path.",
                config_path,
            ));
        };
        let requested_path = found.as_str().trim_end_matches(|c| ".,:!?".contains(c));
        let Some(expanded) = ctx.expanduser(requested_path) else {
            continue;
        };
        let candidate = if expanded.is_absolute() {
            expanded
        } else {
            home.join(&expanded.to_string())
        };
        let Some(relative) = candidate.relative_to(&attachment_root) else {
            continue;
        };
        if ctx
            .host
            .path_contains_symlink(&candidate.to_string(), &root_text)
        {
            return Some(scan_failure(
                requested_path,
                "Guard could not verify the Codex attachment path.",
                config_path,
            ));
        }
        let Some(mut reader) = ctx.host.attachment_reader(&root_text, &relative, MAX_BYTES) else {
            return Some(scan_failure(
                requested_path,
                "Guard could not fully scan the Codex attachment.",
                config_path,
            ));
        };
        let Ok((classes, digest)) = scan_attachment(reader.as_mut(), deadline) else {
            return Some(scan_failure(
                requested_path,
                "Guard could not fully scan the Codex attachment.",
                config_path,
            ));
        };
        if classes.is_empty() {
            continue;
        }
        return Some(artifact(&classes, &digest, config_path));
    }
    None
}

/// `_scan_attachment`: the raw digest and the guarded classes every
/// overlapping decoded window names, or the `OSError`/`UnicodeError` Python
/// turns into an unscanned-attachment artifact.
fn scan_attachment(
    reader: &mut dyn std::io::Read,
    deadline: Instant,
) -> Result<(Vec<String>, String), ()> {
    let mut decoder = StrictUtf8::default();
    let mut digest = Sha256::new();
    let mut overlap = String::new();
    let mut guarded: Vec<String> = Vec::new();
    let mut cache: HashMap<(usize, [u8; 32]), Vec<String>> = HashMap::new();
    let mut inherited: TrailingReadState = None;
    let mut total: u64 = 0;
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        if Instant::now() >= deadline {
            return Err(());
        }
        let read = reader.read(&mut chunk).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_BYTES {
            return Err(());
        }
        digest.update(&chunk[..read]);
        let decoded = decoder.decode(&chunk[..read])?;
        let window = format!("{overlap}{decoded}");
        let (classes, state) = classify_window(&window, &mut cache, inherited)?;
        guarded.extend(classes);
        inherited = state;
        overlap = tail(&window, OVERLAP_CHARS);
    }
    // `decoder.decode(b"", final=True)` with `errors="strict"` either raises on
    // a half-finished character or yields nothing at all, so the Python branch
    // that classifies a final window never runs.
    decoder.finish()?;
    let mut seen: Vec<String> = Vec::new();
    for class in guarded {
        if !seen.contains(&class) {
            seen.push(class);
        }
    }
    let hex = hex::encode(digest.finalize());
    Ok((seen, hex.chars().take(FINGERPRINT_LENGTH).collect()))
}

/// `_classify_stream_window`: the window's own guarded classes, plus the
/// `secret_read` an instruction split across the chunk boundary only names
/// once the previous window's trailing state is prefixed back on.
fn classify_window(
    window: &str,
    cache: &mut HashMap<(usize, [u8; 32]), Vec<String>>,
    inherited: TrailingReadState,
) -> Result<(Vec<String>, TrailingReadState), ()> {
    let mut classes = cached_classes(window, cache)?;
    let prefix = inherited.map_or(String::new(), |(distance, positive)| {
        let verb = if positive { "Read" } else { "Do not read" };
        if distance == 0 {
            format!("{verb} ")
        } else {
            format!("{verb} something. ")
        }
    });
    let inherited_window = format!("{prefix}{window}");
    if inherited.is_some()
        && cached_classes(&inherited_window, cache)?
            .iter()
            .any(|class| class == "secret_read")
    {
        classes.push("secret_read".to_owned());
    }
    let mut seen: Vec<String> = Vec::new();
    for class in classes {
        if !seen.contains(&class) {
            seen.push(class);
        }
    }
    let state = trailing_secret_read_state(&inherited_window).map_err(|_| ())?;
    Ok((seen, state))
}

/// `_guarded_classes`, memoized on the window's bytes as
/// `_cached_guarded_classes` is.
fn cached_classes(
    window: &str,
    cache: &mut HashMap<(usize, [u8; 32]), Vec<String>>,
) -> Result<Vec<String>, ()> {
    let bytes = window.as_bytes();
    let key = (bytes.len(), Sha256::digest(bytes).into());
    if let Some(found) = cache.get(&key) {
        return Ok(found.clone());
    }
    let classes: Vec<String> = extract_prompt_requests(window)
        .map_err(|_| ())?
        .into_iter()
        .map(|request| request.request_class)
        .filter(|class| GUARDED_CLASSES.contains(&class.as_str()))
        .collect();
    cache.insert(key, classes.clone());
    Ok(classes)
}

/// `window[-limit:]`, which counts characters rather than bytes.
fn tail(window: &str, limit: usize) -> String {
    let count = window.chars().count();
    window.chars().skip(count.saturating_sub(limit)).collect()
}

/// `codecs.getincrementaldecoder("utf-8")(errors="strict")`: a sequence the
/// chunk boundary cut in half is carried to the next chunk, and anything that
/// is not valid UTF-8 is an error rather than a replacement character.
#[derive(Default)]
struct StrictUtf8 {
    pending: Vec<u8>,
}

impl StrictUtf8 {
    fn decode(&mut self, bytes: &[u8]) -> Result<String, ()> {
        let buffer = if self.pending.is_empty() {
            bytes.to_vec()
        } else {
            let mut joined = std::mem::take(&mut self.pending);
            joined.extend_from_slice(bytes);
            joined
        };
        match std::str::from_utf8(&buffer) {
            Ok(text) => Ok(text.to_owned()),
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                let text = std::str::from_utf8(&buffer[..valid])
                    .map_err(|_| ())?
                    .to_owned();
                self.pending = buffer[valid..].to_vec();
                Ok(text)
            }
            Err(_) => Err(()),
        }
    }

    /// `decode(b"", final=True)`: a half-finished character at the end of the
    /// stream is a decoding error.
    fn finish(&self) -> Result<(), ()> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn artifact(classes: &[String], digest: &str, config_path: &str) -> GuardRunPromptArtifact {
    let summary = "Codex attachment needs review before its instructions are used.";
    let mut metadata = Map::new();
    metadata.insert(
        "prompt_signals".to_owned(),
        json!(["Requested Codex attachment contains guarded instructions."]),
    );
    metadata.insert(
        "prompt_summary".to_owned(),
        json!("Guard found risky instructions inside a requested Codex attachment."),
    );
    metadata.insert(
        "prompt_matched_text".to_owned(),
        json!("Codex attachment content"),
    );
    metadata.insert("prompt_request_class".to_owned(), json!(classes[0]));
    metadata.insert("prompt_request_classes".to_owned(), json!(classes));
    metadata.insert("request_summary".to_owned(), json!(summary));
    metadata.insert("runtime_request_summary".to_owned(), json!(summary));
    metadata.insert(
        "runtime_request_reason".to_owned(),
        json!("Guard scanned the attachment locally and found guarded instructions."),
    );
    metadata.insert("attachment_content_digest".to_owned(), json!(digest));
    GuardRunPromptArtifact {
        artifact_id: format!("codex:session:prompt-attachment:{digest}"),
        name: "Codex attachment with guarded instructions".to_owned(),
        harness: "codex".to_owned(),
        artifact_type: "prompt_request".to_owned(),
        source_scope: "session".to_owned(),
        config_path: config_path.to_owned(),
        metadata,
    }
}

/// `_scan_failure`: the attachment is held for review precisely because Guard
/// could not read it.
fn scan_failure(requested_path: &str, reason: &str, config_path: &str) -> GuardRunPromptArtifact {
    let fingerprint: String = hex::encode(Sha256::digest(requested_path.as_bytes()))
        .chars()
        .take(FINGERPRINT_LENGTH)
        .collect();
    let mut metadata = Map::new();
    metadata.insert("prompt_signals".to_owned(), json!([reason]));
    metadata.insert("prompt_summary".to_owned(), json!(reason));
    metadata.insert("prompt_matched_text".to_owned(), json!("Codex attachment"));
    metadata.insert(
        "prompt_request_class".to_owned(),
        json!("prompt_injection_intent"),
    );
    metadata.insert(
        "prompt_request_classes".to_owned(),
        json!(["prompt_injection_intent"]),
    );
    metadata.insert("request_summary".to_owned(), json!(reason));
    metadata.insert("runtime_request_summary".to_owned(), json!(reason));
    metadata.insert("runtime_request_reason".to_owned(), json!(reason));
    GuardRunPromptArtifact {
        artifact_id: format!("codex:session:prompt-attachment-unscanned:{fingerprint}"),
        name: "Codex attachment could not be scanned".to_owned(),
        harness: "codex".to_owned(),
        artifact_type: "prompt_request".to_owned(),
        source_scope: "session".to_owned(),
        config_path: config_path.to_owned(),
        metadata,
    }
}

/// Serialized answer for the wire: the artifact, or JSON `null`.
pub(crate) fn answer(artifact: Option<GuardRunPromptArtifact>) -> Value {
    artifact.map_or(Value::Null, |found| found.to_dict())
}

#[cfg(all(test, unix))]
#[path = "codex_prompt_attachment_tests.rs"]
mod tests;
