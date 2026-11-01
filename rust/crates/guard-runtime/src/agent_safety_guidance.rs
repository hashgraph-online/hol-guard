//! `agent-safety-guidance --stdin`: install or remove the Guard-owned agent
//! guidance (`agent_safety_guidance.py`).
//!
//! - `install` writes `~/.hol-support/SAFETY.md` and adds the managed block
//!   that points to it to `~/.codex/AGENTS.md`, keeping every other byte;
//! - `uninstall` removes the managed block (and an `AGENTS.md` it leaves
//!   empty) and a `SAFETY.md` that Guard wrote.
//!
//! A `SAFETY.md` that is neither the current guide nor a known earlier one is
//! never trusted or removed. Each file is read and replaced inside its opened
//! parent directory, and a file that changes between the read and the
//! replacement is left alone. A failure answers one message naming which
//! files had already changed.

use std::fs::Metadata;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(unix)]
#[path = "agent_safety_guidance_unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "agent_safety_guidance_windows.rs"]
mod platform;
#[cfg(test)]
#[path = "agent_safety_guidance_tests.rs"]
mod tests;

use platform::SupportDirectory;

const SCHEMA: &str = "agent-safety-guidance.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MODE: u32 = 0o644;
const AGENTS_DIRECTORY: &str = ".codex";
const AGENTS_NAME: &str = "AGENTS.md";
const SAFETY_DIRECTORY: &str = ".hol-support";
const SAFETY_NAME: &str = "SAFETY.md";
const MANAGED_BEGIN: &str = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->";
const MANAGED_END: &str = "<!-- END HOL GUARD SAFETY GUIDANCE -->";
const MANAGED_BLOCK: &str = "<!-- BEGIN HOL GUARD SAFETY GUIDANCE -->
## HOL Guard

- Before planning shell, Git, package, filesystem, or remote actions, read `~/.hol-support/SAFETY.md`.
- Follow that guide to avoid unnecessary approval prompts without bypassing HOL Guard.
<!-- END HOL GUARD SAFETY GUIDANCE -->
";
const SAFETY_GUIDANCE: &str = concat!(
    "<!-- HOL GUARD MANAGED SAFETY DOCUMENT v2 -->\n",
    include_str!("../../../../src/codex_plugin_scanner/guard/agent-safety-guidance.md")
);
const LEGACY_SAFETY_DIGESTS: [&str; 5] = [
    // Guidance before the self-approval section: unprefixed, then v2-prefixed.
    "8dfc18925c07e425e6ac5e5c4b5aba27d15e9bba4472409cf57411085f6389ed",
    "5276fa1bb1460b07d4ce2c42f732931b06744d11ad28fd9422dc2ff24be1eeda",
    // Guidance that let an agent decide for itself that a secret read was authorized.
    "5211684ae7093b4e0363e176ab38c3d5f2e83a88f557381cffb220b37fb36652",
    // Guidance before it named the script-free npm install Guard lets continue.
    "2726e5000e64235af716c767a45912d389fc522ce16748139ab309f9ffe53075",
    // Guidance before it named a "not set up on this device" reason as a setup decision.
    "855a66a828fd86bb249b9751d5d3d8875e293a85c81e942ff03e840b60b32eb4",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    home_dir: String,
}

/// What one support file held when it was read.
struct ExistingFile {
    text: String,
    mode: u32,
    state: FileState,
}

/// Enough to tell that a support file changed after it was read.
#[derive(PartialEq, Eq)]
struct FileState {
    identity: platform::Identity,
    size: u64,
    modified: Option<std::time::SystemTime>,
    digest: Vec<u8>,
}

#[derive(Default)]
struct Progress {
    agents_changed: bool,
    safety_changed: bool,
}

/// Called with a file's name just before its replacement is committed.
type BeforeCommit<'a> = &'a mut dyn FnMut(&str);

pub(crate) fn is_command(command: &str) -> bool {
    command == "agent-safety-guidance"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "agent_safety_guidance_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("agent_safety_guidance_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let home = Path::new(&request.home_dir);
    if request.schema != SCHEMA || !home.is_absolute() {
        return Err(invalid());
    }
    let mut progress = Progress::default();
    let answer = match request.op.as_str() {
        "install" => {
            let result = install(home, &mut progress, &mut |_| ());
            answer("install", "installed", &progress, result)
        }
        "uninstall" => {
            let result = uninstall(home, &mut progress);
            answer("remove", "removed", &progress, result)
        }
        _ => return Err(invalid()),
    };
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "agent_safety_guidance_request_invalid".to_owned()
}

fn answer(action: &str, status: &str, progress: &Progress, result: Result<(), String>) -> Value {
    match result {
        Ok(()) => json!({
            "status": status,
            "changed": progress.agents_changed || progress.safety_changed,
            "agents_path": "~/.codex/AGENTS.md",
            "safety_path": "~/.hol-support/SAFETY.md",
        }),
        Err(error) => json!({
            "failure": format!(
                "Guard could not {action} agent safety guidance (agents_changed={}, safety_changed={}): {error}",
                progress.agents_changed, progress.safety_changed
            ),
        }),
    }
}

/// Install the Guard-owned guide and its managed global AGENTS.md pointer.
fn install(
    home: &Path,
    progress: &mut Progress,
    before_commit: BeforeCommit<'_>,
) -> Result<(), String> {
    let agents = SupportDirectory::open(&home.join(AGENTS_DIRECTORY))?;
    let safety = SupportDirectory::open(&home.join(SAFETY_DIRECTORY))?;
    let existing_agents = agents.read(AGENTS_NAME)?;
    let current_agents = existing_agents.as_ref().map(|file| file.text.as_str());
    let updated_agents = upsert_managed_block(current_agents.unwrap_or(""))?;
    let existing_safety = safety.read(SAFETY_NAME)?;
    let current_safety = existing_safety.as_ref().map(|file| file.text.as_str());
    if current_safety.is_some_and(|text| !is_known_safety_guidance(text)) {
        return Err("Guard refused to trust an unmanaged SAFETY.md file".to_owned());
    }
    if current_safety != Some(SAFETY_GUIDANCE) {
        safety.write(
            SAFETY_NAME,
            SAFETY_GUIDANCE,
            existing_safety.as_ref(),
            before_commit,
        )?;
        progress.safety_changed = true;
    }
    if current_agents != Some(updated_agents.as_str()) {
        agents.write(
            AGENTS_NAME,
            &updated_agents,
            existing_agents.as_ref(),
            before_commit,
        )?;
        progress.agents_changed = true;
    }
    Ok(())
}

/// Remove only Guard-managed guidance after the last harness uninstall.
fn uninstall(home: &Path, progress: &mut Progress) -> Result<(), String> {
    let agents_parent = home.join(AGENTS_DIRECTORY);
    if agents_parent.exists() {
        let agents = SupportDirectory::open(&agents_parent)?;
        if let Some(existing) = agents.read(AGENTS_NAME)? {
            let updated = remove_managed_block(&existing.text)?;
            if updated != existing.text {
                if updated.is_empty() {
                    agents.unlink(AGENTS_NAME, &existing.state)?;
                } else {
                    agents.write(AGENTS_NAME, &updated, Some(&existing), &mut |_| ())?;
                }
                progress.agents_changed = true;
            }
        }
    }
    let safety_parent = home.join(SAFETY_DIRECTORY);
    if safety_parent.exists() {
        let safety = SupportDirectory::open(&safety_parent)?;
        if let Some(existing) = safety.read(SAFETY_NAME)? {
            if !is_known_safety_guidance(&existing.text) {
                return Err("Guard refused to remove an unmanaged SAFETY.md file".to_owned());
            }
            safety.unlink(SAFETY_NAME, &existing.state)?;
            progress.safety_changed = true;
        }
    }
    Ok(())
}

fn is_known_safety_guidance(text: &str) -> bool {
    text == SAFETY_GUIDANCE
        || LEGACY_SAFETY_DIGESTS.contains(&hex::encode(Sha256::digest(text.as_bytes())).as_str())
}

/// The span of each managed block, as `(?ms)^BEGIN\n.*?^END\n?` finds them.
fn managed_blocks(text: &str) -> Vec<(usize, usize)> {
    let opening = format!("{MANAGED_BEGIN}\n");
    let mut blocks = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find(&opening) {
        let start = cursor + offset;
        cursor = start + 1;
        if !at_line_start(text, start) {
            continue;
        }
        let Some(end) = line_start_closing(text, start + opening.len()) else {
            continue;
        };
        let mut stop = end + MANAGED_END.len();
        if text[stop..].starts_with('\n') {
            stop += 1;
        }
        blocks.push((start, stop));
        cursor = stop;
    }
    blocks
}

fn line_start_closing(text: &str, from: usize) -> Option<usize> {
    let mut cursor = from;
    while let Some(offset) = text[cursor..].find(MANAGED_END) {
        let index = cursor + offset;
        if at_line_start(text, index) {
            return Some(index);
        }
        cursor = index + 1;
    }
    None
}

fn at_line_start(text: &str, index: usize) -> bool {
    index == 0 || text.as_bytes()[index - 1] == b'\n'
}

/// The one complete managed block, refusing duplicates and stray markers.
fn single_managed_block(text: &str) -> Result<Option<(usize, usize)>, String> {
    let blocks = managed_blocks(text);
    if blocks.len() > 1
        || text.matches(MANAGED_BEGIN).count() != blocks.len()
        || text.matches(MANAGED_END).count() != blocks.len()
    {
        return Err("Guard found an incomplete managed safety guidance block".to_owned());
    }
    Ok(blocks.first().copied())
}

fn upsert_managed_block(existing: &str) -> Result<String, String> {
    Ok(match single_managed_block(existing)? {
        Some((start, stop)) => {
            format!("{}{MANAGED_BLOCK}{}", &existing[..start], &existing[stop..])
        }
        None if existing.is_empty() => MANAGED_BLOCK.to_owned(),
        None => format!("{existing}\n{MANAGED_BLOCK}"),
    })
}

fn remove_managed_block(existing: &str) -> Result<String, String> {
    let Some((start, stop)) = single_managed_block(existing)? else {
        return Ok(existing.to_owned());
    };
    let after = &existing[stop..];
    let mut before = &existing[..start];
    if after.is_empty() {
        before = before.strip_suffix('\n').unwrap_or(before);
    }
    Ok(format!("{before}{after}"))
}

/// Read an opened support file that must be a bounded, regular UTF-8 file.
fn read_opened(
    file: std::fs::File,
    metadata: &Metadata,
    name: &str,
    identity: platform::Identity,
    mode: u32,
) -> Result<ExistingFile, String> {
    if !metadata.is_file() {
        return Err(non_regular(name));
    }
    let mut raw = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| failed(name, &error))?;
    if raw.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("Guard refused an oversized support file: {name}"));
    }
    let digest = Sha256::digest(&raw).to_vec();
    let text = String::from_utf8(raw)
        .map_err(|_| format!("Guard refused a support file that is not UTF-8: {name}"))?;
    Ok(ExistingFile {
        text,
        mode,
        state: FileState {
            identity,
            size: metadata.len(),
            modified: metadata.modified().ok(),
            digest,
        },
    })
}

/// Refuse a support directory that is a link, a reparse point or not a
/// directory, then create it (and its parents) when it is missing.
fn prepare_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !platform::is_reparse(&metadata) => {}
        Ok(_) => return Err(non_directory(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(failed(&directory_name(path), &error)),
    }
    std::fs::create_dir_all(path).map_err(|error| failed(&directory_name(path), &error))
}

fn temporary_name(name: &str) -> Result<String, String> {
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| format!("Guard could not name a temporary file: {name}"))?;
    Ok(format!(".{name}.guard-{}.tmp", hex::encode(nonce)))
}

fn directory_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn non_directory(path: &Path) -> String {
    format!(
        "Guard refused to use a non-directory support path: {}",
        directory_name(path)
    )
}

fn non_regular(name: &str) -> String {
    format!("Guard refused to replace a non-regular support file: {name}")
}

fn changed(name: &str) -> String {
    format!("Guard support file changed during update: {name}")
}

fn failed(name: &str, error: &dyn std::fmt::Display) -> String {
    format!("{error}: {name}")
}
