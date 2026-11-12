//! Invocation forms that launch the same CLI as its plain invocation.
//!
//! A grant binds a CLI's content and path, not the words that start it. Two
//! forms reach a granted file through another shape:
//!
//! * a shell running an executable shell script (`bash ~/.local/bin/tool`)
//!   runs the file a direct launch (`~/.local/bin/tool`) runs, so it names the
//!   direct launch's executable identity;
//! * a pipeline whose later stages only filter the first stage's output
//!   (`tool status 2>&1 | tail -15`) launches the first stage's CLI.
//!
//! Anything else keeps the identity it had: a script without an execute bit,
//! a `#!` line naming another interpreter, a `#!` line other than the one the
//! content hash covered, or a pipeline stage that can write, read files or
//! run code.

use std::io::Read;
use std::path::Path;

use guard_command::command_model::{CanonicalCommand, CommandSegment};
use guard_command::is_bounded_read_only_filter;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::executable_name;
use crate::context_digest_local_cli::python_whitespace;

const SHELLS: [&str; 6] = ["ash", "bash", "dash", "ksh", "sh", "zsh"];
const MAX_SHEBANG_BYTES: usize = 4096;
const EXECUTE_BITS: u64 = 0o111;
const TOP_LEVEL: &str = "top:0";
/// `bytes.splitlines()` boundaries, as the launch identity reads `#!` lines.
const LINE_BOUNDARIES: [u8; 8] = [b'\n', b'\r', 0x0b, 0x0c, 0x1c, 0x1d, 0x1e, 0x85];

/// The name a direct launch gives the file a shell runs, when that file is an
/// executable shell script; `None` keeps the shell run's script identity.
pub(super) fn direct_launch_name(entrypoint: &Value) -> Option<String> {
    let text = |key: &str| entrypoint.get(key).and_then(Value::as_str);
    let shell_script = text("kind")
        .and_then(|kind| kind.strip_suffix("-script"))
        .is_some_and(|shell| SHELLS.contains(&shell));
    if !shell_script
        || text("status") != Some("verified")
        || text("shebang_status") != Some("verified")
    {
        return None;
    }
    let mode = entrypoint.get("mode").and_then(Value::as_u64)?;
    if mode & EXECUTE_BITS == 0 {
        return None;
    }
    let path = text("path")?;
    let shebang = read_shebang(Path::new(path))?;
    // The `#!` line read here must be the one the content hash covered.
    let digest = hex::encode(Sha256::digest(shebang.as_bytes()));
    if text("shebang_sha256") != Some(digest.as_str()) || !names_shell(&shebang) {
        return None;
    }
    executable_name(Some(text("launch_path").unwrap_or(path))).filter(|name| !name.is_empty())
}

/// The words after the script when `segment` is a shell running the script
/// named `name` as its first operand: `bash ~/.local/bin/tool status` passes
/// `status`, as `tool status` does.
pub(super) fn shell_script_arguments<'a>(
    segment: &'a CommandSegment,
    name: &str,
) -> Option<&'a [String]> {
    let program = executable_name(segment.executable.as_deref())?;
    let (script, rest) = segment.arguments.split_first()?;
    (super::is_shell_name(&program) && executable_name(Some(script)).as_deref() == Some(name))
        .then_some(rest)
}

/// The arguments a launch's subcommand tokens are read from. A shell's
/// direct-launch identity reads past the script operand, so a subcommand
/// rule meets `bash tool status` as it meets `tool status`.
pub(crate) fn launch_arguments<'a>(
    segment: &'a CommandSegment,
    name: &str,
    kind: &str,
) -> &'a [String] {
    match shell_script_arguments(segment, name) {
        Some(rest) if kind == "executable" => rest,
        _ => &segment.arguments,
    }
}

/// The first stage of a top-level pipeline whose later stages only filter
/// its output, as `head`, `tail`, `wc` or a bounded `sed` without files.
pub(super) fn filtered_pipeline_head(model: &CanonicalCommand) -> Option<&str> {
    if model.confidence != "exact"
        || !model.redirects.is_empty()
        || !model.embedded_commands.is_empty()
        || !model.wrapper_chain.is_empty()
        || model.segments.len() < 2
    {
        return None;
    }
    let staged = model.segments.iter().enumerate().all(|(index, segment)| {
        segment.execution_context == TOP_LEVEL
            && segment.pipeline_index == index
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
    });
    let (head, filters) = model.segments.split_first()?;
    let filtered = filters.iter().all(|stage| {
        stage.environment_names.is_empty() && is_bounded_read_only_filter(&stage.text)
    });
    (staged && filtered).then_some(head.text.as_str())
}

/// The `#!` line of `path` past its marker, stripped as the launch identity
/// strips it before hashing.
fn read_shebang(path: &Path) -> Option<String> {
    let mut prefix = Vec::with_capacity(MAX_SHEBANG_BYTES + 1);
    std::fs::File::open(path)
        .ok()?
        .take(MAX_SHEBANG_BYTES as u64 + 1)
        .read_to_end(&mut prefix)
        .ok()?;
    let line = prefix.strip_prefix(b"#!")?;
    let end = line
        .iter()
        .position(|byte| LINE_BOUNDARIES.contains(byte))
        .unwrap_or(line.len());
    if end + 2 > MAX_SHEBANG_BYTES {
        return None;
    }
    let decoded = std::str::from_utf8(&line[..end]).ok()?;
    let stripped = decoded.trim_matches(python_whitespace);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// Whether a `#!` line runs a shell, directly or through `env`.
fn names_shell(shebang: &str) -> bool {
    let mut words = shebang.split_whitespace();
    let Some(mut program) = words.next().and_then(|word| executable_name(Some(word))) else {
        return false;
    };
    if program == "env" {
        let Some(word) = words.find(|word| !word.starts_with('-') && !word.contains('=')) else {
            return false;
        };
        program = executable_name(Some(word)).unwrap_or_default();
    }
    SHELLS.contains(&program.as_str())
}

#[cfg(test)]
#[path = "local_cli_identify_forms_tests.rs"]
mod tests;
