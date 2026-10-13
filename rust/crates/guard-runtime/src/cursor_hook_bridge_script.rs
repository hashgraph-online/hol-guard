//! The generated Cursor hook client the native bridge answers for.
//!
//! Cursor runs `guard-runtime cursor-hook-bridge <python> -I <script>
//! --cursor-hook-event <event>`, where `<script>` is the client
//! `cursor_hook_script_source` rendered. The native bridge answers only for
//! the client it was ported from: the script, with its six rendered
//! constants put back to their template placeholders, must hash to
//! [`CURSOR_SCRIPT_SHA256`]. Any other client, including one installed by
//! an older Guard, runs as Python with the original argv and stdin.
//!
//! `tests/test_cursor_native_bridge.py` renders the current template and
//! checks it against this digest, so a template change fails CI until the
//! native port is reviewed and the digest updated.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::pyjson::{self, PyVal};

/// SHA-256 of the current template with its placeholders in place.
pub(crate) const CURSOR_SCRIPT_SHA256: &str =
    "408da727f1b2f0f6aa5f3ed68be4bb046789fa170f78ca76d7137d354ef31f49";

const MAX_SCRIPT_BYTES: u64 = 256 * 1024;
/// Each constant line the renderer writes, as `<name> = <value>`.
const CONSTANT_NAMES: [&str; 6] = [
    "GUARD_HOME",
    "GUARD_CLI",
    "GUARD_RECOVERY_COMMAND",
    "GUARD_HOOK_ARGV",
    "GUARD_INHERIT_ENV_KEYS",
    "GUARD_HOOK_TIMEOUT_SECONDS",
];

/// The constants the bridge reads from the client.
#[derive(Debug, PartialEq)]
pub(crate) struct ScriptConstants {
    /// `GUARD_HOME`: `str(guard_home.resolve())`.
    pub(crate) guard_home: String,
    /// `_guard_hook_arg_value("--home")`.
    pub(crate) home: Option<String>,
    /// `GUARD_HOOK_TIMEOUT_SECONDS`: `str(int)`, at least one.
    pub(crate) timeout_seconds: u64,
}

/// A JSON string or list of strings, as the renderer's `json.dumps` writes
/// it and Python reads it back as a literal.
fn rendered_value(value: &str) -> Option<PyVal> {
    let parsed = pyjson::parse_mapping_lone_surrogates(value).ok()?;
    if parsed.mapped {
        return None;
    }
    let strings = match &parsed.value {
        PyVal::Str(_) => true,
        PyVal::List(items) => items.iter().all(|item| item.as_str().is_some()),
        _ => false,
    };
    strings.then_some(parsed.value)
}

/// `str(int)` for a positive whole number.
fn parse_timeout(token: &str) -> Option<u64> {
    if token.is_empty() || token.starts_with('0') || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// `_guard_hook_arg_value(flag)`: the item after the first `flag`, when it
/// is a non-blank string, unstripped.
fn hook_arg_value(argv: &[PyVal], flag: &str) -> Option<String> {
    let index = argv.iter().position(|item| item.as_str() == Some(flag))?;
    let value = argv.get(index + 1)?.as_str()?;
    (!crate::claude_hook_bridge_render::py_strip(value).is_empty()).then(|| value.to_owned())
}

/// The script with its rendered constants put back to the template
/// placeholders, and those constants. `None` unless each constant line
/// appears exactly once and holds a value the renderer writes.
pub(crate) fn normalize(text: &str) -> Option<(String, ScriptConstants)> {
    let mut values: [Option<&str>; 6] = [None; 6];
    let mut lines = Vec::new();
    let placeholders = CONSTANT_NAMES.map(|name| format!("{name} = __{name}__"));
    for line in text.split('\n') {
        let found = CONSTANT_NAMES.iter().enumerate().find_map(|(index, name)| {
            let value = line.strip_prefix(name)?.strip_prefix(" = ")?;
            Some((index, value))
        });
        match found {
            Some((index, value)) => {
                if values[index].replace(value).is_some() {
                    return None;
                }
                lines.push(placeholders[index].as_str());
            }
            None => lines.push(line),
        }
    }
    let [guard_home, cli, recovery, argv, inherit, timeout] = values;
    let PyVal::Str(guard_home) = rendered_value(guard_home?)? else {
        return None;
    };
    for list in [cli?, recovery?, inherit?] {
        rendered_value(list)?.as_list()?;
    }
    let argv = rendered_value(argv?)?;
    let constants = ScriptConstants {
        guard_home,
        home: hook_arg_value(argv.as_list()?, "--home"),
        timeout_seconds: parse_timeout(timeout?)?,
    };
    Some((lines.join("\n"), constants))
}

/// The client's constants when `text` is the ported Cursor client.
pub(crate) fn ported_constants(text: &str) -> Option<ScriptConstants> {
    let (template, constants) = normalize(text)?;
    let digest = hex::encode(Sha256::digest(template.as_bytes()));
    (digest == CURSOR_SCRIPT_SHA256).then_some(constants)
}

/// Read the client Python would run and return its constants when it is
/// the ported Cursor client.
pub(crate) fn read_ported_script(path: &Path) -> Option<ScriptConstants> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_SCRIPT_BYTES {
        return None;
    }
    ported_constants(std::str::from_utf8(&bytes).ok()?)
}
