//! The generated Grok hook client the native bridge answers for.
//!
//! Grok runs `guard-runtime bounded-hook-bridge <python> -I <script>
//! <config>`, where `<script>` is `managed/bounded-hooks/grok.py` rendered
//! by `_render_bounded_hook_script`. The bridge reads the three constants
//! the renderer writes, from the current client or one an older Guard
//! installed, and answers the hook itself; the client's own code never
//! runs. A script whose constants it cannot read fails the hook closed. The
//! `<config>` argument is read here too, as `_configure_grok_invocation`
//! reads it.
//!
//! [`GROK_SCRIPT_SHA256`] is the digest of the template the bridge was
//! ported from, with its placeholders in place.
//! `tests/test_grok_native_bridge.py` renders the current template and
//! checks it against this digest, so a template change fails CI until the
//! native port is reviewed and the digest updated.

use std::io::Read;
use std::path::Path;

use crate::bounded_hook_bridge_grok_render::{json_object, py_float};
use crate::bounded_hook_bridge_render::member;
use crate::pyjson::{self, PyVal};

/// SHA-256 of the current template with its placeholders in place.
#[allow(dead_code)] // Read by `tests/test_grok_native_bridge.py`.
pub(crate) const GROK_SCRIPT_SHA256: &str =
    "1190f8feeb60bf2e6e4bbfee4e2d5598452e4b46a751cd79a2b28dd7d12b760f";

const MAX_SCRIPT_BYTES: u64 = 256 * 1024;
const GUARD_HOME_LINE: &str = "GUARD_HOME = ";
const HARNESS_LINE: &str = "HARNESS = ";
const TIMEOUT_LINE: &str = "TIMEOUT_SECONDS = ";
const MAX_CONFIG_CHARS: usize = 64 * 1024;
const INVOCATION_OPTIONS: [&str; 4] = ["--harness", "--guard-home", "--home", "--workspace"];

/// The constants `_render_bounded_hook_script` wrote into the client.
#[derive(Debug, PartialEq)]
pub(crate) struct ScriptConstants {
    /// `GUARD_HOME`: `str(guard_home.resolve(strict=False))`.
    pub(crate) guard_home: String,
    /// `TIMEOUT_SECONDS`, finite and positive.
    pub(crate) timeout_seconds: f64,
}

/// `timeout_token`: `str(int)` for a whole number, else `str(float)`.
fn parse_timeout(token: &str) -> Option<f64> {
    let seconds = if !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit()) {
        token.parse::<f64>().ok()?
    } else {
        py_float(token)?
    };
    (seconds.is_finite() && seconds > 0.0).then_some(seconds)
}

/// The script with its rendered constants put back to the template
/// placeholders, and those constants. `None` unless each constant line
/// appears exactly once and holds a value the renderer writes.
pub(crate) fn normalize(text: &str) -> Option<(String, ScriptConstants)> {
    let mut guard_home = None;
    let mut harness_seen = false;
    let mut timeout_seconds = None;
    let mut lines = Vec::new();
    for line in text.split('\n') {
        if let Some(value) = line.strip_prefix(GUARD_HOME_LINE) {
            if guard_home.is_some() {
                return None;
            }
            let parsed = pyjson::parse_mapping_lone_surrogates(value).ok()?;
            let PyVal::Str(home) = parsed.value else {
                return None;
            };
            if parsed.mapped {
                return None;
            }
            guard_home = Some(home);
            lines.push("GUARD_HOME = __GUARD_HOME__");
        } else if let Some(value) = line.strip_prefix(HARNESS_LINE) {
            if harness_seen || value != "\"grok\"" {
                return None;
            }
            harness_seen = true;
            lines.push("HARNESS = __HARNESS__");
        } else if let Some(value) = line.strip_prefix(TIMEOUT_LINE) {
            if timeout_seconds.is_some() {
                return None;
            }
            timeout_seconds = Some(parse_timeout(value)?);
            lines.push("TIMEOUT_SECONDS = __TIMEOUT_SECONDS__");
        } else {
            lines.push(line);
        }
    }
    if !harness_seen {
        return None;
    }
    let constants = ScriptConstants {
        guard_home: guard_home?,
        timeout_seconds: timeout_seconds?,
    };
    Some((lines.join("\n"), constants))
}

/// Read the client the installer wrote and return the constants it was
/// rendered with.
pub(crate) fn read_client_constants(path: &Path) -> Option<ScriptConstants> {
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
    normalize(std::str::from_utf8(&bytes).ok()?).map(|(_, constants)| constants)
}

/// What `_configure_grok_invocation` records from the hook command.
#[derive(Debug, PartialEq)]
pub(crate) struct Invocation {
    /// `_GROK_HOME`: `--home`, or `str(Path.home())`.
    pub(crate) home: String,
    /// `_GROK_WORKSPACE`: `--workspace`, when given.
    pub(crate) workspace: Option<String>,
}

/// `str(Path(text))` for an absolute path. `None` for a relative path and
/// for a leading `//`, which Python keeps and this port does not model.
pub(crate) fn python_path(text: &str) -> Option<String> {
    if !text.starts_with('/') || text.starts_with("//") {
        return None;
    }
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    Some(format!("/{}", parts.join("/")))
}

/// `str(Path.home())` from `HOME`, which the client evaluates even when the
/// hook names `--home`. `None` when `HOME` is unset or not a plain absolute
/// path, so the client decides.
pub(crate) fn python_home() -> Option<String> {
    let home = std::env::var_os("HOME")?;
    python_path(home.to_str()?)
}

/// `_configure_grok_invocation` for the config argument. `None` wherever the
/// client would refuse the invocation or its outcome depends on a path this
/// port does not resolve.
pub(crate) fn invocation(argument: &str, guard_home: &str) -> Option<Invocation> {
    let fallback_home = python_home()?;
    if argument.chars().count() > MAX_CONFIG_CHARS {
        return None;
    }
    let config = json_object(argument)?;
    if member(&config, "harness").and_then(PyVal::as_str) != Some("grok")
        || member(&config, "guard_home").and_then(PyVal::as_str) != Some(guard_home)
    {
        return None;
    }
    let args = member(&config, "cli_args")?.as_list()?;
    let args: Vec<&str> = args.iter().map(PyVal::as_str).collect::<Option<_>>()?;
    if args.len() < 3 || args[..2] != ["guard", "hook"] || args[args.len() - 1] != "--json" {
        return None;
    }
    let options = &args[2..args.len() - 1];
    if options.len() % 2 != 0 {
        return None;
    }
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for pair in options.chunks(2) {
        if pairs.iter().any(|(name, _)| *name == pair[0]) {
            return None;
        }
        pairs.push((pair[0], pair[1]));
    }
    let option = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    };
    let guard_home_option = option("--guard-home").filter(|value| !value.is_empty())?;
    if option("--harness") != Some("grok")
        || pairs
            .iter()
            .any(|(name, _)| !INVOCATION_OPTIONS.contains(name))
        || pairs
            .iter()
            .any(|(name, value)| *name != "--harness" && !value.starts_with('/'))
    {
        return None;
    }
    let resolved = std::fs::canonicalize(guard_home_option).ok()?;
    if resolved.to_str()? != python_path(guard_home)? {
        return None;
    }
    Some(Invocation {
        home: option("--home").map_or(fallback_home, str::to_owned),
        workspace: option("--workspace").map(str::to_owned),
    })
}
