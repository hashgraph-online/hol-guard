//! `runner_authority` kind `paseo_providers`: the provider classification
//! behind `paseo_config.paseo_providers`. Python resolves the daemon's
//! `config.json` path (`PASEO_HOME` or the home), the default XDG config
//! directory and the runtime-redirecting variables of its own environment;
//! this reads the configuration with a bounded, no-follow read and decides,
//! for each provider, which native harness runs it and why Guard cannot
//! cover it. Provider environment values never leave this kind.
//!
//! Invalid configuration is an answer, not a refusal: `{"error": message}`
//! carries the message Python raises, and never a JSON snippet or an
//! environment value.

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;

use guard_runtime_pyjson::{parse_unique, PyVal};
use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDERS: usize = 256;
const MAX_ENVIRON: usize = 256;

/// `PASEO_NATIVE_HARNESSES`: the Paseo provider IDs Guard protects through
/// a native harness integration, sorted by provider ID.
const NATIVE_HARNESSES: [(&str, &str); 6] = [
    ("claude", "claude-code"),
    ("codex", "codex"),
    ("copilot", "copilot"),
    ("omp", "omp"),
    ("opencode", "opencode"),
    ("pi", "pi"),
];

/// Variables that relocate or alter any runtime a provider launches.
const COMMON_OVERRIDES: [&str; 14] = [
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONHOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
];

const GUARD_PREFIXES: [&str; 2] = ["HOL_GUARD_", "GUARD_"];

const ACP_REASON: &str =
    "ACP and plugin providers require a separately verified native Guard integration.";
const NESTED_REASON: &str =
    "Nested provider inheritance requires separate native Guard verification.";
const COMMAND_REASON: &str =
    "Custom provider commands require separate native Guard configuration and verification.";
const PROVIDER_ENV_REASON: &str =
    "Provider environment overrides may relocate or disable native Guard protection.";
const CURRENT_ENV_REASON: &str =
    "The current environment redirects this runtime; verify the daemon's native configuration separately.";

const ERR_PROVIDER: &str = "Paseo providers must use valid provider IDs and JSON objects.";
const ERR_ENABLED: &str = "Paseo provider enabled must be a boolean.";
const ERR_INHERITED: &str = "Paseo inherited provider configuration must be a JSON object.";
const ERR_ENV_VALUE: &str = "Paseo provider environment values must be strings.";
const ERR_COUNT: &str = "Paseo provider configuration exceeds the supported provider count.";

/// `_RUNTIME_OVERRIDES`: the variables each native runtime reads to find or
/// disable its own configuration.
fn runtime_overrides(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude-code" => &[
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_DISABLE_HOOKS",
            "CLAUDE_CODE_SIMPLE",
        ],
        "codex" => &["CODEX_HOME"],
        "copilot" => &["COPILOT_HOME", "COPILOT_CONFIG_DIR", "XDG_CONFIG_HOME"],
        "opencode" => &["OPENCODE_CONFIG", "OPENCODE_DISABLE", "XDG_CONFIG_HOME"],
        "pi" => &["PI_CODING_AGENT_DIR", "PI_CONFIG_DIR", "PI_PROFILE"],
        "omp" => &[
            "PI_CODING_AGENT_DIR",
            "PI_CONFIG_DIR",
            "PI_PROFILE",
            "OMP_AGENT_DIR",
            "OMP_PROFILE",
        ],
        _ => &[],
    }
}

fn native_harness(provider: &str) -> Option<&'static str> {
    NATIVE_HARNESSES
        .iter()
        .find(|(id, _)| *id == provider)
        .map(|(_, harness)| *harness)
}

struct Request<'a> {
    config_path: &'a str,
    /// `context.home_dir / ".config"`, as Python spells it.
    xdg_default: &'a str,
    /// The caller's own non-empty runtime-redirecting variables.
    environ: Vec<(&'a str, &'a str)>,
}

impl<'a> Request<'a> {
    fn parse(args: &'a Value) -> Result<Self, &'static str> {
        let args = args_object(args)?;
        let text = |key: &str| {
            args.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(ERR_INVALID)
        };
        let environ = args
            .get("environ")
            .and_then(Value::as_object)
            .ok_or(ERR_INVALID)?;
        if environ.len() > MAX_ENVIRON {
            return Err(ERR_INVALID);
        }
        let environ = environ
            .iter()
            .map(|(key, value)| Ok((key.as_str(), value.as_str().ok_or(ERR_INVALID)?)))
            .collect::<Result<Vec<_>, &'static str>>()?;
        Ok(Self {
            config_path: text("config_path")?,
            xdg_default: text("xdg_default")?,
            environ,
        })
    }
}

/// `read_config_object`: a missing file is an empty configuration; a link,
/// a non-regular or oversized file, undecodable text, invalid or ambiguous
/// JSON, or anything but an object is unreadable.
fn read_config(spelled: &str) -> Result<Vec<(String, PyVal)>, String> {
    let unreadable = || {
        format!(
            "Cannot safely read configuration at {spelled}; repair it before installing Paseo protection."
        )
    };
    let path = Path::new(spelled);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(unreadable()),
        Ok(metadata) if !metadata.file_type().is_file() => return Err(unreadable()),
        Ok(_) => {}
    }
    let bytes = read_bounded(path).ok_or_else(unreadable)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| unreadable())?;
    match parse_unique(text) {
        Ok(PyVal::Dict(entries)) => Ok(entries),
        _ => Err(unreadable()),
    }
}

/// The bounded read of `read_config_object`. Python refuses links,
/// non-regular and oversized files and nothing else, so a hard-linked
/// configuration still reads: Guard never writes this file. The open never
/// follows a final link and never blocks on a FIFO swapped in after the
/// `symlink_metadata` check; the descriptor's own metadata decides the rest.
fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let file = open_without_following(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_CONFIG_BYTES).then_some(bytes)
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    // Opening the reparse point itself makes a swapped-in link read as a
    // link, which the `is_file` check on the handle then refuses.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// `_object_field`: an absent field is an empty object; any other
/// non-object value is refused.
fn object_field<'v>(
    entries: &'v [(String, PyVal)],
    key: &str,
) -> Result<&'v [(String, PyVal)], String> {
    match entries.iter().find(|(name, _)| name == key) {
        None => Ok(&[]),
        Some((_, PyVal::Dict(value))) => Ok(value),
        Some(_) => Err(format!("Paseo {key} must be a JSON object.")),
    }
}

fn has_key(entries: &[(String, PyVal)], key: &str) -> bool {
    entries.iter().any(|(name, _)| name == key)
}

fn field<'v>(entries: &'v [(String, PyVal)], key: &str) -> Option<&'v PyVal> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `_PROVIDER_ID`: `^[a-z][a-z0-9-]{0,127}$`.
fn valid_provider_id(provider: &str) -> bool {
    let bytes = provider.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// `posixpath.normpath` for an absolute path: `.` and empty parts drop, `..`
/// removes the part before it, and exactly two leading slashes are kept.
fn normpath(value: &str) -> String {
    let leading = if value.starts_with("//") && !value.starts_with("///") {
        "//"
    } else {
        "/"
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("{leading}{}", parts.join("/"))
}

/// Whether `value` names the default XDG config directory, as
/// `Path(os.path.abspath(value)) == context.home_dir / ".config"` decides on
/// POSIX. A path with a Windows prefix is never treated as the default, so a
/// spelling Python would accept there is classified as a redirect.
fn is_default_xdg(value: &str, xdg_default: &str) -> bool {
    if !value.starts_with('/') {
        return false;
    }
    let Some(default) = posix_path_text(xdg_default) else {
        return false;
    };
    normpath(value) == default
}

/// `str(PurePosixPath(path))` for an absolute path: repeated separators
/// and `.` parts collapse, `..` stays, and exactly two leading slashes are
/// kept as POSIX allows.
fn posix_path_text(text: &str) -> Option<String> {
    if !text.starts_with('/') {
        return None;
    }
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else {
        "/"
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !matches!(*part, "" | "."))
        .collect();
    Some(format!("{root}{}", parts.join("/")))
}

/// `redirects` inside `_override_reason`.
fn redirects(harness: &str, key: &str, value: &str, xdg_default: &str) -> bool {
    let upper = key.to_uppercase();
    if upper == "XDG_CONFIG_HOME" && (value.is_empty() || is_default_xdg(value, xdg_default)) {
        return false;
    }
    runtime_overrides(harness)
        .iter()
        .chain(GUARD_PREFIXES.iter())
        .any(|prefix| upper.starts_with(prefix))
}

/// The merged `env` of an effective provider entry: inherited variables
/// first, each one the provider sets replacing it in place.
fn merged_env<'v>(
    inherited: &'v [(String, PyVal)],
    raw: &'v [(String, PyVal)],
) -> Result<Vec<(&'v str, &'v PyVal)>, String> {
    let mut env: Vec<(&str, &PyVal)> = Vec::new();
    let mut positions: HashMap<&str, usize> = HashMap::new();
    for (key, value) in object_field(inherited, "env")?
        .iter()
        .chain(object_field(raw, "env")?)
    {
        match positions.get(key.as_str()) {
            Some(&index) => env[index].1 = value,
            None => {
                positions.insert(key.as_str(), env.len());
                env.push((key.as_str(), value));
            }
        }
    }
    Ok(env)
}

/// `_override_reason`: why a provider's command or environment may relocate
/// or bypass the native protection, if it may.
fn override_reason(
    harness: &str,
    has_command: bool,
    env: &[(&str, &PyVal)],
    request: &Request<'_>,
) -> Result<Option<&'static str>, String> {
    if has_command {
        return Ok(Some(COMMAND_REASON));
    }
    let mut environment = Vec::with_capacity(env.len());
    for (key, value) in env {
        let PyVal::Str(value) = value else {
            return Err(ERR_ENV_VALUE.to_owned());
        };
        environment.push((*key, value.as_str()));
    }
    if environment.iter().any(|(key, value)| {
        COMMON_OVERRIDES.contains(&key.to_uppercase().as_str())
            || redirects(harness, key, value, request.xdg_default)
    }) {
        return Ok(Some(PROVIDER_ENV_REASON));
    }
    let own = runtime_overrides(harness);
    if request.environ.iter().any(|(key, value)| {
        !value.is_empty()
            && own
                .iter()
                .any(|prefix| key.to_uppercase().starts_with(prefix))
            && redirects(harness, key, value, request.xdg_default)
    }) {
        return Ok(Some(CURRENT_ENV_REASON));
    }
    Ok(None)
}

/// `_provider`: classify one profile using its effective inherited command
/// and environment.
fn provider(
    provider_id: &str,
    raw: &PyVal,
    entries: &[(String, PyVal)],
    request: &Request<'_>,
) -> Result<Value, String> {
    let PyVal::Dict(raw) = raw else {
        return Err(ERR_PROVIDER.to_owned());
    };
    if !valid_provider_id(provider_id) {
        return Err(ERR_PROVIDER.to_owned());
    }
    let enabled = match field(raw, "enabled") {
        None => provider_id != "omp",
        Some(PyVal::Bool(enabled)) => *enabled,
        Some(_) => return Err(ERR_ENABLED.to_owned()),
    };
    let base = match field(raw, "extends") {
        None => Some(provider_id),
        Some(PyVal::Str(base)) => Some(base.as_str()),
        Some(_) => None,
    };
    let native = base.and_then(native_harness);
    let mut reason = Some(ACP_REASON);
    if let (Some(base), Some(harness)) = (base, native) {
        let empty = PyVal::Dict(Vec::new());
        let inherited = if base == provider_id {
            &empty
        } else {
            field(entries, base).unwrap_or(&empty)
        };
        let PyVal::Dict(inherited) = inherited else {
            return Err(ERR_INHERITED.to_owned());
        };
        let env = merged_env(inherited, raw)?;
        reason = if has_key(inherited, "extends") {
            Some(NESTED_REASON)
        } else {
            let has_command = has_key(inherited, "command") || has_key(raw, "command");
            override_reason(harness, has_command, &env, request)?
        };
    }
    Ok(json!({
        "provider": provider_id,
        "native_harness": native,
        "enabled": enabled,
        "unsupported_reason": reason,
    }))
}

/// `paseo_providers`: every configured provider plus the supported native
/// defaults, sorted by provider ID.
fn providers(request: &Request<'_>) -> Result<Vec<Value>, String> {
    let payload = read_config(request.config_path)?;
    let configured = object_field(object_field(&payload, "agents")?, "providers")?;
    if configured.len() > MAX_PROVIDERS {
        return Err(ERR_COUNT.to_owned());
    }
    let mut entries: Vec<(String, PyVal)> = NATIVE_HARNESSES
        .iter()
        .filter(|(id, _)| !has_key(configured, id))
        .map(|(id, _)| ((*id).to_owned(), PyVal::Dict(Vec::new())))
        .collect();
    entries.extend(configured.iter().cloned());
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
        .iter()
        .map(|(id, raw)| provider(id, raw, &entries, request))
        .collect()
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request = Request::parse(args)?;
    Ok(match providers(&request) {
        Ok(providers) => json!({ "providers": providers }),
        Err(message) => json!({ "error": message }),
    })
}

#[cfg(test)]
#[path = "paseo_providers_tests.rs"]
mod tests;
