//! Native launch-identity material and shell-tokenizer argv rules shared
//! by the Unix implementation and the non-Unix stub.

use std::path::Path;

use guard_contracts::write_canonical_json;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// Native authority matches OpaqueMaterialDigest: raw UTF-8, not a fallback sentinel.
#[cfg(unix)]
pub(crate) fn context_opaque_digest_strict(material: &str) -> String {
    sha256_hex(material.as_bytes())
}

// `_launch_argv_digest` (:891-897) — `opaque_material_digest` over
// `json.dumps(list(argv), ensure_ascii=True, separators=(",",":"))`.
pub(crate) fn launch_argv_digest(argv: &[String]) -> String {
    let material = Value::Array(argv.iter().map(|s| Value::String(s.clone())).collect());
    let mut bytes = Vec::with_capacity(64);
    if write_canonical_json(&material, &mut bytes).is_err() {
        bytes.clear();
    }
    sha256_hex(&bytes)
}

// `_runtime_launch_identity` argv construction (:906-920), extracted so the
// Unix and non-Unix implementations resolve the launch vector through one
// code path.
//
// - `command` must be a non-blank string; anything else is `Invalid`.
// - A `structured_command` is already an executable name — the whole string
//   is one token even when it contains whitespace or quote characters; no
//   tokenization is attempted, so structured commands can never be malformed.
// - A shell command string is tokenized with the same parser the Unix path
//   uses (`crate::shell_tokens`, POSIX shlex-equivalent rules); an
//   unterminated quote or dangling escape is `Invalid`, as is a vector that
//   produces no token or carries a non-string `args` element.
// - `Valid` carries the full argv (`executable + command-derived tokens +
//   args`) used for `argv_sha256`; `Invalid` carries the command's first
//   token — or the raw command when tokenization failed — so the caller can
//   still name the executable in the fail-closed identity.
pub(crate) enum RuntimeLaunchArgv {
    Valid(Vec<String>),
    Invalid(Value),
}

pub(crate) fn runtime_launch_argv(
    command: &Value,
    args: &[Value],
    structured_command: bool,
) -> RuntimeLaunchArgv {
    let command_str = match command.as_str() {
        Some(s) if !s.trim().is_empty() => s,
        _ => return RuntimeLaunchArgv::Invalid(Value::Null),
    };
    let command_tokens: Vec<String>;
    if structured_command {
        command_tokens = vec![command_str.to_string()];
    } else {
        match crate::shell_tokens(command_str, false) {
            Ok(t) => command_tokens = t,
            Err(_) => {
                // Tokenization failed before a vector existed; name the raw
                // command so the fail-closed executable identity is usable.
                return RuntimeLaunchArgv::Invalid(command.clone());
            }
        }
    }
    let invalid = || {
        RuntimeLaunchArgv::Invalid(
            command_tokens
                .first()
                .map(|s| Value::String(s.clone()))
                .unwrap_or_else(|| command.clone()),
        )
    };
    if command_tokens.is_empty() || !args.iter().all(|a| a.is_string()) {
        return invalid();
    }
    let mut full_argv = command_tokens;
    full_argv.reserve(args.len());
    for a in args {
        if let Some(s) = a.as_str() {
            full_argv.push(s.to_string());
        }
    }
    RuntimeLaunchArgv::Valid(full_argv)
}

// Normalize an existing cwd and expand the current-user `~` shortcut.
// Unix uses HOME; Windows uses USERPROFILE or HOMEDRIVE+HOMEPATH.
// Nonexistent paths retain a best-effort absolute spelling. Named-user
// shortcuts remain literal.
pub(crate) fn expand_user(path: &Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        return expand_user_windows(path, &text);
    }
    if text == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

// `ntpath.expanduser` tail test: expandable `~` references are `~`, `~/...`,
// and `~\...`; the returned tail keeps its leading separator because Python
// concatenates `userhome + path[i:]`.
fn windows_tilde_tail(text: &str) -> Option<&str> {
    match text.strip_prefix('~') {
        Some(tail) if tail.is_empty() || tail.starts_with('/') || tail.starts_with('\\') => {
            Some(tail)
        }
        _ => None,
    }
}

// `ntpath.expanduser` home resolution: `USERPROFILE` when the variable is
// present (even empty), else `HOMEDRIVE`+`HOMEPATH` joined (`HOMEDRIVE`
// defaults to `""`); absent `HOMEPATH` leaves the path unexpanded.
fn windows_home_text(
    userprofile: Option<String>,
    homedrive: Option<String>,
    homepath: Option<String>,
) -> Option<String> {
    if let Some(profile) = userprofile {
        return Some(profile);
    }
    let homepath = homepath?;
    let mut home = homedrive.unwrap_or_default();
    // Match ntpath's verbatim drive concatenation, including drive-relative paths.
    home.reserve(homepath.len());
    home.push_str(&homepath);
    Some(home)
}

fn expand_user_windows(path: &Path, text: &str) -> std::path::PathBuf {
    let Some(tail) = windows_tilde_tail(text) else {
        return path.to_path_buf();
    };
    let env = |name: &str| {
        std::env::var_os(name).map(|value| {
            value
                .into_string()
                .unwrap_or_else(|value| value.to_string_lossy().into_owned())
        })
    };
    let home = match env("USERPROFILE") {
        Some(profile) => windows_home_text(Some(profile), None, None),
        None => {
            let homepath = env("HOMEPATH");
            let drive = homepath.as_ref().and_then(|_| env("HOMEDRIVE"));
            windows_home_text(None, drive, homepath)
        }
    };
    let Some(mut home) = home else {
        return path.to_path_buf();
    };
    home.reserve(tail.len());
    home.push_str(tail);
    std::path::PathBuf::from(home)
}

// Python `Path.resolve`/`os.path.realpath` on Windows strips the `\\?\`
// prefix `GetFinalPathNameByHandle` adds (`canonicalize` keeps it): an
// ordinary drive path `\\?\C:\x` resolves to `C:\x`, and
// `\\?\UNC\server\share` to `\\server\share`. A caller-supplied
// `\\?\` prefix is preserved — realpath never strips a prefix the input
// already carried.
#[cfg(any(windows, test))]
fn strip_generated_extended_prefix(original: &str, mut resolved: String) -> String {
    if original.starts_with("\\\\?\\") {
        return resolved;
    }
    if resolved.starts_with("\\\\?\\UNC\\") {
        resolved.replace_range(..8, "\\\\");
        return resolved;
    }
    if resolved.starts_with("\\\\?\\") {
        resolved.replace_range(..4, "");
    }
    resolved
}

pub(crate) fn normalized_launch_cwd(cwd: Option<&Path>) -> std::path::PathBuf {
    let candidate = cwd
        .map(expand_user)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        });
    let resolved = candidate.canonicalize().unwrap_or_else(|_| {
        if candidate.is_absolute() {
            candidate.clone()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(&candidate)
        }
    });
    // On Windows `canonicalize` returns the `\\?\`-prefixed path from
    // `GetFinalPathNameByHandle`; Python's `resolve` strips that generated
    // prefix for ordinary inputs, so `launch_cwd` must do the same to keep
    // the identity bytes consistent with Python's Windows cwd representation.
    #[cfg(windows)]
    let resolved = std::path::PathBuf::from(strip_generated_extended_prefix(
        &candidate.to_string_lossy(),
        resolved
            .into_os_string()
            .into_string()
            .unwrap_or_else(|path| path.to_string_lossy().into_owned()),
    ));
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn argv_of(command: &Value, args: &[Value], structured: bool) -> Result<Vec<String>, Value> {
        match runtime_launch_argv(command, args, structured) {
            RuntimeLaunchArgv::Valid(argv) => Ok(argv),
            RuntimeLaunchArgv::Invalid(executable_cmd) => Err(executable_cmd),
        }
    }

    #[test]
    fn empty_cwd_serializes_like_the_current_directory() {
        let empty = normalized_launch_cwd(Some(Path::new("")));
        let current = normalized_launch_cwd(None);
        assert_eq!(empty.as_os_str(), current.as_os_str());
    }

    // Review regression (PR3664): a shell command string and the equivalent
    // structured command must resolve to the same argv — the stub previously
    // hashed the raw string as one argv element, so `"git status"` digested
    // as `["git status"]` on Windows but `["git","status"]` on Unix.
    #[test]
    fn shell_command_and_structured_vector_agree() {
        let args = [json!("--porcelain")];
        let shell = argv_of(&json!("git status"), &args, false).unwrap();
        assert_eq!(shell, vec!["git", "status", "--porcelain"]);
        // The structured form carries the executable only; the digest of a
        // structured launch is byte-identical to the tokenized shell launch
        // for the same vector — and identical on every platform.
        let structured = argv_of(
            &json!("git"),
            &[json!("status"), json!("--porcelain")],
            true,
        )
        .unwrap();
        assert_eq!(shell, structured);
        assert_eq!(launch_argv_digest(&shell), launch_argv_digest(&structured));
    }

    #[test]
    fn structured_command_stays_single_token() {
        // A structured command is an executable name verbatim — whitespace
        // and quote characters are never tokenized, so it can never be
        // malformed the way a shell string can.
        let argv = argv_of(&json!("my tool --flag"), &[], true).unwrap();
        assert_eq!(argv, vec!["my tool --flag"]);
        let argv = argv_of(&json!("unterminated 'quote"), &[], true).unwrap();
        assert_eq!(argv, vec!["unterminated 'quote"]);
    }

    #[test]
    fn quoted_argument_boundaries_hold() {
        // Quoted groups join into single argv elements; quoting inside one
        // quoting style is preserved per shlex rules.
        let argv = argv_of(&json!("python -m \"my module\" 'other arg'"), &[], false).unwrap();
        assert_eq!(argv, vec!["python", "-m", "my module", "other arg"]);
        let argv = argv_of(&json!("say \"hi\""), &[], false).unwrap();
        assert_eq!(argv, vec!["say", "hi"]);
        let argv = argv_of(&json!("say 'a\\b'"), &[], false).unwrap();
        assert_eq!(argv, vec!["say", "a\\b"]);
    }

    #[test]
    fn malformed_command_and_non_string_args_are_invalid() {
        // Unterminated quote / dangling escape must invalidate the vector,
        // never partially tokenize (same fail-closed surface as Unix).
        assert!(argv_of(&json!("git 'unterminated"), &[], false).is_err());
        assert!(argv_of(&json!("git foo\\"), &[], false).is_err());
        assert!(argv_of(&json!(""), &[], false).is_err());
        assert!(argv_of(&json!("   "), &[], false).is_err());
        assert!(argv_of(&Value::Null, &[], false).is_err());
        assert!(argv_of(&json!(42), &[], false).is_err());
        // Non-string args poison the whole vector even when the command
        // tokenizes cleanly.
        assert!(argv_of(&json!("git"), &[json!(1)], false).is_err());
        assert!(argv_of(&json!("git"), &[json!(null)], true).is_err());
        assert!(argv_of(&json!("git"), &[json!("-m"), json!({"k": 1})], false).is_err());
    }

    // Windows `expanduser`/`realpath` semantics — pure helpers, no env
    // mutation, so they run deterministically on any host.

    #[test]
    fn windows_tilde_accepts_forward_and_backslash() {
        // ntpath.expanduser treats ~, ~/, and ~\ as the current-user home;
        // ~user stays literal (no user lookup in this port).
        assert_eq!(windows_tilde_tail("~"), Some(""));
        assert_eq!(windows_tilde_tail("~/docs"), Some("/docs"));
        assert_eq!(windows_tilde_tail("~\\docs"), Some("\\docs"));
        assert_eq!(windows_tilde_tail("~alice/docs"), None);
        assert_eq!(windows_tilde_tail("nottilde"), None);
    }

    #[test]
    fn windows_home_prefers_userprofile_then_drive_pair() {
        assert_eq!(
            windows_home_text(
                Some("C:\\Users\\me".to_string()),
                Some("D:".to_string()),
                Some("\\other".to_string())
            ),
            Some("C:\\Users\\me".to_string())
        );
        // Present-but-empty USERPROFILE wins over the drive pair (Python
        // tests env membership, not non-empty).
        assert_eq!(
            windows_home_text(Some("".to_string()), None, Some("\\Users\\me".to_string())),
            Some("".to_string())
        );
        assert_eq!(
            windows_home_text(
                None,
                Some("D:".to_string()),
                Some("\\Users\\me".to_string())
            ),
            Some("D:\\Users\\me".to_string())
        );
        // HOMEDRIVE defaults to "" when absent; missing HOMEPATH fails
        // expansion entirely. A non-rooted HOMEPATH stays drive-relative,
        // matching ntpath.join's verbatim drive concatenation.
        assert_eq!(
            windows_home_text(None, None, Some("\\Users\\me".to_string())),
            Some("\\Users\\me".to_string())
        );
        assert_eq!(
            windows_home_text(None, Some("D:".to_string()), Some("Users\\me".to_string())),
            Some("D:Users\\me".to_string())
        );
        assert_eq!(windows_home_text(None, Some("D:".to_string()), None), None);
        assert_eq!(windows_home_text(None, None, None), None);
    }

    #[test]
    fn extended_prefix_strip_matches_python_realpath() {
        // Ordinary drive input: canonicalize's generated \\?\ prefix is
        // removed, matching Path.resolve.
        assert_eq!(
            strip_generated_extended_prefix("C:\\work", "\\\\?\\C:\\work".to_string()),
            "C:\\work"
        );
        // UNC: \\?\UNC\server\share collapses to \\server\share.
        assert_eq!(
            strip_generated_extended_prefix(
                "\\\\server\\share\\dir",
                "\\\\?\\UNC\\server\\share\\dir".to_string()
            ),
            "\\\\server\\share\\dir"
        );
        // Caller-supplied \\?\ prefix is preserved verbatim.
        assert_eq!(
            strip_generated_extended_prefix("\\\\?\\C:\\work", "\\\\?\\C:\\work".to_string()),
            "\\\\?\\C:\\work"
        );
        // Non-prefixed results pass through unchanged.
        assert_eq!(
            strip_generated_extended_prefix("C:\\work", "C:\\work".to_string()),
            "C:\\work"
        );
    }
}
