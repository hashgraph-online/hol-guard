//! `stable_mcp_server_identifier` for an OpenCode server, which a verified
//! `hol-guard::` companion's `--server-id` must equal: the digest of the
//! server's launch with every path spelled out of it.

use guard_command::command_option_parsing::python_is_alphabetic;
use guard_contracts::python_strip;
use sha2::{Digest, Sha256};

use crate::claude_guard_question::python_lower;
use crate::hook_env_stamp::json_string;

/// `_STABLE_SLASH_FLAG_TOKENS`: a leading-slash argument that is a flag.
const SLASH_FLAGS: [&str; 12] = [
    "/?",
    "/debug",
    "/dry-run",
    "/h",
    "/help",
    "/quiet",
    "/read-only",
    "/readonly",
    "/ro",
    "/safe",
    "/trace",
    "/verbose",
];
/// The keys `_looks_like_path_assignment` reads as naming a path.
const PATH_KEYS: [&str; 11] = [
    "cache",
    "config",
    "cwd",
    "dir",
    "directory",
    "file",
    "folder",
    "path",
    "root",
    "workspace",
    "workdir",
];

/// `stable_mcp_server_identifier` for an OpenCode server: the digest of its
/// launch with every path spelled out of it.
pub(crate) fn server_identifier(
    name: &str,
    scope: &str,
    command: &str,
    args: &[&str],
    transport: &str,
    mapped: bool,
) -> String {
    let scope = python_lower(python_strip(scope));
    let name = match python_lower(python_strip(name)) {
        stripped if stripped.is_empty() => "unnamed".to_owned(),
        stripped => stripped,
    };
    let quoted = |text: &str| json_string(text, true, mapped);
    let args: Vec<String> = args.iter().map(|arg| quoted(&stable_arg(arg))).collect();
    let payload = format!(
        "{{\"args\": [{}], \"command\": {}, \"harness\": \"opencode\", \"name\": {}, \"source_scope\": {}, \"transport\": {}}}",
        args.join(", "),
        quoted(&stable_command(command)),
        quoted(&name),
        quoted(&scope),
        quoted(transport),
    );
    let digest: String = Sha256::digest(payload.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("mcp_server:opencode:{scope}:{name}:{}", &digest[..20])
}

/// `_stable_arg_token`.
fn stable_arg(value: &str) -> String {
    if let Some((key, item)) = value.split_once('=') {
        if looks_like_path_assignment(key, item) || looks_like_path(item) {
            return format!("{key}=<path>");
        }
    }
    if looks_like_path(value) {
        return "<path>".to_owned();
    }
    value.to_owned()
}

/// `_looks_like_path_assignment`.
fn looks_like_path_assignment(key: &str, value: &str) -> bool {
    let key = python_lower(python_strip(key).trim_start_matches(['-', '/'])).replace('_', "-");
    PATH_KEYS.contains(&key.as_str()) && python_strip(value).replace('\\', "/").starts_with('/')
}

/// `_looks_like_path_token`.
fn looks_like_path(value: &str) -> bool {
    let normalized = python_strip(value).replace('\\', "/");
    if ["~/", "./", "../"]
        .iter()
        .any(|prefix| normalized.starts_with(*prefix))
    {
        return true;
    }
    if let Some(rest) = normalized.strip_prefix('/') {
        return rest.contains('/') || !SLASH_FLAGS.contains(&python_lower(&normalized).as_str());
    }
    let mut chars = normalized.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(first), Some(':'), Some('/')) if python_is_alphabetic(first)
    )
}

/// `_stable_command_name`: the lowered final component of the command, read
/// as this platform's `PurePath` reads it once backslashes are slashes.
fn stable_command(command: &str) -> String {
    let normalized = command.replace('\\', "/");
    let tail = if cfg!(windows) {
        windows_tail(&normalized)
    } else {
        normalized.as_str()
    };
    let name = tail
        .split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("");
    python_lower(name)
}

/// What follows the drive and root in `ntpath.splitroot`, for a path whose
/// separators are already slashes.
fn windows_tail(path: &str) -> &str {
    let mut chars = path.char_indices().skip(1);
    if let Some(rest) = path.strip_prefix("//") {
        let start = if path
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case("//?/UNC/"))
        {
            6
        } else {
            0
        };
        let Some(server_end) = rest[start..].find('/').map(|index| start + index) else {
            return "";
        };
        return match rest[server_end + 1..].find('/') {
            Some(index) => &rest[server_end + 1 + index + 1..],
            None => "",
        };
    }
    if let Some(rest) = path.strip_prefix('/') {
        return rest;
    }
    match (chars.next(), chars.next()) {
        (Some((_, ':')), Some((index, '/'))) => &path[index + 1..],
        (Some((index, ':')), _) => &path[index + 1..],
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::{looks_like_path, stable_arg, stable_command, windows_tail};

    #[test]
    fn the_windows_tail_follows_ntpath_splitroot() {
        assert_eq!(windows_tail("//server/share/x/y"), "x/y");
        assert_eq!(windows_tail("//?/UNC/server/share/z"), "z");
        assert_eq!(windows_tail("//?/unc/server/share/z"), "z");
        assert_eq!(windows_tail("//?/c:/z"), "z");
        assert_eq!(windows_tail("//server"), "");
        assert_eq!(windows_tail("//server/share"), "");
        assert_eq!(windows_tail("C:/a/b"), "a/b");
        assert_eq!(windows_tail("C:a"), "a");
        assert_eq!(windows_tail("/a"), "a");
        assert_eq!(windows_tail("rel/x"), "rel/x");
    }

    #[test]
    fn command_names_lose_their_directories_and_case() {
        assert_eq!(stable_command("C:\\Tools\\Node.EXE"), "node.exe");
        assert_eq!(stable_command("/usr/bin/"), "bin");
        assert_eq!(stable_command("a/."), "a");
        assert_eq!(stable_command(""), "");
    }

    #[test]
    fn path_arguments_are_spelled_out() {
        assert_eq!(stable_arg("--config=/srv/x.json"), "--config=<path>");
        assert_eq!(stable_arg("dir=/a"), "dir=<path>");
        assert_eq!(stable_arg("--Work_Dir= /q"), "--Work_Dir=<path>");
        assert_eq!(stable_arg("./rel"), "<path>");
        assert_eq!(stable_arg("C:/w"), "<path>");
        assert_eq!(stable_arg("/verbose/x"), "<path>");
        assert_eq!(stable_arg("/help"), "/help");
        assert_eq!(stable_arg("/HELP"), "/HELP");
        assert_eq!(stable_arg("name=value"), "name=value");
        assert!(!looks_like_path("1:/x"));
        assert!(looks_like_path("é:/x"));
    }
}
