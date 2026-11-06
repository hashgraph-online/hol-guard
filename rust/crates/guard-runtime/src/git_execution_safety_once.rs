//! The state a one-time approval of `git push origin <branch>` is bound to.
//!
//! `push_origin` lets a push to the native GitHub HTTPS origin run without a
//! review. A push to any other ssh or credential-free https origin is still
//! reviewed. When the user approves one, its retry may reuse the approval only
//! while the same checks still pass and every input they rest on is unchanged:
//! the trusted Git, its effective configuration and the files it came from,
//! the transport program, and the commit the branch names. Each fact comes
//! from a probe of that Git, never from parsing its configuration here.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use guard_contracts::GitExecutionSafetyRequestV1;
use serde_json::{json, Value};

use super::Context;
use crate::git_execution_safety_binary::{
    binary_path_is_trusted, resolve_trusted_git, which_for_cwd,
};
use crate::git_execution_safety_config::{parse_null_config, rewritten_remote_url};
use crate::git_execution_safety_probe::{ProbeOutput, Prober};
use crate::guard_store_wfcap_frame::sha256_hex;

/// ssh keywords that run or load a local program the binding cannot pin.
/// `XAuthLocation` is not one: ssh runs xauth only for X11 forwarding, which
/// `ForwardX11` turns on, so that keyword is refused instead.
const SSH_PROGRAM_KEYWORDS: [&str; 5] = [
    "proxycommand",
    "localcommand",
    "knownhostscommand",
    "pkcs11provider",
    "securitykeyprovider",
];
/// The include line distributions ship in the system ssh config. Every file
/// in that folder is read and checked, whichever glob names it.
const SYSTEM_SSH_INCLUDES: [&str; 2] = [
    "include /etc/ssh/ssh_config.d/*.conf",
    "include /etc/ssh/ssh_config.d/*",
];
const SYSTEM_SSH_CONFIG: &str = "/etc/ssh/ssh_config";
const SYSTEM_SSH_CONFIG_DIR: &str = "/etc/ssh/ssh_config.d";
const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_PROGRAM_BYTES: u64 = 256 * 1_048_576;
const MAX_SSH_FILES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Ssh,
    Https,
}

/// The digestible state of a push the native checks would pass but for its
/// non-GitHub origin, or `None` when any check or probe fails.
pub(crate) fn push_once_state(request: &GitExecutionSafetyRequestV1) -> Option<Value> {
    if cfg!(windows) {
        return None;
    }
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home);
    if !cwd.is_absolute() || !home.is_absolute() {
        return None;
    }
    let git = resolve_trusted_git(cwd, &request.environment, home, &request.groups)?;
    Context {
        request,
        cwd: cwd.to_path_buf(),
        home: home.to_path_buf(),
        git,
    }
    .push_once()
}

impl Context<'_> {
    fn push_once(&self) -> Option<Value> {
        let branch = self.request.branch.as_deref()?;
        if !self.push_origin(&|url| transport(url).is_some()) {
            return None;
        }
        let repository = fs::canonicalize(&self.cwd).ok()?;
        let prober = self.prober(&repository);
        let text = |arguments: &[&str]| probe_text(&prober, arguments);
        // The effective configuration, and every file it came from or that
        // Git would read once created.
        let shown = text(&["config", "--null", "--list", "--show-origin"])?;
        let mut files = BTreeMap::new();
        for origin in config_origins(&shown, &repository)? {
            let digest = file_digest(&origin, MAX_CONFIG_BYTES)?;
            files.insert(origin, digest);
        }
        for variable in ["GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"] {
            for path in text(&["var", variable])?
                .lines()
                .filter(|line| !line.is_empty())
            {
                files.insert(path.to_owned(), file_digest(path, MAX_CONFIG_BYTES)?);
            }
        }
        let config = parse_null_config(&text(&["config", "--null", "--list"])?)?;
        let url = rewritten_remote_url(&config, config.get("remote.origin.url")?.first()?)?;
        let transport_state = match transport(&url)? {
            Transport::Ssh => self.ssh_state(&repository)?,
            Transport::Https => {
                let exec_path = text(&["--exec-path"])?;
                let helper = Path::new(exec_path.trim()).join("git-remote-https");
                json!({"helper": self.trusted_program(&helper, &repository)?})
            }
        };
        let commit = text(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("refs/heads/{branch}^{{commit}}"),
        ])?;
        let head = text(&["symbolic-ref", "--quiet", "HEAD"])?;
        Some(json!({
            "kind": "git-push-once.v1",
            "git": self.trusted_program(&self.git, &repository)?,
            "repository": repository,
            "branch": branch,
            "head": head.trim(),
            "commit": commit.trim(),
            "remote": url,
            "config": sha256_hex(shown.as_bytes()),
            "config_files": files,
            "transport": transport_state,
        }))
    }

    /// A program's resolved path, which must be trusted, and its digest.
    fn trusted_program(&self, path: &Path, repository: &Path) -> Option<Value> {
        let resolved = fs::canonicalize(path).ok()?;
        if !binary_path_is_trusted(&resolved, repository, &self.home, &self.request.groups) {
            return None;
        }
        let digest = file_digest(&resolved.to_string_lossy(), MAX_PROGRAM_BYTES)?;
        Some(json!({"path": resolved, "sha256": digest}))
    }

    /// The `ssh` the push launches and every client config file it reads.
    fn ssh_state(&self, repository: &Path) -> Option<Value> {
        let ssh = which_for_cwd("ssh", repository, self.environment(), &self.home)?;
        let program = self.trusted_program(&ssh, repository)?;
        let user = self.home.join(".ssh/config").to_string_lossy().into_owned();
        let mut paths = vec![(user, false), (SYSTEM_SSH_CONFIG.to_owned(), true)];
        paths.extend(
            directory_files(SYSTEM_SSH_CONFIG_DIR)?
                .into_iter()
                .map(|path| (path, false)),
        );
        let mut config = BTreeMap::new();
        for (path, allows_system_include) in paths {
            if Path::new(&path).is_file() {
                let data = read_bounded(&path, MAX_CONFIG_BYTES)?;
                ssh_config_runs_no_program(&String::from_utf8_lossy(&data), allows_system_include)
                    .then_some(())?;
            }
            let digest = file_digest(&path, MAX_CONFIG_BYTES)?;
            config.insert(path, digest);
        }
        Some(json!({"ssh": program, "config": config}))
    }
}

fn probe_text(prober: &Prober<'_>, arguments: &[&str]) -> Option<String> {
    prober
        .run(arguments)
        .filter(ProbeOutput::success)
        .and_then(|output| output.text().map(str::to_owned))
}

/// The files `git config --show-origin --null --list` names, resolved against
/// the repository. Any origin other than a file (a `command line:` value or
/// a `blob:`) fails closed.
fn config_origins(shown: &str, repository: &Path) -> Option<Vec<String>> {
    let fields: Vec<&str> = shown.split('\0').collect();
    let mut origins = Vec::new();
    for pair in fields.chunks(2) {
        let [origin, _entry] = pair else {
            if pair.iter().all(|field| field.is_empty()) {
                continue;
            }
            return None;
        };
        let path = origin.strip_prefix("file:")?;
        let path = Path::new(path);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            repository.join(path)
        };
        origins.push(path.to_string_lossy().into_owned());
    }
    Some(origins)
}

/// The transport a push URL selects, or `None` for one this cannot pin:
/// credentials in an https URL, a local path or `file://` (whose hooks run
/// here), `git://`, a `<helper>::` remote, or an option-shaped host or path.
fn transport(url: &str) -> Option<Transport> {
    if !url.bytes().all(|byte| byte.is_ascii_graphic()) || url.contains(['?', '#', '\\']) {
        return None;
    }
    if let Some(rest) = url.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/')?;
        let plain = !authority.is_empty()
            && !authority.contains('@')
            && !authority.starts_with('-')
            && !path.is_empty();
        return plain.then_some(Transport::Https);
    }
    let (authority, path) = if let Some(rest) = url.strip_prefix("ssh://") {
        rest.split_once('/')?
    } else if url.contains("://") || url.contains("::") || url.starts_with(['/', '.', '~', '-']) {
        return None;
    } else {
        // scp-like `[user@]host:path`: no slash before the first colon.
        let (authority, path) = url.split_once(':')?;
        if authority.contains('/') {
            return None;
        }
        (authority, path)
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let plain = !host.is_empty()
        && !host.starts_with('-')
        && !authority.starts_with('-')
        && !path.is_empty()
        && !path.starts_with('-');
    plain.then_some(Transport::Ssh)
}

/// OpenSSH strips double quotes when it splits a line, so the keywords are
/// compared without them: `"ProxyCommand"` is still `ProxyCommand`.
fn ssh_config_runs_no_program(text: &str, allows_system_include: bool) -> bool {
    text.lines().all(|line| {
        let line = line.trim().replace('"', "");
        if line.is_empty() || line.starts_with('#') {
            return true;
        }
        let words: Vec<String> = line
            .split(|character: char| character.is_whitespace() || character == '=')
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let keyword = words.first().map_or("", String::as_str);
        if keyword == "include" {
            return allows_system_include
                && SYSTEM_SSH_INCLUDES.contains(&words.join(" ").as_str());
        }
        let matches_exec = keyword == "match"
            && words
                .iter()
                .any(|word| word.trim_start_matches('!') == "exec");
        let forwards_x11 =
            keyword == "forwardx11" && words.get(1).is_none_or(|value| value != "no");
        !(SSH_PROGRAM_KEYWORDS.contains(&keyword) || matches_exec || forwards_x11)
    })
}

fn directory_files(directory: &str) -> Option<Vec<String>> {
    let Ok(entries) = fs::read_dir(directory) else {
        return (!Path::new(directory).exists()).then(Vec::new);
    };
    let mut names: Vec<String> = entries
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .ok()?;
    if names.len() > MAX_SSH_FILES {
        return None;
    }
    names.sort();
    Some(
        names
            .into_iter()
            .map(|name| {
                Path::new(directory)
                    .join(name)
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|path| Path::new(path).is_file())
            .collect(),
    )
}

fn read_bounded(path: &str, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > limit {
        return None;
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data).ok()?;
    (data.len() as u64 <= limit).then_some(data)
}

/// The digest of a file, `absent` when there is none, or `None` when it
/// exists but cannot be read within the bound.
fn file_digest(path: &str, limit: u64) -> Option<String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some("absent".to_owned()),
        Err(_) => None,
        Ok(_) => read_bounded(path, limit).map(|data| sha256_hex(&data)),
    }
}

#[cfg(all(test, unix))]
#[path = "git_execution_safety_once_tests.rs"]
mod tests;
