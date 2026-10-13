use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Attribute inspection never invokes clean/smudge/process filters. Check every
// tracked and untracked path, or only the `named` operands when the command
// reads nothing else; a global filter definition alone cannot execute.
#[allow(clippy::too_many_arguments)]
pub(super) fn unused(
    binary: &Path,
    leading: &[String],
    cwd: &Path,
    home: &Path,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    deadline: Instant,
    named: &[&str],
    repository_optional: bool,
) -> Option<bool> {
    let query = |arguments: &[&str], input: Option<Vec<u8>>, root: Option<&Path>| {
        let mut command = Command::new(binary);
        command.env_clear();
        #[cfg(windows)]
        for key in ["SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        if let Some(directory) = environment.and_then(|value| value.xdg_config_home.as_deref()) {
            command.env("XDG_CONFIG_HOME", directory);
        } else if environment.is_none() {
            if let Some(directory) = std::env::var_os("XDG_CONFIG_HOME") {
                command.env("XDG_CONFIG_HOME", directory);
            }
        }
        if environment.is_some_and(|value| value.git_config_no_system) {
            command.env("GIT_CONFIG_NOSYSTEM", "1");
        }
        command
            .env("HOME", home)
            .env("USERPROFILE", home)
            .current_dir(cwd)
            .args(leading)
            .args([
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
            ]);
        if let Some(root) = root {
            command.arg("-C").arg(root);
        }
        command.args(arguments);
        bounded_output(command, input, deadline)
    };
    if !named.is_empty() {
        // Operands resolve against the caller's directory. A path outside the
        // work tree makes check-attr fail, which keeps the command reviewed.
        let mut batch = Vec::new();
        for path in named {
            if path.is_empty() || path.contains('\0') || path.len() > 4096 {
                return None;
            }
            batch.extend_from_slice(path.as_bytes());
            batch.push(0);
        }
        let attributes = query(
            &["check-attr", "-z", "--stdin", "filter"],
            Some(batch.clone()),
            None,
        )?;
        return filters_unset(&attributes, &batch);
    }
    let Some(root) = query(&["rev-parse", "--show-toplevel"], None, None) else {
        // `git status` outside any repository stops during repository setup,
        // before it reads attributes or starts a filter. Both discovery
        // queries failing is that case; a bare repository or a git directory
        // still answers `--git-dir` and stays unproven.
        // A probe cut off by the deadline proves nothing.
        return (repository_optional
            && Instant::now() < deadline
            && query(&["rev-parse", "--git-dir"], None, None).is_none()
            && query(&["rev-parse", "--is-inside-work-tree"], None, None).is_none())
        .then_some(true);
    };
    let root = std::str::from_utf8(&root).ok()?.strip_suffix('\n')?;
    if root.len() > 4096 || root.chars().any(char::is_control) {
        return None;
    }
    let root = std::fs::canonicalize(root).ok()?;
    let paths = query(
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        None,
        Some(&root),
    )?;
    if paths.is_empty() {
        return Some(true);
    }
    if paths.last() != Some(&0) {
        return None;
    }
    // Untracked nested repositories and linked worktrees are listed as `dir/`.
    // Status reports them as one untracked entry and never descends into them,
    // so they cannot run filters. Tracked gitlinks (mode 160000) are listed
    // without a trailing slash and can make status inspect another repository,
    // whose filter configuration this proof does not cover.
    let mut covered = Vec::with_capacity(paths.len());
    for path in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if Instant::now() >= deadline {
            return None;
        }
        if path.ends_with(b"/") {
            continue;
        }
        let candidate = root.join(std::str::from_utf8(path).ok()?);
        if candidate.is_dir() && candidate.join(".git").exists() {
            return Some(false);
        }
        covered.extend_from_slice(path);
        covered.push(0);
    }
    let paths = covered;
    if paths.is_empty() {
        return Some(true);
    }
    // Attribute output repeats each path plus two fields. Batch by the
    // expected response size while retaining the per-query output cap.
    const BATCH_BYTES: usize = 512 * 1024;
    let mut offset = 0;
    let mut batches = 0;
    while offset < paths.len() {
        if Instant::now() >= deadline || batches >= 64 {
            return None;
        }
        let start = offset;
        let mut expected_bytes = 0;
        for path in paths[start..].split(|byte| *byte == 0) {
            if path.is_empty() {
                break;
            }
            let cost = path.len().checked_add(20)?;
            if cost > BATCH_BYTES {
                return None;
            }
            if expected_bytes + cost > BATCH_BYTES {
                break;
            }
            expected_bytes += cost;
            offset += path.len() + 1;
        }
        if offset == start {
            return None;
        }
        let batch = &paths[start..offset];
        let attributes = query(
            &["check-attr", "-z", "--stdin", "filter"],
            Some(batch.to_vec()),
            Some(&root),
        )?;
        if !filters_unset(&attributes, batch)? {
            return Some(false);
        }
        batches += 1;
    }
    Some(true)
}

/// Parse `check-attr -z filter` output for exactly the paths in `batch`.
fn filters_unset(attributes: &[u8], batch: &[u8]) -> Option<bool> {
    let mut fields = attributes.split(|byte| *byte == 0);
    for path in batch
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if fields.next()? != path || fields.next()? != b"filter" {
            return None;
        }
        if !matches!(fields.next()?, b"unspecified" | b"unset") {
            return Some(false);
        }
    }
    if fields.next()? != b"" || fields.next().is_some() {
        return None;
    }
    Some(true)
}

fn bounded_output(
    mut command: Command,
    input: Option<Vec<u8>>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    const LIMIT: u64 = super::super::git_probe::LISTING_LIMIT;
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (output_sender, output_receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take(LIMIT + 1)
            .read_to_end(&mut output)
            .ok()
            .and_then(|_| (output.len() <= LIMIT as usize).then_some(output));
        let _ = output_sender.send(result);
    });
    let writer = input.map(|input| {
        let mut stdin = child.stdin.take();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = stdin
                .as_mut()
                .and_then(|stdin| stdin.write_all(&input).ok());
            let _ = sender.send(result);
        });
        receiver
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = output_receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()??;
    if let Some(writer) = writer {
        writer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()??;
    }
    status?.success().then_some(output)
}
