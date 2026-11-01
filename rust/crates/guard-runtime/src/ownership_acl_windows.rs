//! `ownership-acl`'s `windows-probe` and `windows-file-probe` ops run the
//! pinned PowerShell ACL probe themselves, as `mdm/acl.py` did before them,
//! and decide with the same rules as `windows-verify`.
//!
//! The probe gets the payload as Base64-encoded JSON, so no protected path is
//! spelled on its command line, and runs from `System32` with a fixed
//! environment. A probe that cannot start, fails, overruns its time or output,
//! or prints anything but JSON reports `ownership_acl_probe_failed`.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::Value;

use super::{payload_json, probe_failed, windows_verify, PayloadItem, Verdict};

const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_POLL: Duration = Duration::from_millis(5);
const MAX_PROBE_OUTPUT_BYTES: usize = 1024 * 1024;

const SCRIPT_HEAD: &str = concat!(
    "$ErrorActionPreference='Stop';",
    "$items=ConvertFrom-Json([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('",
);
const SCRIPT_TAIL: &str = concat!(
    "')));",
    "$out=@();foreach($item in $items){",
    "if(-not(Test-Path -LiteralPath $item.path)){$out+=@{Name=$item.name;Kind=$item.kind;",
    "ExpectedContainer=$item.expectedContainer;Leaf=$item.leaf;Exists=$false};continue};",
    "$acl=Get-Acl -LiteralPath $item.path;",
    "$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;",
    "$rawRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|",
    "Select-Object -First 257);",
    "$truncated=$rawRules.Count -gt 256;",
    "$rules=@($rawRules|Select-Object -First 256|ForEach-Object{",
    "$rights=if($item.kind -eq 'registry'){[int64]$_.RegistryRights}else{[int64]$_.FileSystemRights};",
    "@{Sid=$_.IdentityReference.Value;Type=$_.AccessControlType.ToString();Rights=$rights;",
    "Propagation=$_.PropagationFlags.ToString()}});",
    "$raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0);",
    "$target=if($item.kind -eq 'registry'){$null}else{Get-Item -LiteralPath $item.path -Force};",
    "$attributes=if($null -eq $target){0}else{[int64]$target.Attributes};",
    "$container=if($item.kind -eq 'registry'){$true}else{[bool]$target.PSIsContainer};",
    "$out+=@{Name=$item.name;Kind=$item.kind;ExpectedContainer=$item.expectedContainer;Leaf=$item.leaf;",
    "Exists=$true;Owner=$owner;Rules=$rules;Truncated=$truncated;",
    "Attributes=$attributes;Container=$container;NullDacl=($null -eq $raw.DiscretionaryAcl)}};",
    "$out|ConvertTo-Json -Compress -Depth 6",
);

/// Runs the probe program; tests stand in for the real PowerShell.
pub(super) trait Runner {
    /// Standard output of a run that exited with status zero.
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Vec<u8>>;
}

/// The real PowerShell, bounded by a wall clock.
pub(super) struct SystemRunner {
    pub(super) timeout: Duration,
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self {
            timeout: PROBE_TIMEOUT,
        }
    }
}

impl Runner for SystemRunner {
    fn run(
        &mut self,
        program: &str,
        arguments: &[&str],
        cwd: &str,
        environment: &[(&str, &str)],
    ) -> io::Result<Vec<u8>> {
        run_bounded(program, arguments, cwd, environment, self.timeout)
    }
}

/// Probe every payload item and classify the rows. The Windows directory
/// comes from the kernel by way of the caller and must be drive-rooted
/// (`C:\` or `C:/`); a drive-relative `C:Windows` names a directory under
/// that drive's current directory, not a fixed one.
pub(super) fn probe(
    payload: Result<Vec<PayloadItem>, ()>,
    windows_directory: &str,
    runner: &mut impl Runner,
) -> Verdict {
    let Ok(payload) = payload else {
        return probe_failed();
    };
    let mut chars = windows_directory.chars();
    let drive_rooted = chars
        .next()
        .is_some_and(|letter| letter.is_ascii_alphabetic())
        && chars.next() == Some(':')
        && matches!(chars.next(), Some('\\' | '/'));
    if !drive_rooted {
        return probe_failed();
    }
    let items: Vec<Value> = payload.iter().map(payload_json).collect();
    let Ok(items) = serde_json::to_vec(&items) else {
        return probe_failed();
    };
    let script = format!(
        "{SCRIPT_HEAD}{}{SCRIPT_TAIL}",
        base64::engine::general_purpose::STANDARD.encode(items)
    );
    let system_directory = nt_join(windows_directory, "System32");
    let powershell = format!(r"{system_directory}\WindowsPowerShell\v1.0\powershell.exe");
    let comspec = format!(r"{system_directory}\cmd.exe");
    let environment = [
        ("ComSpec", comspec.as_str()),
        ("SystemRoot", windows_directory),
        ("WINDIR", windows_directory),
    ];
    let arguments = ["-NoProfile", "-NonInteractive", "-Command", script.as_str()];
    let Ok(stdout) = runner.run(&powershell, &arguments, &system_directory, &environment) else {
        return probe_failed();
    };
    match serde_json::from_slice::<Value>(&stdout) {
        Ok(rows) => windows_verify(Ok(payload), rows),
        Err(_) => probe_failed(),
    }
}

/// `ntpath.join(base, name)` for a drive-rooted `base` and a plain `name`.
fn nt_join(base: &str, name: &str) -> String {
    if base.ends_with(['\\', '/']) || base.len() == 2 {
        format!("{base}{name}")
    } else {
        format!("{base}\\{name}")
    }
}

/// One probe run with no shell, null standard input and error, a wall clock
/// (15 s outside tests) and at most 1 MiB of standard output.
fn run_bounded(
    program: &str,
    arguments: &[&str],
    cwd: &str,
    environment: &[(&str, &str)],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("probe stdout unavailable"));
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(MAX_PROBE_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(PROBE_POLL);
    };
    // A descendant may hold the pipe open; wait only for what is left of the
    // budget and leave the reader behind after that.
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if bytes.len() > MAX_PROBE_OUTPUT_BYTES {
        return Err(io::Error::other("probe output exceeded"));
    }
    if !status.success() {
        return Err(io::Error::other("probe failed"));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "ownership_acl_windows_tests.rs"]
mod tests;
