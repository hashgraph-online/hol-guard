//! Which programs load code a launch identity cannot bind.

use std::sync::OnceLock;

use regex::Regex;

/// Interpreters, shells, task runners and package managers.
const MUTABLE_CODE_LAUNCHERS: &[&str] = &[
    ".", "source", "sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "node", "bun", "deno",
    "ruby", "perl", "npm", "npx", "pnpm", "pnpx", "yarn", "bunx", "make", "just", "task", "cargo",
    "uv", "uvx", "pipx",
];

/// Further interpreters, task runners and wrappers whose launch identity does
/// not bind the code they load or run.
const EXTRA_MUTABLE_LAUNCHERS: &[&str] = &[
    "nodejs",
    "php",
    "go",
    "tsx",
    "ts-node",
    "vite-node",
    "jiti",
    "esno",
    "babel-node",
    "nodemon",
    "zx",
    "docker",
    "podman",
    "git",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "xargs",
    "parallel",
    "env",
    "sudo",
    "doas",
    "nohup",
    "timeout",
    "watch",
    "osascript",
    "pwsh",
    "powershell",
    "java",
    "dotnet",
    "lua",
    "rscript",
    "julia",
    "swift",
    "r",
    "terraform",
    "tofu",
    "terragrunt",
    "pulumi",
    "ansible",
    "ansible-playbook",
    "pytest",
    "py.test",
    "tox",
    "nox",
    "jest",
    "vitest",
    "mocha",
    "rake",
    "gradle",
    "mvn",
    "sed",
];

/// Commands that delete, overwrite, move or reach the network.
const DESTRUCTIVE_EXECUTABLES: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "dd", "mv", "chmod", "chown", "truncate", "mkfs", "kill",
    "pkill", "killall", "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "telnet",
    "ftp",
];

/// Windows shells, script hosts, installers and the system binaries that run
/// code or commands named elsewhere (scheduled tasks, registry, downloads).
/// Git for Windows adds `winpty`, `cygstart` and the Tcl/Tk hosts (`tclsh`,
/// `wish`, including versioned `tclsh86` / `wish86`). They are consulted on
/// Windows only.
const WINDOWS_LAUNCHERS: &[&str] = &[
    "cmd",
    "powershell",
    "powershell_ise",
    "pwsh",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "msiexec",
    "wsl",
    "wslhost",
    "git-bash",
    "mintty",
    "busybox",
    "winpty",
    "cygstart",
    "tclsh",
    "wish",
    "wt",
    "py",
    "pyw",
    "msbuild",
    "csc",
    "vbc",
    "jsc",
    "installutil",
    "regasm",
    "regsvcs",
    "winget",
    "choco",
    "scoop",
    "nuget",
    "psexec",
    "psexec64",
    "schtasks",
    "at",
    "reg",
    "regedit",
    "certutil",
    "bitsadmin",
    "conhost",
    "explorer",
    "start",
    "runas",
    "forfiles",
    "wmic",
    "cmstp",
    "msdt",
    "pcalua",
    "hh",
    "control",
    "odbcconf",
    "mavinject",
    "msxsl",
];

/// Windows commands that delete, overwrite, change access or system state,
/// or reach the network. They are consulted on Windows only.
const WINDOWS_DESTRUCTIVE: &[&str] = &[
    "del", "erase", "rd", "move", "ren", "rename", "copy", "robocopy", "xcopy", "format",
    "diskpart", "cipher", "sdelete", "takeown", "icacls", "cacls", "attrib", "taskkill", "tskill",
    "shutdown", "setx", "cmdkey", "bcdedit", "vssadmin", "wbadmin", "wevtutil", "netsh", "net",
    "net1", "sc", "mklink", "fsutil", "compact",
];

const FILE_BACKED_PROGRAM_COMMANDS: &[&str] = &["sed", "grep", "egrep", "fgrep", "rg"];
const FIND_EXEC_OPTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// Commands whose reuse is bound to the argv alone.
const DIRECT_REUSABLE_COMMANDS: &[&str] = &[
    "cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "stat", "wc", "base64", "xxd",
    "od", "hexdump", "strings",
];

pub(super) fn is_destructive(name: &str) -> bool {
    DESTRUCTIVE_EXECUTABLES.contains(&name)
        || (cfg!(windows) && WINDOWS_DESTRUCTIVE.contains(&name))
}

pub(super) fn is_direct_reusable(name: &str) -> bool {
    DIRECT_REUSABLE_COMMANDS.contains(&name)
}

pub(super) fn is_code_launcher(name: &str) -> bool {
    MUTABLE_CODE_LAUNCHERS.contains(&name) || is_python_launcher(name)
}

pub(super) fn is_python_launcher(name: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            Regex::new(r"(?i)^pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?\z").expect("static pattern")
        })
        .is_match(name)
}

pub(super) fn is_mutable_launcher(name: &str) -> bool {
    is_code_launcher(name)
        || EXTRA_MUTABLE_LAUNCHERS.contains(&name)
        || (cfg!(windows) && (WINDOWS_LAUNCHERS.contains(&name) || is_tcl_wish_host(name)))
}

/// Git for Windows names its Tcl/Tk hosts `tclsh86` and `wish86` (and the
/// threaded `tclsh86t` / `wish86t` builds). The unversioned names are in
/// `WINDOWS_LAUNCHERS`; this matches the versioned spellings too.
fn is_tcl_wish_host(name: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            Regex::new(r"(?i)^(?:tclsh|wish)\d*(?:\.\d+)*t?(?:\.exe)?\z").expect("static pattern")
        })
        .is_match(name)
}

/// `_loads_unbound_code`.
pub(super) fn loads_unbound_code(name: &str, arguments: &[String]) -> bool {
    if is_mutable_launcher(name) {
        return true;
    }
    if name == "find"
        && arguments
            .iter()
            .any(|argument| FIND_EXEC_OPTIONS.contains(&argument.as_str()))
    {
        return true;
    }
    if FILE_BACKED_PROGRAM_COMMANDS.contains(&name) && uses_file_backed_program(arguments) {
        return true;
    }
    name == "rg" && rg_runs_preprocessor(arguments)
}

/// Whether a ripgrep launch runs a mutable preprocessor.
pub(super) fn rg_runs_preprocessor(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| token == "--pre" || token.starts_with("--pre="))
}

/// Whether a program or pattern is loaded from a mutable file instead of argv.
pub(super) fn uses_file_backed_program(tokens: &[String]) -> bool {
    let mut skip_next = false;
    for token in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(token.as_str(), "-f" | "--file" | "--fi" | "--fil") {
            return true;
        }
        if token.starts_with("--file=") || token.starts_with("--fi=") || token.starts_with("--fil=")
        {
            return true;
        }
        if matches!(token.as_str(), "-e" | "--expression" | "--regexp") {
            skip_next = true;
            continue;
        }
        if token.starts_with('-') && !token.starts_with("--") && token != "-" {
            let cluster: Vec<char> = token.chars().skip(1).collect();
            for (index, flag) in cluster.iter().enumerate() {
                if *flag == 'e' {
                    skip_next = index == cluster.len() - 1;
                    break;
                }
                if *flag == 'f' {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_tcl_wish_host;

    #[test]
    fn git_for_windows_tcl_hosts_match_versioned_names() {
        for name in [
            "tclsh",
            "tclsh86",
            "tclsh8.6",
            "tclsh86t",
            "TCLSH86.EXE",
            "wish",
            "wish86",
            "wish8.6",
            "wish86.exe",
        ] {
            assert!(is_tcl_wish_host(name), "{name}");
        }
        for name in ["tcl", "wishful", "tclsh86tx", "python", "winpty"] {
            assert!(!is_tcl_wish_host(name), "{name}");
        }
    }
}
