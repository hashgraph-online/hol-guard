//! Read-only discovery: no transcript reads, environment enumeration, or signals.
use crate::{Adapter, Agent, AgentOrigin, AgentState, Controls, Coverage, MAX_AGENTS};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const HARNESSES: &[(&str, &str, &str)] = &[
    ("codex", "Codex", "codex"),
    ("claude-code", "Claude Code", "claude"),
    ("gemini", "Gemini CLI", "gemini"),
    ("opencode", "OpenCode", "opencode"),
    ("copilot", "Copilot CLI", "copilot"),
    ("aider", "Aider", "aider"),
    ("pi", "Pi", "pi"),
    ("omp", "Oh My Pi", "omp"),
    ("hermes", "Hermes", "hermes"),
];

#[derive(Clone, Debug)]
struct Process {
    pid: u32,
    parent: Option<u32>,
    started: u64,
    executable: PathBuf,
    // Only the entry point and first command are used; never published.
    arguments: Vec<String>,
    workspace: Option<String>,
}

fn basename(path: &Path) -> Option<String> {
    path.file_name()?
        .to_str()
        .map(|n| n.trim_end_matches(".exe").to_ascii_lowercase())
}

fn identify(process: &Process) -> Option<(&'static str, &'static str)> {
    let binary = basename(&process.executable)?;
    let in_claude_versions = process
        .executable
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        == Some("versions")
        && process
            .executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            == Some("claude");
    let name = if in_claude_versions {
        "claude"
    } else {
        binary.as_str()
    };
    let direct = HARNESSES
        .iter()
        .find(|(_, _, candidate)| *candidate == name);
    if let Some((id, label, _)) = direct {
        // Configuration and diagnostic commands are not agent runs.
        if process.arguments.get(1).is_some_and(|arg| {
            matches!(
                arg.as_str(),
                "--help"
                    | "-h"
                    | "--version"
                    | "-V"
                    | "mcp"
                    | "auth"
                    | "login"
                    | "logout"
                    | "update"
                    | "doctor"
            )
        }) {
            return None;
        }
        return Some((id, label));
    }
    if matches!(binary.as_str(), "node" | "bun" | "python" | "python3")
        || binary.starts_with("python3.")
    {
        let entry = process.arguments.get(1)?.replace('\\', "/");
        // Match installed entry-point locations, never a prompt or an arbitrary
        // path whose name merely contains an agent's name.
        for (package, id, label) in [
            ("/@openai/codex/", "codex", "Codex"),
            ("/@anthropic-ai/claude-code/", "claude-code", "Claude Code"),
            ("/@google/gemini-cli/", "gemini", "Gemini CLI"),
            ("/@github/copilot/", "copilot", "Copilot CLI"),
            ("/@mariozechner/pi-coding-agent/", "pi", "Pi"),
        ] {
            if entry.contains(package) {
                return Some((id, label));
            }
        }
    }
    None
}

fn project(processes: Vec<Process>, now: u64) -> (Vec<Agent>, bool) {
    let identified: BTreeMap<u32, (&Process, &str, &str)> = processes
        .iter()
        .filter_map(|p| identify(p).map(|(h, label)| (p.pid, (p, h, label))))
        .collect();
    let by_pid: BTreeMap<u32, &Process> = processes.iter().map(|p| (p.pid, p)).collect();
    let mut agents = Vec::new();
    for (pid, (process, harness, label)) in &identified {
        // A native binary under the same harness's JS launcher is one agent.
        // Do not collapse independently launched nested agents or all children
        // merely because an ancestor happens to be another coding agent.
        let wrapper_parent = process
            .parent
            .and_then(|parent| by_pid.get(&parent))
            .is_some_and(|parent| {
                identified
                    .get(&parent.pid)
                    .is_some_and(|(_, h, _)| h == harness)
                    && basename(&parent.executable)
                        .is_some_and(|n| matches!(n.as_str(), "node" | "bun"))
                    && !basename(&process.executable)
                        .is_some_and(|n| matches!(n.as_str(), "node" | "bun"))
            });
        if wrapper_parent {
            continue;
        }
        agents.push(Agent {
            id: format!("process-{pid}-{}", process.started),
            harness: (*harness).into(),
            label: (*label).into(),
            origin: AgentOrigin::Observed,
            state: AgentState::Observed,
            workspace: process.workspace.clone(),
            task: None,
            model: None,
            pid: Some(*pid),
            started_at_ms: process.started.saturating_mul(1000),
            updated_at_ms: now,
            controls: Controls::default(),
            detail: "Running on this computer. Task and controls belong to its app.".into(),
            activity: None,
            revision: 0,
            queued: 0,
            context_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
            parent_pid: process.parent,
        });
    }
    let limited = agents.len() > MAX_AGENTS;
    agents.truncate(MAX_AGENTS);
    (agents, limited)
}

pub fn discover(now: u64) -> (Vec<Agent>, Coverage) {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .with_cwd(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
    let owner = sysinfo::get_current_pid()
        .ok()
        .and_then(|pid| system.process(pid))
        .and_then(|process| process.user_id())
        .cloned();
    let Some(owner) = owner else {
        return (
            Vec::new(),
            Coverage {
                state: "unavailable".into(),
                limited: false,
                detail: "Guard could not verify which processes belong to this account.".into(),
            },
        );
    };
    let processes = system
        .processes()
        .iter()
        .filter_map(|(pid, p)| {
            if p.user_id() != Some(&owner)
                || matches!(
                    p.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            {
                return None;
            }
            Some(Process {
                pid: pid.as_u32(),
                parent: p.parent().map(|p| p.as_u32()),
                started: p.start_time(),
                executable: p.exe()?.to_path_buf(),
                arguments: p
                    .cmd()
                    .iter()
                    .take(3)
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect(),
                workspace: p.cwd().map(|p| p.to_string_lossy().into_owned()),
            })
        })
        .collect();
    let (agents, limited) = project(processes, now);
    (agents, Coverage { state: "ready".into(), limited,
        detail: "Recognized CLI processes visible to your account. Apps may share a process across sessions; private or unsupported agents may be missing.".into() })
}

/// Resolve only a fixed adapter name in absolute PATH entries. A workspace or
/// browser request cannot supply an executable, PATH override, or command.
pub(crate) fn executable(harness: &str, search_path: &std::ffi::OsStr) -> Option<PathBuf> {
    let (_, _, binary) = HARNESSES.iter().find(|(id, _, _)| *id == harness)?;
    resolve(binary, Some(search_path))
}

fn resolve(binary: &str, search_path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let mut seen = BTreeSet::new();
    for folder in std::env::split_paths(search_path?) {
        if !folder.is_absolute() || !seen.insert(folder.clone()) {
            continue;
        }
        let names: &[String] = if cfg!(windows) {
            &[
                format!("{binary}.exe"),
                format!("{binary}.cmd"),
                format!("{binary}.bat"),
            ]
        } else {
            &[binary.to_owned()]
        };
        for name in names {
            let file = folder.join(name);
            let Ok(real) = file.canonicalize() else {
                continue;
            };
            let Ok(metadata) = real.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Some(real);
        }
    }
    None
}

pub fn installed_adapters(search_path: &std::ffi::OsStr) -> Vec<Adapter> {
    HARNESSES.iter().map(|(id, label, _)| {
        let installed = executable(id, search_path).is_some();
        let supported = matches!(*id, "codex" | "claude-code");
        Adapter { id: (*id).into(), label: (*label).into(), installed, launch_supported: installed && supported,
            detail: if installed && supported { "Run tasks, queue follow-ups, interrupt, and stop. Uses your CLI configuration and permissions." }
                else if installed { "Visible in Swarm when running. Continue working in its own app." }
                else { "Install and sign in to this CLI to use it on this computer." }.into() }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn process(pid: u32, exe: &str, args: &[&str]) -> Process {
        Process {
            pid,
            parent: None,
            started: 123,
            executable: exe.into(),
            arguments: args.iter().map(|s| (*s).into()).collect(),
            workspace: Some("/project".into()),
        }
    }

    #[test]
    fn discovers_entry_points_without_matching_prompt_text() {
        assert!(identify(&process(1, "/bin/sh", &["sh", "-c", "codex"])).is_none());
        assert!(identify(&process(1, "/bin/node", &["node", "/work/claude-steal.js"])).is_none());
        assert!(identify(&process(1, "/usr/bin/codex", &["codex", "--help"])).is_none());
        assert_eq!(
            identify(&process(
                1,
                "/bin/node",
                &["node", "/opt/node_modules/@openai/codex/bin/codex.js"]
            )),
            Some(("codex", "Codex"))
        );
    }

    #[test]
    fn wrapper_is_one_agent_but_nested_agents_remain_separate() {
        let wrapper = process(
            20,
            "/bin/node",
            &["node", "/opt/node_modules/@openai/codex/bin/codex.js"],
        );
        let mut child = process(21, "/opt/codex", &["codex"]);
        child.parent = Some(20);
        let mut nested = process(22, "/opt/codex", &["codex"]);
        nested.parent = Some(21);
        let (agents, limited) = project(vec![wrapper, child, nested], 5000);
        assert_eq!(agents.len(), 2);
        assert!(!limited);
        assert!(agents
            .iter()
            .all(|a| !a.controls.stop && !a.controls.message && a.task.is_none()));
    }

    #[test]
    fn reused_pid_has_a_new_identity_and_output_is_bounded() {
        let a = process(1, "/opt/codex", &["codex"]);
        let mut b = a.clone();
        b.started += 1;
        assert_ne!(project(vec![a], 0).0[0].id, project(vec![b], 0).0[0].id);
        let (agents, limited) = project(
            (1..=300)
                .map(|p| process(p, "/opt/codex", &["codex"]))
                .collect(),
            0,
        );
        assert_eq!(agents.len(), MAX_AGENTS);
        assert!(limited);
        assert!(resolve("codex", Some(std::ffi::OsStr::new(".:relative"))).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolves_cmd_launchers_installed_by_npm() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("codex.cmd"), "@echo off\r\n").unwrap();
        let path = std::ffi::OsString::from(directory.path());
        assert_eq!(
            resolve("codex", Some(&path)),
            Some(directory.path().join("codex.cmd").canonicalize().unwrap())
        );
    }
}
