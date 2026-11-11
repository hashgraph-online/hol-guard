use crate::adapter;
use crate::process::{Output, Process};
use crate::service::Registry;
use crate::AgentState;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) fn run(registry: Arc<Mutex<Registry>>, id: String) {
    loop {
        let Some((mut command, prompt, harness)) = prepare(&registry, &id) else {
            return;
        };
        let mut process = match Process::spawn(&mut command, prompt) {
            Ok(process) => process,
            Err(error) => {
                update(&registry, &id, |run| {
                    run.active = false;
                    run.agent.state = AgentState::Failed;
                    run.pending.clear();
                    run.event("error", format!("Could not start the CLI ({:?}). Check its installation and project directory.", error.kind()));
                    run.controls();
                });
                return;
            }
        };
        update(&registry, &id, |run| {
            run.agent.pid = Some(process.id());
            run.agent.state = AgentState::Running;
            run.agent.detail =
                "Working on the current turn. New instructions run after this turn.".into();
            run.agent.revision += 1;
            run.event("lifecycle", "CLI started.");
            run.controls();
        });
        let mut completed = false;
        let mut failed = false;
        let mut attention = false;
        let mut cancel;
        let mut ends = 0;
        let mut exited: Option<(Instant, bool)> = None;
        let mut usage = (0, 0);
        let mut decoder = adapter::Decoder::default();
        let started = Instant::now();
        loop {
            if let Ok(state) = registry.lock() {
                cancel = if state.shutdown {
                    2
                } else {
                    state.runs.get(&id).map_or(2, |r| r.cancel)
                };
            } else {
                cancel = 2;
            }
            if cancel != 0 {
                break;
            }
            if started.elapsed() > Duration::from_secs(24 * 60 * 60) {
                failed = true;
                update(&registry, &id, |r| {
                    r.event("error", "The turn reached Swarm's 24-hour runtime limit.")
                });
                break;
            }
            match process.output.recv_timeout(Duration::from_millis(50)) {
                Ok(Output::Line(line)) => {
                    if let Some(decoded) = decoder.decode(&harness, &line) {
                        completed |= decoded.completed;
                        failed |= decoded.failed;
                        if let Some(tokens) = decoded.usage {
                            usage = tokens;
                        }
                        attention |= decoded.events.iter().any(|(kind, _)| kind == "permission");
                        update(&registry, &id, |run| {
                            if let Some(session) = decoded.session {
                                run.session = Some(session);
                            }
                            run.agent.context_calls = run
                                .agent
                                .context_calls
                                .saturating_add(decoded.context_calls);
                            for (kind, text) in decoded.events {
                                run.event(&kind, text);
                            }
                            if attention && run.agent.state == AgentState::Running {
                                run.agent.state = AgentState::NeedsAttention;
                                run.agent.revision += 1;
                            }
                        });
                    }
                }
                Ok(Output::Diagnostic(text)) => {
                    update(&registry, &id, |r| r.event("diagnostic", text));
                }
                Ok(Output::End) => {
                    ends += 1;
                }
                Ok(Output::Overflow) => {
                    failed = true;
                    update(&registry, &id, |r| {
                        r.event("error", "CLI output exceeded the bounded activity buffer. The turn was stopped.")
                    });
                    break;
                }
                Err(_) => {}
            }
            if exited.is_none() {
                match process.finished() {
                    Ok(Some(ok)) => exited = Some((Instant::now(), ok)),
                    Ok(None) => {}
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if let Some((at, ok)) = exited {
                if ends >= 2 || at.elapsed() > Duration::from_secs(1) {
                    failed |= !ok;
                    break;
                }
            }
        }
        drop(process); // Reap the owned tree before advertising a stopped state.
        let mut again = false;
        update(&registry, &id, |run| {
            run.agent.pid = None;
            run.agent.input_tokens = run.agent.input_tokens.saturating_add(usage.0);
            run.agent.output_tokens = run.agent.output_tokens.saturating_add(usage.1);
            run.agent.revision += 1;
            run.agent.state = if cancel == 2 {
                AgentState::Stopped
            } else if cancel == 1 {
                AgentState::Interrupted
            } else if failed || !completed {
                AgentState::Failed
            } else if attention {
                AgentState::NeedsAttention
            } else if run.session.is_some() {
                AgentState::AwaitingInput
            } else {
                AgentState::Completed
            };
            run.agent.detail = match run.agent.state {
                AgentState::Stopped => "Stopped. Changes already made to project files remain.",
                AgentState::Interrupted => "Turn interrupted. Send a follow-up to resume the conversation.",
                AgentState::Failed => "The CLI did not complete the turn. Review activity and permissions before continuing.",
                AgentState::AwaitingInput => "Turn complete. Ready for your next instruction.",
                AgentState::NeedsAttention => "The harness denied a tool. Check permissions and Guard Inbox before continuing.",
                _ => "Turn complete. This CLI did not report a resumable session.",
            }.into();
            run.event("lifecycle", run.agent.detail.clone());
            if cancel != 0 || failed || attention || !completed || run.session.is_none() {
                if !run.pending.is_empty() {
                    run.event("instruction", "Queued instructions were not sent because the turn did not complete successfully.");
                }
                run.pending.clear();
            }
            again = !run.pending.is_empty();
            run.active = again;
            run.controls();
        });
        if !again {
            return;
        }
    }
}

fn prepare(registry: &Arc<Mutex<Registry>>, id: &str) -> Option<(Command, String, String)> {
    let mut state = registry.lock().ok()?;
    let shutdown = state.shutdown;
    let run = state.runs.get_mut(id)?;
    if shutdown || run.cancel != 0 {
        run.active = false;
        run.pending.clear();
        run.agent.state = if run.cancel == 1 {
            AgentState::Interrupted
        } else {
            AgentState::Stopped
        };
        run.controls();
        return None;
    }
    let prompt = run.pending.pop_front()?;
    let mut command = Command::new(&run.executable);
    command.current_dir(run.agent.workspace.as_deref()?);
    {
        let path = &run.cli_path;
        // Script entry points may use /usr/bin/env. Relative PATH entries must
        // not resolve an interpreter from the newly selected project.
        match std::env::join_paths(std::env::split_paths(path).filter(|p| p.is_absolute())) {
            Ok(path) => {
                command.env("PATH", path);
            }
            Err(_) => {
                command.env_remove("PATH");
            }
        }
    }
    for key in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_THREAD_ID",
        "HOL_GUARD_SESSION_ID",
        "HOL_GUARD_OPERATION_ID",
    ] {
        command.env_remove(key);
    }
    adapter::configure(
        &mut command,
        &run.agent.harness,
        run.session.as_deref(),
        run.agent.model.as_deref(),
    );
    run.controls();
    Some((command, prompt, run.agent.harness.clone()))
}

fn update(registry: &Arc<Mutex<Registry>>, id: &str, f: impl FnOnce(&mut crate::service::Run)) {
    if let Ok(mut state) = registry.lock() {
        if let Some(run) = state.runs.get_mut(id) {
            f(run);
        }
    }
}
