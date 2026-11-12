use crate::service::Run;
use crate::{Agent, AgentOrigin, AgentState, Controls, Service};
use std::collections::VecDeque;
use std::path::PathBuf;

impl Service {
    /// A bounded recovery summary, without tasks, output, tokens, credentials,
    /// resumable session IDs, executable paths, or process control authority.
    pub fn history(&self) -> Result<Vec<Agent>, &'static str> {
        let registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        Ok(registry
            .runs
            .values()
            .map(|run| {
                let mut agent = run.agent.clone();
                agent.task = None;
                agent.activity = None;
                agent.model = None;
                agent.pid = None;
                agent.controls = Controls::default();
                agent.queued = 0;
                agent.context_calls = 0;
                agent.input_tokens = 0;
                agent.output_tokens = 0;
                agent
            })
            .collect())
    }

    /// Restored metadata is inert. Only a newly launched, service-owned child
    /// can have controls; never reattach to a PID or replay queued tasks.
    pub fn restore_history(&self, agents: Vec<Agent>) -> Result<(), &'static str> {
        if agents.len() > 64
            || agents.iter().any(|a| {
                !crate::valid_id(&a.id)
                    || !matches!(a.harness.as_str(), "codex" | "claude-code")
                    || a.workspace.as_ref().is_some_and(|p| p.len() > 4096)
            })
        {
            return Err("swarm_history_invalid");
        }
        let mut registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        if !registry.runs.is_empty() {
            return Err("swarm_history_already_loaded");
        }
        for mut agent in agents {
            agent.origin = AgentOrigin::Managed;
            agent.task = None;
            agent.activity = None;
            agent.model = None;
            agent.pid = None;
            agent.controls = Controls::default();
            agent.queued = 0;
            agent.context_calls = 0;
            agent.input_tokens = 0;
            agent.output_tokens = 0;
            if !matches!(
                agent.state,
                AgentState::Stopped | AgentState::Completed | AgentState::Failed
            ) {
                agent.state = AgentState::Interrupted;
            }
            agent.label = if agent.harness == "codex" {
                "Codex"
            } else {
                "Claude Code"
            }
            .into();
            agent.detail = "Previous Guard session. This task was not relaunched; open its CLI transcript to continue it.".into();
            let mut run = Run {
                agent,
                executable: PathBuf::new(),
                cli_path: std::ffi::OsString::new(),
                session: None,
                pending: VecDeque::new(),
                events: VecDeque::new(),
                sequence: 0,
                active: false,
                cancel: 2,
            };
            run.event(
                "lifecycle",
                "Recovered a previous session summary. Activity and control are not restored.",
            );
            registry.runs.insert(run.agent.id.clone(), run);
        }
        Ok(())
    }
}
