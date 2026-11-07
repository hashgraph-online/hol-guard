use crate::{
    discover, installed_adapters, now_ms, Action, Agent, AgentOrigin, AgentState, Controls, Event,
    Launch, Snapshot, MAX_EVENTS, MAX_RUNS, SCHEMA,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) struct Run {
    pub agent: Agent,
    pub executable: PathBuf,
    pub session: Option<String>,
    pub pending: VecDeque<String>,
    pub events: VecDeque<Event>,
    pub sequence: u64,
    pub active: bool,
    pub cancel: u8,
}

impl Run {
    pub fn event(&mut self, kind: &str, text: impl Into<String>) {
        // Keep Unicode output within the resident's response byte budget.
        let text = crate::model::clipped(&text.into(), 4096);
        if matches!(
            kind,
            "message" | "command" | "files" | "tool" | "context" | "permission" | "error"
        ) {
            self.agent.activity = Some(text.chars().take(180).collect());
        }
        self.sequence += 1;
        self.agent.updated_at_ms = now_ms();
        self.events.push_back(Event {
            sequence: self.sequence,
            at_ms: self.agent.updated_at_ms,
            kind: kind.into(),
            text,
        });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }
    pub fn controls(&mut self) {
        let stopped = matches!(self.agent.state, AgentState::Stopped | AgentState::Stopping);
        self.agent.controls = Controls {
            message: !stopped && self.pending.len() < 4 && (self.active || self.session.is_some()),
            steer: false,
            interrupt: self.active && !stopped,
            stop: !stopped,
        };
        self.agent.queued = self.pending.len();
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    pub runs: BTreeMap<String, Run>,
    // Receipts never expire within an epoch, preventing uncertain retries from
    // running twice. A new resident epoch rejects previous mutations.
    receipts: BTreeMap<String, (String, String)>,
    pub shutdown: bool,
}

pub struct Service {
    epoch: String,
    inventory: Mutex<Option<(Instant, Snapshot)>>,
    pub(crate) registry: Arc<Mutex<Registry>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    #[cfg(test)]
    pub(crate) test_executable: Option<PathBuf>,
}

impl Default for Service {
    fn default() -> Self {
        let mut bytes = [0u8; 16];
        let epoch = if getrandom::fill(&mut bytes).is_ok() {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        } else {
            String::new()
        };
        Self {
            epoch,
            inventory: Mutex::new(None),
            registry: Arc::new(Mutex::new(Registry::default())),
            workers: Mutex::new(Vec::new()),
            #[cfg(test)]
            test_executable: None,
        }
    }
}

impl Service {
    /// Owned work keeps the resident alive even when its dashboard is closed.
    pub fn has_active_runs(&self) -> bool {
        self.registry
            .lock()
            .is_ok_and(|registry| registry.runs.values().any(|run| run.active))
    }

    pub fn snapshot(&self) -> Result<Snapshot, &'static str> {
        if self.epoch.is_empty() {
            return Err("swarm_unavailable");
        }
        let mut inventory = self.inventory.lock().map_err(|_| "swarm_unavailable")?;
        if inventory
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(1))
        {
            let observed_at_ms = now_ms();
            let (agents, discovery) = discover(observed_at_ms);
            *inventory = Some((
                Instant::now(),
                Snapshot {
                    schema: SCHEMA.into(),
                    epoch: self.epoch.clone(),
                    observed_at_ms,
                    discovery,
                    agents,
                    adapters: installed_adapters(),
                },
            ));
        }
        let mut snapshot = inventory.as_ref().ok_or("swarm_unavailable")?.1.clone();
        let registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        snapshot.agents.retain(|observed| {
            !registry
                .runs
                .values()
                .any(|run| run.active && run.agent.pid == observed.pid)
        });
        snapshot
            .agents
            .extend(registry.runs.values().map(|r| r.agent.clone()));
        snapshot.observed_at_ms = now_ms();
        Ok(snapshot)
    }

    pub fn launch(&self, request: Launch) -> Result<Agent, &'static str> {
        request.validate()?;
        self.check_epoch(&request.epoch)?;
        let fingerprint = digest(&request)?;
        let mut registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        if let Some(agent) = replay(&registry, &request.request_id, &fingerprint)? {
            return Ok(agent);
        }
        if registry.runs.values().filter(|r| r.active).count() >= MAX_RUNS {
            return Err("swarm_run_limit");
        }
        let executable = self
            .executable(&request.harness)
            .ok_or("swarm_cli_missing")?;
        let workspace = PathBuf::from(&request.workspace)
            .canonicalize()
            .map_err(|_| "swarm_workspace_invalid")?;
        if !workspace.is_dir() {
            return Err("swarm_workspace_invalid");
        }
        if registry.runs.len() >= 64 {
            let old = registry
                .runs
                .iter()
                .filter(|(_, r)| !r.active)
                .min_by_key(|(_, r)| r.agent.updated_at_ms)
                .map(|(id, _)| id.clone());
            if let Some(id) = old {
                registry.runs.remove(&id);
            } else {
                return Err("swarm_run_limit");
            }
        }
        let id = format!("run-{}", &fingerprint[..32]);
        let now = now_ms();
        let agent = Agent {
            id: id.clone(),
            harness: request.harness.clone(),
            label: if request.harness == "codex" {
                "Codex"
            } else {
                "Claude Code"
            }
            .into(),
            origin: AgentOrigin::Managed,
            state: AgentState::Starting,
            workspace: Some(workspace.to_string_lossy().into()),
            task: Some(crate::model::clipped(&request.task, 2048)),
            model: request.model,
            pid: None,
            started_at_ms: now,
            updated_at_ms: now,
            controls: Controls::default(),
            revision: 1,
            queued: 0,
            context_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
            detail: "Starting a task with the CLI's existing configuration and permissions.".into(),
            activity: None,
        };
        let mut run = Run {
            agent,
            executable,
            session: None,
            pending: VecDeque::from([request.task]),
            events: VecDeque::new(),
            sequence: 0,
            active: true,
            cancel: 0,
        };
        run.event("lifecycle", "Task accepted. Starting the CLI.");
        run.controls();
        let agent = run.agent.clone();
        registry.runs.insert(id.clone(), run);
        registry
            .receipts
            .insert(request.request_id, (fingerprint, id.clone()));
        drop(registry);
        self.start_worker(id)?;
        Ok(agent)
    }

    pub fn action(&self, request: Action) -> Result<Agent, &'static str> {
        request.validate()?;
        self.check_epoch(&request.epoch)?;
        let fingerprint = digest(&request)?;
        let mut registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        if let Some(agent) = replay(&registry, &request.request_id, &fingerprint)? {
            return Ok(agent);
        }
        let at_capacity = registry.runs.values().filter(|r| r.active).count() >= MAX_RUNS;
        let run = registry
            .runs
            .get_mut(&request.run_id)
            .ok_or("swarm_unknown_run")?;
        if run.agent.revision != request.expected_revision {
            return Err("swarm_stale");
        }
        let mut start = false;
        match request.action.as_str() {
            "message" if run.agent.controls.message => {
                if !run.active && at_capacity {
                    return Err("swarm_run_limit");
                }
                run.pending
                    .push_back(request.text.ok_or("swarm_action_invalid")?);
                run.event(
                    "instruction",
                    if run.active {
                        "Instruction queued for the next turn."
                    } else {
                        "Follow-up accepted."
                    },
                );
                if !run.active {
                    run.active = true;
                    run.cancel = 0;
                    start = true;
                    run.agent.state = AgentState::Starting;
                }
            }
            "interrupt" if run.agent.controls.interrupt => {
                run.cancel = 1;
                run.pending.clear();
                run.agent.state = AgentState::Stopping;
                run.event(
                    "lifecycle",
                    "Interrupt requested. Queued instructions cleared.",
                );
            }
            "stop" if run.agent.controls.stop => {
                run.cancel = 2;
                run.pending.clear();
                run.agent.state = if run.active {
                    AgentState::Stopping
                } else {
                    AgentState::Stopped
                };
                run.event("lifecycle", "Stop requested. Queued instructions cleared.");
            }
            _ => return Err("swarm_action_unavailable"),
        }
        run.agent.revision += 1;
        run.controls();
        let agent = run.agent.clone();
        registry
            .receipts
            .insert(request.request_id, (fingerprint, request.run_id.clone()));
        drop(registry);
        if start {
            self.start_worker(request.run_id)?;
        }
        Ok(agent)
    }

    pub fn events(&self, id: &str) -> Result<Vec<Event>, &'static str> {
        let registry = self.registry.lock().map_err(|_| "swarm_unavailable")?;
        Ok(registry
            .runs
            .get(id)
            .ok_or("swarm_unknown_run")?
            .events
            .iter()
            .cloned()
            .collect())
    }

    fn check_epoch(&self, epoch: &str) -> Result<(), &'static str> {
        if self.epoch.is_empty() || epoch != self.epoch {
            Err("swarm_stale")
        } else {
            Ok(())
        }
    }

    fn executable(&self, harness: &str) -> Option<PathBuf> {
        #[cfg(test)]
        if let Some(path) = self.test_executable.as_ref() {
            return Some(path.clone());
        }
        crate::discovery::executable(harness)
    }

    fn start_worker(&self, id: String) -> Result<(), &'static str> {
        let registry = self.registry.clone();
        let mut workers = self.workers.lock().map_err(|_| "swarm_unavailable")?;
        let mut running = Vec::new();
        for worker in workers.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                running.push(worker);
            }
        }
        let task_id = id.clone();
        match std::thread::Builder::new()
            .name("guard-swarm".into())
            .spawn(move || crate::worker::run(registry, task_id))
        {
            Ok(worker) => running.push(worker),
            Err(_) => {
                if let Ok(mut registry) = self.registry.lock() {
                    if let Some(run) = registry.runs.get_mut(&id) {
                        run.active = false;
                        run.agent.state = AgentState::Failed;
                        run.pending.clear();
                        run.event("error", "Guard could not start the agent worker.");
                        run.controls();
                    }
                }
                *workers = running;
                return Err("swarm_worker_unavailable");
            }
        }
        *workers = running;
        Ok(())
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.shutdown = true;
        }
        if let Ok(workers) = self.workers.get_mut() {
            for worker in workers.drain(..) {
                let _ = worker.join();
            }
        }
    }
}

fn digest(value: &impl serde::Serialize) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "swarm_request_invalid")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn replay(registry: &Registry, id: &str, fingerprint: &str) -> Result<Option<Agent>, &'static str> {
    if let Some((previous, run_id)) = registry.receipts.get(id) {
        if previous != fingerprint {
            return Err("swarm_request_conflict");
        }
        return registry
            .runs
            .get(run_id)
            .map(|r| Some(r.agent.clone()))
            .ok_or("swarm_expired");
    }
    if registry.shutdown {
        return Err("swarm_unavailable");
    }
    if registry.receipts.len() >= 2048 {
        return Err("swarm_request_limit");
    }
    Ok(None)
}
