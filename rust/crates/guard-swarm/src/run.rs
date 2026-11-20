//! One managed agent run: its state, queued instructions and recent events.
use crate::{now_ms, Agent, AgentState, Controls, Event, MAX_EVENTS};
use std::collections::VecDeque;
use std::path::PathBuf;

pub(crate) struct Run {
    pub agent: Agent,
    pub executable: PathBuf,
    pub cli_path: std::ffi::OsString,
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
