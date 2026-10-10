//! The proxy's `tools/list` catalog state machine and the saved-allow gate.
//!
//! The resident owns the state (`unobserved`/`pending`/`complete`/
//! `invalidated`/`error`), the generation counter, cursor validation and the
//! poison-on-anomaly rule. The caller keeps the tool definitions and rebuilds
//! them from the names and the normalized page returned here.

use std::collections::BTreeSet;

use guard_command::mcp_tool_catalog::normalized_tools_catalog_page;
use guard_contracts::{
    GuardAction, McpCatalogCursorV1, McpCatalogEventQueryV1, McpCatalogEventV1, McpCatalogStateV1,
    McpSavedAllowGateQueryV1,
};
use serde_json::{json, Map, Value};

use crate::mcp_proxy_actions::{norm, truthy_or, TOOL_CATALOG_INCOMPLETE};

const SAVED_ALLOW_SUMMARY: &str = "Guard cannot reuse a saved MCP approval until the current server process has advertised a complete tool catalog.";

struct Machine {
    state: String,
    generation: i64,
    inflight: bool,
    inflight_cursor: Option<String>,
    expected_cursor: Option<String>,
    catalog: BTreeSet<String>,
    pending: Option<BTreeSet<String>>,
}

impl Machine {
    fn from(state: &McpCatalogStateV1) -> Self {
        Self {
            state: state.state.clone(),
            generation: state.generation,
            inflight: state.inflight,
            inflight_cursor: state.inflight_cursor.clone(),
            expected_cursor: state.expected_cursor.clone(),
            catalog: state.catalog_names.iter().cloned().collect(),
            pending: state
                .pending_names
                .as_ref()
                .map(|names| names.iter().cloned().collect()),
        }
    }

    fn clear(&mut self, state: &str, advance_generation: bool) {
        self.state = state.to_owned();
        self.catalog.clear();
        self.pending = None;
        self.expected_cursor = None;
        self.inflight = false;
        self.inflight_cursor = None;
        if advance_generation {
            self.generation += 1;
        }
    }

    fn poison(&mut self) {
        self.clear("error", true);
    }

    /// `_begin_tools_catalog_request`: returns the request generation.
    fn begin(&mut self, cursor: &McpCatalogCursorV1, advance_root: bool) -> i64 {
        let McpCatalogCursorV1::None = cursor else {
            let request_generation = self.generation;
            let continuation = match cursor {
                McpCatalogCursorV1::String { value } => Some(value),
                _ => None,
            };
            let valid = continuation.is_some_and(|value| {
                self.state == "pending"
                    && self.pending.is_some()
                    && !self.inflight
                    && self.expected_cursor.as_deref() == Some(value.as_str())
            });
            match continuation {
                Some(value) if valid => {
                    self.inflight = true;
                    self.inflight_cursor = Some(value.clone());
                }
                _ => self.poison(),
            }
            return request_generation;
        };
        if advance_root {
            self.generation += 1;
        }
        self.state = "pending".to_owned();
        self.catalog.clear();
        self.pending = Some(BTreeSet::new());
        self.expected_cursor = None;
        self.inflight = true;
        self.inflight_cursor = None;
        self.generation
    }

    fn cursor_matches_inflight(&self, cursor: &McpCatalogCursorV1) -> bool {
        match cursor {
            McpCatalogCursorV1::None => self.inflight_cursor.is_none(),
            McpCatalogCursorV1::String { value } => {
                self.inflight_cursor.as_deref() == Some(value.as_str())
            }
            McpCatalogCursorV1::Other => false,
        }
    }

    /// `_capture_tools_catalog`: returns the accepted page, if any.
    fn capture(
        &mut self,
        cursor: &McpCatalogCursorV1,
        request_generation: Option<i64>,
        response: &Value,
    ) -> Option<Map<String, Value>> {
        let request_generation = match request_generation {
            None => self.begin(cursor, true),
            Some(generation) if generation != self.generation => return None,
            Some(_) if !self.inflight => self.begin(cursor, false),
            Some(generation) => generation,
        };
        if request_generation != self.generation {
            return None;
        }
        if !self.inflight || !self.cursor_matches_inflight(cursor) {
            self.poison();
            return None;
        }
        let Some(page) = accepted_page(response) else {
            self.poison();
            return None;
        };
        let (page, next_cursor) = page;
        let names: BTreeSet<String> = page.keys().cloned().collect();
        let overlaps = match &self.pending {
            None => true,
            Some(pending) => names.iter().any(|name| pending.contains(name)),
        };
        if overlaps {
            self.poison();
            return None;
        }
        let mut merged = self.pending.take().unwrap_or_default();
        merged.extend(names);
        self.inflight = false;
        self.inflight_cursor = None;
        if let Some(next) = next_cursor {
            self.state = "pending".to_owned();
            self.catalog.clear();
            self.pending = Some(merged);
            self.expected_cursor = Some(next);
        } else {
            self.state = "complete".to_owned();
            self.catalog = merged;
            self.pending = None;
            self.expected_cursor = None;
        }
        Some(page)
    }

    fn payload(&self, page: Option<Map<String, Value>>, request_generation: Option<i64>) -> Value {
        json!({
            "state": {
                "state": self.state,
                "generation": self.generation,
                "inflight": self.inflight,
                "inflight_cursor": self.inflight_cursor,
                "expected_cursor": self.expected_cursor,
            },
            "catalog_names": self.catalog,
            "pending_names": self.pending,
            "page": page.map(Value::Object),
            "request_generation": request_generation,
        })
    }
}

/// The normalized page and `nextCursor` of an acceptable `tools/list` reply.
fn accepted_page(response: &Value) -> Option<(Map<String, Value>, Option<String>)> {
    let reply = response.as_object()?;
    if reply.contains_key("error") {
        return None;
    }
    let result = reply.get("result")?.as_object()?;
    let tools = result.get("tools")?.as_array()?;
    let mut entries = Vec::with_capacity(tools.len());
    for tool in tools {
        let name = tool.as_object()?.get("name")?.as_str()?;
        entries.push((name.to_owned(), tool.clone()));
    }
    let page = normalized_tools_catalog_page(&entries)?;
    let next = match result.get("nextCursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => return None,
    };
    Some((page, next))
}

pub(crate) fn catalog_event(query: &McpCatalogEventQueryV1) -> Value {
    let mut machine = Machine::from(&query.state);
    let mut page = None;
    let mut request_generation = None;
    match &query.event {
        McpCatalogEventV1::Begin {
            cursor,
            advance_root_generation,
        } => request_generation = Some(machine.begin(cursor, *advance_root_generation)),
        McpCatalogEventV1::Capture {
            cursor,
            request_generation: generation,
            response,
        } => page = machine.capture(cursor, *generation, response),
        McpCatalogEventV1::Fail { request_generation } => {
            if *request_generation == machine.generation {
                machine.poison();
            }
        }
        McpCatalogEventV1::Invalidate => machine.clear("invalidated", true),
        McpCatalogEventV1::Reset => machine.clear("unobserved", true),
        McpCatalogEventV1::Poison => machine.poison(),
    }
    machine.payload(page, request_generation)
}

/// `_disable_saved_allow_without_complete_catalog`.
pub(crate) fn saved_allow_gate(query: &McpSavedAllowGateQueryV1) -> Value {
    let decision = &query.decision;
    if query.catalog_state == "complete" || !decision.has_pending {
        return json!({ "disable": false });
    }
    let action = norm(
        truthy_or(decision.current_action.as_deref(), &decision.action),
        GuardAction::Review,
    );
    json!({
        "disable": true,
        "action": action.as_str(),
        "source": "tool-catalog-state",
        "summary": SAVED_ALLOW_SUMMARY,
        "approval_reuse_status": "rejected",
        "approval_reuse_reason_code": TOOL_CATALOG_INCOMPLETE,
    })
}
