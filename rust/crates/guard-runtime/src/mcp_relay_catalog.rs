//! The relay's mirror of the advertised `tools/list` catalog.
//!
//! Every transition is decided by `mcp_proxy_catalog::catalog_event`, called
//! in-process; this module only keeps the tool definitions and rebuilds them
//! from the names and the normalized page the transition returns, exactly as
//! the Python proxy's `_catalog_event` does.

use std::collections::BTreeMap;

use guard_command::mcp_tool_catalog::tool_catalog_fingerprint;
use guard_contracts::{
    McpCatalogCursorV1, McpCatalogEventQueryV1, McpCatalogEventV1, McpCatalogStateV1,
};
use serde_json::Value;

use crate::mcp_proxy_catalog::catalog_event;

const CATALOG_FINGERPRINT_VERSION: &str = "mcp-advertised-tool-catalog-v2";

/// The catalog authority a forwarded `tools/call` was decided against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogSnapshot {
    pub(crate) generation: i64,
    pub(crate) state: String,
    pub(crate) fingerprint: Option<String>,
}

type Definitions = BTreeMap<String, Value>;

/// The mirrored catalog state and its definitions.
pub(crate) struct RelayCatalog {
    state: String,
    generation: i64,
    inflight: bool,
    inflight_cursor: Option<String>,
    expected_cursor: Option<String>,
    catalog: Definitions,
    pending: Option<Definitions>,
}

impl Default for RelayCatalog {
    fn default() -> Self {
        Self {
            state: "unobserved".to_owned(),
            generation: 0,
            inflight: false,
            inflight_cursor: None,
            expected_cursor: None,
            catalog: Definitions::new(),
            pending: None,
        }
    }
}

/// `cursor_fact`: the request cursor of a `tools/list` call.
pub(crate) fn cursor_fact(params: Option<&Value>) -> McpCatalogCursorV1 {
    match params {
        None => McpCatalogCursorV1::None,
        Some(Value::Object(params)) => match params.get("cursor") {
            None | Some(Value::Null) => McpCatalogCursorV1::None,
            Some(Value::String(value)) => McpCatalogCursorV1::String {
                value: value.clone(),
            },
            Some(_) => McpCatalogCursorV1::Other,
        },
        Some(_) => McpCatalogCursorV1::Other,
    }
}

impl RelayCatalog {
    /// `_tool_catalog_fingerprint(self._tool_catalog, state=...)`.
    pub(crate) fn snapshot(&self) -> CatalogSnapshot {
        let entries: Vec<(String, Value)> = self
            .catalog
            .iter()
            .map(|(name, definition)| (name.clone(), definition.clone()))
            .collect();
        let (fingerprint, _) =
            tool_catalog_fingerprint(&entries, &self.state, CATALOG_FINGERPRINT_VERSION);
        CatalogSnapshot {
            generation: self.generation,
            state: self.state.clone(),
            fingerprint,
        }
    }

    /// Every advertised definition, once a listing made the catalog whole.
    pub(crate) fn complete_tools(&self) -> Option<Vec<Value>> {
        (self.state == "complete").then(|| self.catalog.values().cloned().collect())
    }

    /// The advertised definition of `name` (`self._tool_catalog.get(name)`).
    pub(crate) fn definition(&self, name: &str) -> Option<&Value> {
        self.catalog.get(name)
    }

    /// `_catalog_authority_matches`: an unserializable catalog never matches.
    pub(crate) fn matches(&self, expected: &CatalogSnapshot) -> bool {
        let current = self.snapshot();
        current.fingerprint.is_some() && current == *expected
    }

    pub(crate) fn invalidate(&mut self) {
        self.apply(McpCatalogEventV1::Invalidate);
    }

    pub(crate) fn poison(&mut self) {
        self.apply(McpCatalogEventV1::Poison);
    }

    /// `_begin_tools_catalog_request`: returns the request generation.
    pub(crate) fn begin(&mut self, cursor: McpCatalogCursorV1) -> i64 {
        let payload = self.apply(McpCatalogEventV1::Begin {
            cursor,
            advance_root_generation: true,
        });
        payload
            .and_then(|payload| payload.get("request_generation").and_then(Value::as_i64))
            .unwrap_or(self.generation)
    }

    pub(crate) fn fail(&mut self, request_generation: i64) {
        self.apply(McpCatalogEventV1::Fail { request_generation });
    }

    pub(crate) fn capture(
        &mut self,
        cursor: McpCatalogCursorV1,
        request_generation: i64,
        response: &Value,
    ) {
        self.apply(McpCatalogEventV1::Capture {
            cursor,
            request_generation: Some(request_generation),
            response: response.clone(),
        });
    }

    fn state_fact(&self) -> McpCatalogStateV1 {
        McpCatalogStateV1 {
            state: self.state.clone(),
            generation: self.generation,
            inflight: self.inflight,
            inflight_cursor: self.inflight_cursor.clone(),
            expected_cursor: self.expected_cursor.clone(),
            catalog_names: self.catalog.keys().cloned().collect(),
            pending_names: self
                .pending
                .as_ref()
                .map(|pending| pending.keys().cloned().collect()),
        }
    }

    /// `_catalog_event`: apply one decided transition; a payload that cannot
    /// be applied records `_catalog_unavailable` and returns `None`.
    fn apply(&mut self, event: McpCatalogEventV1) -> Option<Value> {
        let query = McpCatalogEventQueryV1 {
            state: self.state_fact(),
            event,
        };
        let payload = catalog_event(&query);
        if self.rebuild(&payload).is_none() {
            self.unavailable();
            return None;
        }
        Some(payload)
    }

    fn rebuild(&mut self, payload: &Value) -> Option<()> {
        let state = payload.get("state")?;
        let mut pool = self.catalog.clone();
        if let Some(pending) = &self.pending {
            pool.extend(pending.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if let Some(page) = payload.get("page").and_then(Value::as_object) {
            pool.extend(page.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        let pick = |names: &Value| -> Option<Definitions> {
            names
                .as_array()?
                .iter()
                .map(|name| {
                    let name = name.as_str()?;
                    Some((name.to_owned(), pool.get(name)?.clone()))
                })
                .collect()
        };
        let catalog = pick(payload.get("catalog_names")?)?;
        let pending = match payload.get("pending_names")? {
            Value::Null => None,
            names => Some(pick(names)?),
        };
        let optional = |key: &str| -> Option<Option<String>> {
            match state.get(key)? {
                Value::Null => Some(None),
                Value::String(text) => Some(Some(text.clone())),
                _ => None,
            }
        };
        let next_state = state.get("state")?.as_str()?.to_owned();
        let generation = state.get("generation")?.as_i64()?;
        let inflight = state.get("inflight")?.as_bool()?;
        let inflight_cursor = optional("inflight_cursor")?;
        let expected_cursor = optional("expected_cursor")?;
        self.state = next_state;
        self.generation = generation;
        self.inflight = inflight;
        self.inflight_cursor = inflight_cursor;
        self.expected_cursor = expected_cursor;
        self.catalog = catalog;
        self.pending = pending;
        Some(())
    }

    /// `_catalog_unavailable`: the `error` state authorizes nothing.
    fn unavailable(&mut self) {
        self.state = "error".to_owned();
        self.catalog.clear();
        self.pending = None;
        self.expected_cursor = None;
        self.inflight = false;
        self.inflight_cursor = None;
        self.generation += 1;
    }
}

#[cfg(test)]
#[path = "mcp_relay_catalog_tests.rs"]
mod tests;
