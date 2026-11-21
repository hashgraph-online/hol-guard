//! Host-only graph API. HTTP/MCP adapters must derive scopes from authenticated
//! Guard sessions, never deserialize these private handles from caller facts.
use crate::{Limits, RuntimeError, VerifiedRuntime};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
const RPC_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Clone, Debug)]
pub struct WorkspaceHandle {
    epoch: u64,
    id: String,
    generation: u64,
}
#[derive(Clone, Debug)]
pub struct ViewHandle {
    workspace: WorkspaceHandle,
    id: String,
    generation: u64,
}

/// Already-admitted text from the native host. This type performs no filesystem
/// read and is not an ingestion authorization. The source is assigned by host.
#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextDocument {
    pub id: String,
    pub text: String,
    #[serde(default = "first_line")]
    pub start_line: u32,
}
fn first_line() -> u32 {
    1
}

#[derive(Clone, Serialize)]
pub struct ContextBrief {
    pub schema: &'static str,
    pub snapshot_id: String,
    pub policy_revision: String,
    pub graph_revision: u64,
    pub rendered: String,
    pub rendered_tokens: u64,
    pub citations: Vec<Value>,
    pub excerpts: Vec<ContextExcerpt>,
    pub data_role: bool,
}

#[derive(Clone, Serialize)]
pub struct ContextExcerpt {
    pub text: String,
    pub citations: Vec<Value>,
}

/// Retain the full SDK context on the native side for currentness checks and
/// on-demand selection details. A brief or snapshot ID is never authority.
pub struct RetainedContext {
    view: ViewHandle,
    source_revisions: BTreeMap<String, u64>,
    raw: Value,
    brief: ContextBrief,
}
impl RetainedContext {
    pub fn brief(&self) -> &ContextBrief {
        &self.brief
    }
}

struct Source {
    revision: u64,
    documents: BTreeMap<String, ContextDocument>,
}
struct View {
    sources: BTreeSet<String>,
    generation: u64,
    policy_revision: String,
}
struct Graph {
    generation: u64,
    limits: Limits,
    sources: BTreeMap<String, Source>,
    views: BTreeMap<String, View>,
    next_view: u64,
}

pub(crate) struct GraphRegistry {
    epoch: u64,
    next_workspace: u64,
    graphs: BTreeMap<String, Graph>,
}
impl Default for GraphRegistry {
    fn default() -> Self {
        Self {
            epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
            next_workspace: 0,
            graphs: BTreeMap::new(),
        }
    }
}

fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_:-".contains(&c))
}

impl VerifiedRuntime {
    fn graph(&self, handle: &WorkspaceHandle) -> Result<&Graph, RuntimeError> {
        if handle.epoch != self.graphs.epoch {
            return Err(RuntimeError::ScopeDenied);
        }
        self.graphs
            .graphs
            .get(&handle.id)
            .filter(|graph| graph.generation == handle.generation)
            .ok_or(RuntimeError::ScopeDenied)
    }

    /// Called only after native local consent and workspace/app admission.
    pub fn open_workspace(
        &mut self,
        id: &str,
        limits: &Limits,
    ) -> Result<WorkspaceHandle, RuntimeError> {
        if !opaque(id)
            || !(1..=8).contains(&limits.max_active_workspaces)
            || !(64..=16384).contains(&limits.context_tokens)
            || limits.reserve_tokens >= limits.context_tokens
        {
            return Err(RuntimeError::RequestInvalid);
        }
        if self.graphs.graphs.contains_key(id) {
            return Err(RuntimeError::ScopeDenied);
        }
        if self.graphs.graphs.len() >= limits.max_active_workspaces as usize {
            return Err(RuntimeError::ResourceLimit);
        }
        self.recheck_artifacts()?;
        let generation = self
            .graphs
            .next_workspace
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.rpc(json!({"op": "open_graph", "graph": id, "limits": {
            "max_documents": 1024, "max_document_bytes": 65536, "max_total_bytes": 4194304,
            "max_edges_per_document": 16, "max_edges": 4096, "cache_entries": 1024, "cache_text_bytes": 2097152
        }}), RPC_TIMEOUT)?;
        self.graphs.next_workspace = generation;
        self.graphs.graphs.insert(
            id.into(),
            Graph {
                generation,
                limits: limits.clone(),
                sources: BTreeMap::new(),
                views: BTreeMap::new(),
                next_view: 0,
            },
        );
        Ok(WorkspaceHandle {
            epoch: self.graphs.epoch,
            id: id.into(),
            generation,
        })
    }

    pub fn replace_source(
        &mut self,
        workspace: &WorkspaceHandle,
        source: &str,
        documents: Vec<ContextDocument>,
    ) -> Result<Value, RuntimeError> {
        if !opaque(source) || documents.len() > 1024 {
            return Err(RuntimeError::RequestInvalid);
        }
        let graph = self.graph(workspace)?;
        if graph.sources.len() >= 128 && !graph.sources.contains_key(source) {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut ids = BTreeSet::new();
        let mut bytes = 0_usize;
        for doc in &documents {
            if !opaque(&doc.id)
                || !ids.insert(doc.id.clone())
                || doc.text.len() > 65536
                || doc.text.contains('\0')
                || doc.start_line == 0
            {
                return Err(RuntimeError::RequestInvalid);
            }
            bytes += doc.text.len();
        }
        let existing_bytes: usize = graph
            .sources
            .iter()
            .filter(|(key, _)| *key != source)
            .flat_map(|(_, item)| item.documents.values())
            .map(|doc| doc.text.len())
            .sum();
        if bytes + existing_bytes > 4194304 {
            return Err(RuntimeError::ResourceLimit);
        }
        let wire: Vec<Value> = documents.iter().map(|doc| json!({"id": doc.id, "source": source, "text": doc.text, "start_line": doc.start_line})).collect();
        let result = self.rpc(json!({"op": "replace_source", "graph": workspace.id, "source": source, "documents": wire}), RPC_TIMEOUT)?;
        let changed = ["inserted", "replaced", "removed"]
            .iter()
            .try_fold(0_u64, |sum, key| {
                result[key]
                    .as_u64()
                    .and_then(|n| sum.checked_add(n))
                    .ok_or(RuntimeError::TransportFailed)
            });
        let changed = match changed {
            Ok(changes) => changes > 0,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        let graph = self
            .graphs
            .graphs
            .get_mut(&workspace.id)
            .ok_or(RuntimeError::ScopeDenied)?;
        let revision = graph
            .sources
            .get(source)
            .map_or(0, |item| item.revision)
            .checked_add(u64::from(changed))
            .ok_or(RuntimeError::ResourceLimit)?;
        graph.sources.insert(
            source.into(),
            Source {
                revision,
                documents: documents
                    .into_iter()
                    .map(|doc| (doc.id.clone(), doc))
                    .collect(),
            },
        );
        Ok(result)
    }

    pub fn create_view(
        &mut self,
        workspace: &WorkspaceHandle,
        id: &str,
        sources: BTreeSet<String>,
        policy_revision: &str,
    ) -> Result<ViewHandle, RuntimeError> {
        if !opaque(id) || policy_revision.is_empty() || policy_revision.len() > 256 {
            return Err(RuntimeError::RequestInvalid);
        }
        let graph = self.graph(workspace)?;
        if sources.len() > 128
            || sources
                .iter()
                .any(|source| !graph.sources.contains_key(source))
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if graph.views.len() >= 64 && !graph.views.contains_key(id) {
            return Err(RuntimeError::ResourceLimit);
        }
        let generation = graph
            .next_view
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.rpc(json!({"op": "create_view", "graph": workspace.id, "spec": {
            "id": id, "allowed_sources": sources, "writable_sources": [], "policy_revision": policy_revision
        }}), RPC_TIMEOUT)?;
        let graph = self
            .graphs
            .graphs
            .get_mut(&workspace.id)
            .ok_or(RuntimeError::ScopeDenied)?;
        graph.next_view = generation;
        graph.views.insert(
            id.into(),
            View {
                sources,
                generation,
                policy_revision: policy_revision.into(),
            },
        );
        Ok(ViewHandle {
            workspace: workspace.clone(),
            id: id.into(),
            generation,
        })
    }

    fn view(&self, handle: &ViewHandle) -> Result<(&Graph, &View), RuntimeError> {
        let graph = self.graph(&handle.workspace)?;
        let view = graph
            .views
            .get(&handle.id)
            .filter(|view| view.generation == handle.generation)
            .ok_or(RuntimeError::ScopeDenied)?;
        Ok((graph, view))
    }

    pub fn compile_context(
        &mut self,
        view: &ViewHandle,
        query: &str,
        required: Vec<String>,
    ) -> Result<RetainedContext, RuntimeError> {
        if query.len() > 4096 || required.len() > 64 {
            return Err(RuntimeError::RequestInvalid);
        }
        let (graph, record) = self.view(view)?;
        if required.iter().any(|id| {
            !record
                .sources
                .iter()
                .any(|source| graph.sources[source].documents.contains_key(id))
        }) {
            return Err(RuntimeError::ScopeDenied);
        }
        let source_revisions = record
            .sources
            .iter()
            .map(|source| (source.clone(), graph.sources[source].revision))
            .collect();
        let request = json!({"query": query, "required": required, "max_tokens": graph.limits.context_tokens,
            "reserve_tokens": graph.limits.reserve_tokens, "policy_revision": record.policy_revision,
            "max_candidates": 64, "max_blocks": 16, "graph_depth": 4, "excerpt_mode": "full"});
        let raw = self.rpc(json!({"op": "compile_view", "graph": view.workspace.id, "view": view.id, "request": request}), RPC_TIMEOUT)?;
        let (graph, record) = self.view(view)?;
        let brief = match brief::validate_brief(&raw, graph, record, view) {
            Ok(brief) => brief,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        Ok(RetainedContext {
            view: view.clone(),
            source_revisions,
            raw: raw["context"].clone(),
            brief,
        })
    }

    pub fn explain_context(&mut self, context: &RetainedContext) -> Result<Value, RuntimeError> {
        let (graph, view) = self.view(&context.view)?;
        if context.source_revisions.iter().any(|(id, revision)| {
            graph
                .sources
                .get(id)
                .is_none_or(|source| source.revision != *revision)
        }) || context
            .source_revisions
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != view.sources
        {
            return Err(RuntimeError::ContextStale);
        }
        self.rpc(
            json!({"op": "explain_view", "graph": context.view.workspace.id,
            "view": context.view.id, "context": context.raw}),
            RPC_TIMEOUT,
        )
    }

    pub fn revoke_view(&mut self, view: &ViewHandle) -> Result<(), RuntimeError> {
        self.view(view)?;
        self.rpc(
            json!({"op": "revoke_view", "graph": view.workspace.id, "view": view.id}),
            RPC_TIMEOUT,
        )?;
        self.graphs
            .graphs
            .get_mut(&view.workspace.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .views
            .remove(&view.id);
        Ok(())
    }

    pub fn close_workspace(&mut self, workspace: &WorkspaceHandle) -> Result<(), RuntimeError> {
        self.graph(workspace)?;
        self.rpc(
            json!({"op": "close_graph", "graph": workspace.id}),
            RPC_TIMEOUT,
        )?;
        self.graphs.graphs.remove(&workspace.id);
        Ok(())
    }
}

#[path = "graph_brief.rs"]
pub(crate) mod brief;
