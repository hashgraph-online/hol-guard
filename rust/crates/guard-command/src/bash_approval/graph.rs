//! A closed Bash/helper graph and source replacements for a bound launcher.
//!
//! The resolver is resident-owned. Neither a digest nor this graph authorizes
//! execution: the resident must judge every recorded invocation under current
//! policy and verify the platform's interpreter/system-image assurance.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use super::{Analysis, Operation, Result, Uncertainty, MAX_SOURCE_BYTES};

mod broker;
pub use broker::NativeDelivery;
mod curl;
mod inputs;
mod operations;
mod output_fds;
mod output_preparation;
pub use output_fds::{
    build_with_acknowledged_broker_outputs, build_with_acknowledged_outputs, build_with_outputs,
};

const MAX_CODE_INPUTS: usize = 64;
const MAX_GRAPH_CALLS: usize = 1024;
const MAX_RENDERED_BYTES: usize = 4 * MAX_SOURCE_BYTES;
// A helper uses one -c argument. Larger code needs a separate framed pipe,
// rather than silently exceeding a host's argument budget.

/// Source is deliberately not serializable. Only its observed digest belongs
/// in a public descriptor; frozen bytes stay in the native launch boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pub original_path: String,
    pub resolved_path: String,
    pub source: Arc<str>,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Code")
            .field("original_path", &self.original_path)
            .field("resolved_path", &self.resolved_path)
            .field("source_bytes", &self.source.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub enum Executable {
    Bash(Code),
    /// This is an acquisition result, not an immutable-execution claim.
    Native {
        resolved_path: String,
        content_sha256: String,
        openssl_config: Option<Code>,
        delivery: NativeDelivery,
    },
}

pub trait Resolver {
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str>;
    /// Full host-observed names, including exports whose values were withheld.
    fn environment_names(&self) -> &[String] {
        &[]
    }
    fn resolve_source(&self, _path: &str) -> std::result::Result<Code, &'static str> {
        Err("bash_source_unresolved")
    }
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub source_path: String,
    pub operation: Operation,
    pub resolved_path: Option<String>,
    pub broker_id: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct CodeIdentity {
    pub original_path: String,
    pub resolved_path: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug)]
pub struct OutputEffect {
    pub source_path: String,
    pub redirect: super::Redirect,
}

#[derive(Clone)]
pub struct Graph {
    pub entry_path: String,
    pub code: Vec<CodeIdentity>,
    pub sources: Vec<CodeIdentity>,
    pub startup: Vec<CodeIdentity>,
    pub native_images: BTreeMap<String, String>,
    pub brokered_images: BTreeMap<String, String>,
    pub invocations: Vec<Invocation>,
    pub writes: Vec<OutputEffect>,
    // Frozen code alone does not establish a bound output/effect boundary.
    frozen_source: String,
    outputs_bound: bool,
    initial_output: Option<super::Redirect>,
}

impl Graph {
    /// The sole output may be prepared at launch only when initialization is
    /// the first material operation. This is not permission to open it.
    pub fn initial_output(&self) -> Option<&super::Redirect> {
        self.initial_output.as_ref()
    }

    pub fn source_for_launch(&self) -> Result<&str> {
        if !self.writes.is_empty() && !self.outputs_bound {
            return Err(Uncertainty {
                reason: "bash_output_handles_required",
                line: 1,
            });
        }
        Ok(&self.frozen_source)
    }

    /// Frozen source is the dominant retained allocation in an analysis cache.
    /// Callers may use this length only to bound cache memory, never as identity.
    pub fn frozen_source_bytes(&self) -> usize {
        self.frozen_source.len()
    }
}

impl std::fmt::Debug for Graph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Graph")
            .field("code", &self.code)
            .field("sources", &self.sources)
            .field("startup", &self.startup)
            .field("native_images", &self.native_images)
            .field("brokered_images", &self.brokered_images)
            .field("invocation_count", &self.invocations.len())
            .field("write_count", &self.writes.len())
            .field("frozen_bytes", &self.frozen_source.len())
            .finish()
    }
}

struct Builder<'a> {
    resolver: &'a dyn Resolver,
    environment: &'a BTreeMap<String, String>,
    deadline: Instant,
    code: BTreeMap<String, CodeIdentity>,
    sources: BTreeMap<String, CodeIdentity>,
    startup: BTreeMap<String, CodeIdentity>,
    snapshots: BTreeMap<String, String>,
    native_images: BTreeMap<String, String>,
    brokered_images: BTreeMap<String, String>,
    broker_ids: BTreeMap<(String, usize, usize), u16>,
    invocations: Vec<Invocation>,
    writes: Vec<OutputEffect>,
    output_fds: Option<&'a BTreeMap<String, u32>>,
    active: BTreeSet<String>,
    bytes: usize,
    expanded_bytes: usize,
    initial_output: Option<super::Redirect>,
}

/// Resolve and freeze every helper reached by these exact arguments.
pub fn build(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
) -> Result<Graph> {
    build_inner(entry, argv, environment, resolver, deadline, None)
}

fn build_inner(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: Option<&BTreeMap<String, u32>>,
) -> Result<Graph> {
    let mut builder = Builder {
        resolver,
        environment,
        deadline,
        code: BTreeMap::new(),
        sources: BTreeMap::new(),
        startup: BTreeMap::new(),
        snapshots: BTreeMap::new(),
        native_images: BTreeMap::new(),
        brokered_images: BTreeMap::new(),
        broker_ids: BTreeMap::new(),
        invocations: Vec::new(),
        writes: Vec::new(),
        output_fds,
        active: BTreeSet::new(),
        bytes: 0,
        expanded_bytes: 0,
        initial_output: None,
    };
    let frozen_source = builder.visit(&entry, argv)?;
    let frozen_source = broker::render(frozen_source, !builder.brokered_images.is_empty())?;
    if output_fds.is_some() {
        output_preparation::validate_order(&builder.writes)?;
        output_preparation::validate(
            &entry.original_path,
            &builder.writes,
            builder.initial_output.as_ref(),
        )?;
    }
    Ok(Graph {
        entry_path: entry.original_path,
        code: builder.code.into_values().collect(),
        sources: builder.sources.into_values().collect(),
        startup: builder.startup.into_values().collect(),
        native_images: builder.native_images,
        brokered_images: builder.brokered_images,
        invocations: builder.invocations,
        writes: builder.writes,
        frozen_source,
        outputs_bound: output_fds.is_some(),
        initial_output: builder.initial_output,
    })
}

impl Builder<'_> {
    fn visit(&mut self, code: &Code, argv: &[String]) -> Result<String> {
        let entry = self.active.is_empty();
        self.register(code, inputs::Kind::Code)?;
        self.active.insert(code.resolved_path.clone());
        let analysis =
            super::source::analyze(code, argv, self.environment, self.resolver, self.deadline)?;
        if entry && self.output_fds.is_some() {
            self.initial_output = output_preparation::initial(&analysis);
        }
        let transformed = self.operations(code, analysis)?;
        self.active.remove(&code.resolved_path);
        Ok(transformed)
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
