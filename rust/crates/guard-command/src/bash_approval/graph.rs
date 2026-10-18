//! A closed Bash/helper graph and source replacements for a bound launcher.
//!
//! The resolver is resident-owned. Neither a digest nor this graph authorizes
//! execution: the resident must judge every recorded invocation under current
//! policy and verify the platform's interpreter/system-image assurance.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use super::{Analysis, Operation, Result, Uncertainty, MAX_SOURCE_BYTES};

mod inputs;
mod output_preparation;

const MAX_CODE_INPUTS: usize = 64;
const MAX_GRAPH_CALLS: usize = 1024;
const MAX_RENDERED_BYTES: usize = 4 * MAX_SOURCE_BYTES;
// A helper uses one -c argument. Larger code needs a separate framed pipe,
// rather than silently exceeding a host's argument budget.
const MAX_HELPER_ARGUMENT_BYTES: usize = 64 * 1024;

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

pub struct Graph {
    pub entry_path: String,
    pub code: Vec<CodeIdentity>,
    pub sources: Vec<CodeIdentity>,
    pub native_images: BTreeMap<String, String>,
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
}

impl std::fmt::Debug for Graph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Graph")
            .field("code", &self.code)
            .field("sources", &self.sources)
            .field("native_images", &self.native_images)
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
    snapshots: BTreeMap<String, String>,
    native_images: BTreeMap<String, String>,
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

/// Render again using the same captured resolver inputs and native-owned FDs.
/// Neither the FD table nor these source bytes grant permission to execute.
pub fn build_with_outputs(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
    output_fds: &BTreeMap<String, u32>,
) -> Result<Graph> {
    let unique = output_fds.values().copied().collect::<BTreeSet<_>>();
    if output_fds.len() > 64
        || unique.len() != output_fds.len()
        || unique
            .iter()
            .enumerate()
            .any(|(index, fd)| *fd != 6 + index as u32)
    {
        return Err(Uncertainty {
            reason: "bash_output_descriptor_bounds",
            line: 1,
        });
    }
    build_inner(
        entry,
        argv,
        environment,
        resolver,
        deadline,
        Some(output_fds),
    )
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
        snapshots: BTreeMap::new(),
        native_images: BTreeMap::new(),
        invocations: Vec::new(),
        writes: Vec::new(),
        output_fds,
        active: BTreeSet::new(),
        bytes: 0,
        expanded_bytes: 0,
        initial_output: None,
    };
    let frozen_source = builder.visit(&entry, argv)?;
    if output_fds.is_some() {
        validate_output_order(&builder.writes)?;
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
        native_images: builder.native_images,
        invocations: builder.invocations,
        writes: builder.writes,
        frozen_source,
        outputs_bound: output_fds.is_some(),
        initial_output: builder.initial_output,
    })
}

// A held append descriptor preserves a first truncate followed by appends,
// or appends alone. It cannot model a later truncate. Cross-source ordering
// needs a separate proof; collection order is not execution order there.
fn validate_output_order(writes: &[OutputEffect]) -> Result<()> {
    let mut owners = BTreeMap::new();
    for effect in writes {
        if let Some(owner) = owners.insert(&effect.redirect.path, &effect.source_path) {
            if owner != &effect.source_path || !effect.redirect.append {
                return Err(Uncertainty {
                    reason: "bash_output_order_unproven",
                    line: effect.redirect.line,
                });
            }
        }
    }
    Ok(())
}

impl Builder<'_> {
    fn visit(&mut self, code: &Code, argv: &[String]) -> Result<String> {
        let entry = self.active.is_empty();
        self.register(code, false)?;
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

    fn operations(&mut self, code: &Code, analysis: Analysis) -> Result<String> {
        let mut replacements = BTreeMap::<(usize, usize), String>::new();
        let mut replacement_bytes = 0usize;
        let mut sources = analysis.sources;
        for operation in analysis.operations {
            self.expanded_bytes = self
                .expanded_bytes
                .saturating_add(operation.argv.iter().map(String::len).sum::<usize>());
            if self.expanded_bytes > MAX_SOURCE_BYTES {
                return Err(Uncertainty {
                    reason: "bash_expanded_data_bounds",
                    line: operation.line,
                });
            }
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            let mut invocation = Invocation {
                source_path: code.original_path.clone(),
                operation: operation.clone(),
                resolved_path: None,
            };
            let name = &operation.argv[0];
            let mut replacement_span = (operation.command_start, operation.command_end);
            let replacement = if matches!(name.as_str(), "source" | ".") {
                let index = sources
                    .iter()
                    .position(|source| source.command_start == operation.command_start)
                    .ok_or(Uncertainty {
                        reason: "bash_source_analysis_missing",
                        line: operation.line,
                    })?;
                let source = sources.remove(index);
                self.register(&source.code, true)?;
                self.active.insert(source.code.resolved_path.clone());
                invocation.resolved_path = Some(source.code.resolved_path.clone());
                let empty = source.empty_program;
                let body = self.operations(&source.code, source.analysis)?;
                self.active.remove(&source.code.resolved_path);
                replacement_span = (source.start, source.end);
                Some(format!(
                    "{{\n{}{}\n}}",
                    if empty { ":\n" } else { "" },
                    body
                ))
            } else if matches!(
                name.as_str(),
                ":" | "printf" | "echo" | "set" | "test" | "[" | "exit" | "true" | "false"
            ) {
                None
            } else {
                let executable =
                    self.resolver
                        .resolve(&operation.argv)
                        .map_err(|reason| Uncertainty {
                            reason,
                            line: operation.line,
                        })?;
                match executable {
                    Executable::Native {
                        resolved_path,
                        content_sha256,
                    } => {
                        if !resolved_path.starts_with('/')
                            || resolved_path.len() > 4096
                            || resolved_path.contains('\0')
                            || content_sha256.len() != 64
                            || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(Uncertainty {
                                reason: "bash_native_identity_invalid",
                                line: operation.line,
                            });
                        }
                        invocation.resolved_path = Some(resolved_path.clone());
                        if !self.native_images.contains_key(&resolved_path)
                            && self.code.len() + self.sources.len() + self.native_images.len() + 1
                                >= MAX_CODE_INPUTS
                        {
                            return Err(Uncertainty {
                                reason: "bash_graph_bounds",
                                line: operation.line,
                            });
                        }
                        if self
                            .native_images
                            .get(&resolved_path)
                            .is_some_and(|previous| previous != &content_sha256)
                        {
                            return Err(Uncertainty {
                                reason: "bash_code_changed_during_analysis",
                                line: operation.line,
                            });
                        }
                        self.native_images
                            .insert(resolved_path.clone(), content_sha256);
                        // Keep the original native argv[0] while pinning the
                        // executable path. A direct path replacement changes it.
                        let launch = format!("exec -a \"$0\" {} \"$@\"", quote(&resolved_path));
                        Some(format!(
                            "/bin/bash --noprofile --norc -c {} {}",
                            quote(&launch),
                            quote(name)
                        ))
                    }
                    Executable::Bash(helper) => {
                        invocation.resolved_path = Some(helper.resolved_path.clone());
                        let mut helper_argv = operation.argv.clone();
                        helper_argv[0] = helper.original_path.clone();
                        let frozen = self.visit(&helper, &helper_argv)?;
                        if frozen.len() > MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        // This closure uses Bash's protected system interpreter.
                        // The native backend must verify that assurance, enforce
                        // the argv size and attach the reviewed effect boundary.
                        let encoded = quote(&frozen);
                        if encoded.len() > MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        Some(format!(
                            "/bin/bash --noprofile --norc -c {} {}",
                            encoded,
                            quote(&helper.original_path)
                        ))
                    }
                }
            };
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            self.invocations.push(invocation);
            if let Some(replacement) = replacement {
                let span = replacement_span;
                if replacements
                    .get(&span)
                    .is_some_and(|previous| previous != &replacement)
                {
                    // Different loop iterations may select different helper
                    // branches. Their source still must freeze identically.
                    return Err(Uncertainty {
                        reason: "bash_context_dependent_rewrite",
                        line: operation.line,
                    });
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = replacements.entry(span)
                {
                    replacement_bytes += replacement.len();
                    if replacement_bytes + code.source.len() > MAX_RENDERED_BYTES {
                        return Err(Uncertainty {
                            reason: "bash_rendered_source_bounds",
                            line: operation.line,
                        });
                    }
                    entry.insert(replacement);
                }
            }
        }
        for redirect in analysis.writes {
            if let Some(outputs) = self.output_fds {
                let fd = outputs.get(&redirect.path).ok_or(Uncertainty {
                    reason: "bash_output_handle_missing",
                    line: redirect.line,
                })?;
                let replacement = format!(">&{fd}");
                let span = (redirect.start, redirect.end);
                if replacements
                    .get(&span)
                    .is_some_and(|previous| previous != &replacement)
                {
                    return Err(Uncertainty {
                        reason: "bash_context_dependent_output",
                        line: redirect.line,
                    });
                }
                replacements.insert(span, replacement);
            }
            self.writes.push(OutputEffect {
                source_path: code.original_path.clone(),
                redirect,
            });
        }
        let mut source = code.source.to_string();
        for ((start, end), replacement) in replacements.into_iter().rev() {
            source.replace_range(start..end, &replacement);
        }
        if source.len() > MAX_RENDERED_BYTES {
            return Err(Uncertainty {
                reason: "bash_rendered_source_bounds",
                line: 1,
            });
        }
        Ok(source)
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
