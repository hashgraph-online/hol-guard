//! Literal sources share argv, variables and the enclosing resource budget.
//! No source body is executed while resolving or analyzing it.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use super::{graph, Analysis, Node, Operation, Result, State, Uncertainty, MAX_SOURCE_BYTES};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Occurrence {
    pub command_start: usize,
    pub start: usize,
    pub end: usize,
    pub code: graph::Code,
    pub analysis: Analysis,
    pub empty_program: bool,
}

pub(super) struct Context<'a> {
    resolver: &'a dyn graph::Resolver,
    active: BTreeSet<String>,
    seen: BTreeMap<String, String>,
    bytes: usize,
}

impl<'a> Context<'a> {
    pub(super) fn environment_names(&self) -> &[String] {
        self.resolver.environment_names()
    }

    fn new(resolver: &'a dyn graph::Resolver, code: &graph::Code) -> Self {
        Self {
            resolver,
            active: BTreeSet::from([code.resolved_path.clone()]),
            seen: BTreeMap::from([(
                code.resolved_path.clone(),
                hex::encode(Sha256::digest(code.source.as_bytes())),
            )]),
            bytes: code.source.len(),
        }
    }

    fn load(&mut self, path: &str) -> std::result::Result<graph::Code, &'static str> {
        let code = self.resolver.resolve_source(path)?;
        if code.original_path.is_empty()
            || code.original_path.len() > 4096
            || !code.resolved_path.starts_with('/')
            || code.resolved_path.len() > 4096
            || code.original_path.contains('\0')
            || code.resolved_path.contains('\0')
            || code.source.contains('\0')
        {
            return Err("bash_source_input_invalid");
        }
        if self.active.contains(&code.resolved_path) {
            return Err("bash_source_cycle");
        }
        if code.source.len() > MAX_SOURCE_BYTES {
            return Err("bash_source_graph_bounds");
        }
        let digest = hex::encode(Sha256::digest(code.source.as_bytes()));
        if let Some(previous) = self.seen.get(&code.resolved_path) {
            if previous != &digest {
                return Err("bash_source_changed_during_analysis");
            }
        } else {
            self.bytes = self.bytes.saturating_add(code.source.len());
            if self.bytes > MAX_SOURCE_BYTES || self.seen.len() >= 64 {
                return Err("bash_source_graph_bounds");
            }
            self.seen.insert(code.resolved_path.clone(), digest);
        }
        self.active.insert(code.resolved_path.clone());
        Ok(code)
    }
}

pub(super) fn analyze(
    code: &graph::Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn graph::Resolver,
    deadline: std::time::Instant,
) -> Result<Analysis> {
    super::analyze_inner(
        &code.source,
        argv,
        environment,
        deadline,
        Some(Context::new(resolver, code)),
    )
}

impl State<'_, '_> {
    pub(super) fn source_command(
        &mut self,
        node: Node<'_>,
        name: Node<'_>,
        argv: Vec<String>,
        depth: usize,
    ) -> Result<()> {
        if argv.len() != 2
            || argv[1].is_empty()
            || argv[1].starts_with('-')
            || (0..node.child_count())
                .any(|index| node.field_name_for_child(index as u32) == Some("redirect"))
        {
            return Err(self.error(node, "bash_source_arguments_unproven"));
        }
        self.charge(argv[0].len(), node)?;
        let mut context = self
            .source_context
            .take()
            .ok_or_else(|| self.error(node, "bash_source_resolver_unavailable"))?;
        let code = context.load(&argv[1]).map_err(|reason| Uncertainty {
            reason,
            line: node.start_position().row + 1,
        })?;
        let tree = super::parse(&code.source, self.deadline)?;
        let mut cursor = tree.root_node().walk();
        let empty_program = !tree
            .root_node()
            .named_children(&mut cursor)
            .any(|node| node.kind() != "comment");
        let mut child = State {
            source: &code.source,
            argv: self.argv,
            variables: std::mem::take(&mut self.variables),
            analysis: Analysis::default(),
            stopped: false,
            deadline: self.deadline,
            steps: self.steps,
            expanded_bytes: self.expanded_bytes,
            total_effects: self.total_effects,
            source_context: Some(context),
            exported_names: self.exported_names,
        };
        child.walk(tree.root_node(), depth + 1)?;
        self.variables = std::mem::take(&mut child.variables);
        self.stopped = child.stopped;
        self.steps = child.steps;
        self.expanded_bytes = child.expanded_bytes;
        self.total_effects = child.total_effects;
        let mut context = child
            .source_context
            .take()
            .expect("source context remains resident-owned");
        context.active.remove(&code.resolved_path);
        self.source_context = Some(context);
        let analysis = std::mem::take(&mut child.analysis);
        drop(child);
        self.analysis.sources.push(Occurrence {
            command_start: name.start_byte(),
            start: node.start_byte(),
            end: node.end_byte(),
            code,
            analysis,
            empty_program,
        });
        self.analysis.operations.push(Operation {
            argv,
            line: node.start_position().row + 1,
            command_start: name.start_byte(),
            command_end: name.end_byte(),
        });
        Ok(())
    }
}
