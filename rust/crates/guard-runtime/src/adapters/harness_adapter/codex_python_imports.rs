//! `_GuardImportCalls`: whether an inline Python script imports Guard's CLI
//! through `runpy`, `importlib` or `__import__`, read from its syntax without
//! running it.
//!
//! Names bind to the module identities they may hold. A branch merges what
//! each side bound, a function body is read against the module bindings it
//! can see when called, and a `global` written in a body reaches later
//! module-level calls. A structure too deep to read keeps the possible
//! conflict, as Python's `RecursionError` did.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use super::codex_python_values::{
    bare, count_bodies, field_nodes, int_value, kids, literal_sequence, string_value, text, Args,
    Expr, SEQUENCES,
};

type Ids = BTreeSet<String>;
type Scope = BTreeMap<String, Ids>;

const BUILTIN_IMPORT: &str = "builtins.__import__";
const GUARD_MODULES: [&str; 2] = ["codex_plugin_scanner.cli", "codex_plugin_scanner"];
const IMPORT_MODULES: [&str; 3] = ["runpy", "importlib", "builtins"];
const MAX_DEPTH: usize = 300;

#[path = "codex_python_identity.rs"]
mod identity;
#[path = "codex_python_scopes.rs"]
mod scopes;

/// `_IMPORT_APIS`: the keyword each import API takes its module by.
fn import_keyword(identity: &str) -> Option<&'static str> {
    match identity {
        "runpy.run_module" => Some("mod_name"),
        "importlib.import_module" | BUILTIN_IMPORT => Some("name"),
        _ => None,
    }
}

fn default_ids(name: &str) -> Ids {
    if name == "__import__" {
        Ids::from([BUILTIN_IMPORT.to_owned()])
    } else {
        Ids::new()
    }
}

#[derive(Clone)]
struct Deferred<'t> {
    node: Node<'t>,
    enclosing: Scope,
    parameters: Scope,
}

pub(super) struct Calls<'s, 't> {
    src: &'s str,
    bindings: Scope,
    pub(super) found: bool,
    deep: bool,
    depth: usize,
    class_globals: Option<Scope>,
    /// The scope each enclosing comprehension's walrus binds into, as an
    /// index into `saved` (the index the outer scope takes once saved).
    walrus: Vec<Option<usize>>,
    saved: Vec<Scope>,
    module_bindings: Scope,
    global_names: BTreeSet<String>,
    global_updates: Scope,
    deferred: Vec<Deferred<'t>>,
    module_calls: Vec<(Node<'t>, Scope)>,
    in_function: bool,
}

impl<'s, 't> Calls<'s, 't> {
    pub(super) fn new(src: &'s str) -> Self {
        Calls {
            src,
            bindings: Scope::from([("__import__".to_owned(), default_ids("__import__"))]),
            found: false,
            deep: false,
            depth: 0,
            class_globals: None,
            walrus: Vec::new(),
            saved: Vec::new(),
            module_bindings: Scope::new(),
            global_names: BTreeSet::new(),
            global_updates: Scope::new(),
            deferred: Vec::new(),
            module_calls: Vec::new(),
            in_function: false,
        }
    }

    /// Whether the script may import Guard's CLI, or was too deep to tell.
    pub(super) fn imports_guard(mut self, root: Node<'t>) -> bool {
        self.visit(root);
        self.finish();
        self.found || self.deep
    }

    fn name(&self, node: Node<'_>) -> String {
        text(node, self.src).to_owned()
    }

    fn bind(&mut self, name: &str, ids: Ids) {
        if self.global_names.contains(name) {
            self.module_bindings
                .entry(name.to_owned())
                .or_default()
                .extend(ids.iter().cloned());
            self.global_updates
                .entry(name.to_owned())
                .or_default()
                .extend(ids.iter().cloned());
        }
        self.bindings.insert(name.to_owned(), ids);
    }

    fn merge(&mut self, other: &Scope) {
        let names: BTreeSet<String> = other.keys().chain(self.bindings.keys()).cloned().collect();
        for name in names {
            let mut ids = self
                .bindings
                .get(&name)
                .cloned()
                .unwrap_or_else(|| default_ids(&name));
            ids.extend(
                other
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| default_ids(&name)),
            );
            self.bindings.insert(name, ids);
        }
    }

    fn enter(&mut self) -> bool {
        if self.depth >= MAX_DEPTH {
            self.deep = true;
            return false;
        }
        self.depth += 1;
        true
    }

    fn visit(&mut self, node: Node<'t>) {
        if self.enter() {
            self.visit_node(node);
            self.depth -= 1;
        }
    }

    fn visit_all(&mut self, nodes: impl IntoIterator<Item = Node<'t>>) {
        for node in nodes {
            self.visit(node);
        }
    }

    fn visit_field(&mut self, node: Node<'t>, name: &str) {
        self.visit_all(field_nodes(node, name));
    }

    fn visit_node(&mut self, node: Node<'t>) {
        match node.kind() {
            "assignment" => self.assignment(node),
            "augmented_assignment" => {
                self.visit_field(node, "right");
                self.visit_targets(node, "left");
            }
            "named_expression" => self.walrus_binding(node),
            "import_statement" => self.import(node),
            "import_from_statement" => self.import_from(node),
            "global_statement" => {
                let names: Vec<String> = kids(node).into_iter().map(|n| self.name(n)).collect();
                self.global_names.extend(names);
            }
            "decorated_definition" => {
                for decorator in kids(node).into_iter().filter(|n| n.kind() == "decorator") {
                    self.visit_all(kids(decorator));
                }
                if let Some(definition) = node.child_by_field_name("definition") {
                    self.definition(definition);
                }
            }
            "function_definition" | "class_definition" => self.definition(node),
            "lambda" => self.function(node),
            "list_comprehension"
            | "set_comprehension"
            | "generator_expression"
            | "dictionary_comprehension" => self.comprehension(node),
            "if_statement" => {
                let alternatives = field_nodes(node, "alternative");
                self.if_chain(node, &alternatives);
            }
            "for_statement" => {
                self.visit_field(node, "right");
                let before = self.bindings.clone();
                self.visit_targets(node, "left");
                self.visit_field(node, "body");
                self.visit_field(node, "alternative");
                self.merge(&before);
            }
            "while_statement" => {
                self.visit_field(node, "condition");
                let before = self.bindings.clone();
                self.visit_field(node, "body");
                self.visit_field(node, "alternative");
                self.merge(&before);
            }
            "try_statement" => self.try_statement(node),
            "except_clause" | "except_group_clause" => self.handler(node),
            "with_item" => self.with_item(node),
            "delete_statement" => self.delete(node),
            "call" => self.call(node),
            "keyword_argument" => self.visit_field(node, "value"),
            "identifier" | "comment" => {}
            _ => self.visit_all(kids(node)),
        }
    }

    fn visit_targets(&mut self, node: Node<'t>, name: &str) {
        for target in field_nodes(node, name) {
            self.target(target);
        }
    }

    /// A name in a store context binds to nothing known.
    fn target(&mut self, node: Node<'t>) {
        if !self.enter() {
            return;
        }
        let node = bare(node);
        match node.kind() {
            "identifier" => self.bind(&self.name(node), Ids::new()),
            kind if SEQUENCES.contains(&kind) => {
                for item in kids(node) {
                    self.target(item);
                }
            }
            "list_splat_pattern" | "list_splat" => {
                for item in kids(node) {
                    self.target(item);
                }
            }
            _ => self.visit(node),
        }
        self.depth -= 1;
    }

    fn assignment(&mut self, node: Node<'t>) {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        if let Some(annotation) = node.child_by_field_name("type") {
            self.visit(annotation);
            let (Some(left), Some(right)) = (left, right) else {
                return;
            };
            self.visit(right);
            let ids = self.identity(Expr::Node(right));
            self.target(left);
            if bare(left).kind() == "identifier" {
                self.bind(&self.name(bare(left)), ids);
            }
            return;
        }
        let mut targets: Vec<Node<'t>> = left.into_iter().collect();
        let mut value = right;
        while let Some(inner) =
            value.filter(|v| v.kind() == "assignment" && v.child_by_field_name("type").is_none())
        {
            targets.extend(inner.child_by_field_name("left"));
            value = inner.child_by_field_name("right");
        }
        let Some(value) = value else {
            return;
        };
        self.visit(value);
        let mut bindings = Vec::new();
        for target in &targets {
            self.assignment_bindings(*target, Expr::Node(value), &mut bindings);
        }
        for target in targets {
            self.target(target);
        }
        for (name, ids) in bindings {
            self.bind(&name, ids);
        }
    }

    /// `_assignment_bindings`: what each name a literal unpacking binds holds.
    fn assignment_bindings(
        &mut self,
        target: Node<'t>,
        value: Expr<'_, 't>,
        out: &mut Vec<(String, Ids)>,
    ) {
        if !self.enter() {
            return;
        }
        let target = bare(target);
        if target.kind() == "identifier" {
            let ids = self.identity(value);
            out.push((self.name(target), ids));
        } else {
            let mut values = Vec::new();
            if SEQUENCES.contains(&target.kind()) && literal_sequence(value, &mut values) {
                self.unpack(target, &values, out);
            }
        }
        self.depth -= 1;
    }

    fn unpack(&mut self, target: Node<'t>, values: &[Node<'t>], out: &mut Vec<(String, Ids)>) {
        let elements = kids(target);
        let starred = |n: &Node<'_>| matches!(n.kind(), "list_splat_pattern" | "list_splat");
        let stars: Vec<usize> = (0..elements.len())
            .filter(|i| starred(&elements[*i]))
            .collect();
        if stars.is_empty() && elements.len() == values.len() {
            for (item, value) in elements.iter().zip(values) {
                self.assignment_bindings(*item, Expr::Node(*value), out);
            }
        } else if let ([index], true) = (stars.as_slice(), values.len() + 1 >= elements.len()) {
            let index = *index;
            let suffix = &elements[index + 1..];
            let end = values.len() - suffix.len();
            for (item, value) in elements[..index].iter().zip(values) {
                self.assignment_bindings(*item, Expr::Node(*value), out);
            }
            if let Some(rest) = kids(elements[index]).first() {
                self.assignment_bindings(*rest, Expr::List(&values[index..end]), out);
            }
            for (item, value) in suffix.iter().zip(&values[end..]) {
                self.assignment_bindings(*item, Expr::Node(*value), out);
            }
        }
    }

    fn walrus_binding(&mut self, node: Node<'t>) {
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        self.visit(value);
        let ids = self.identity(Expr::Node(value));
        let Some(name) = node.child_by_field_name("name").map(|n| self.name(n)) else {
            return;
        };
        self.bind(&name, Ids::new());
        self.bind(&name, ids.clone());
        // While the first iterable is read the owner is still the current
        // scope, which already holds the binding.
        if let Some(Some(owner)) = self.walrus.last().copied() {
            if owner < self.saved.len() {
                std::mem::swap(&mut self.bindings, &mut self.saved[owner]);
                self.bind(&name, ids);
                std::mem::swap(&mut self.bindings, &mut self.saved[owner]);
            }
        }
    }

    /// `finish`: read the deferred bodies until the globals they write stop
    /// changing, then the module-level calls with those globals.
    fn finish(&mut self) {
        self.module_bindings = self.bindings.clone();
        let roots = self.deferred.clone();
        let bodies: usize = roots.iter().map(|d| count_bodies(d.node)).sum();
        let mut settled = false;
        for _ in 0..=bodies {
            let previous = self.global_updates.clone();
            self.deferred = roots.clone();
            let mut index = 0;
            while index < self.deferred.len() {
                let body = self.deferred[index].clone();
                index += 1;
                self.bindings = body.enclosing;
                let module = self.module_bindings.clone();
                self.merge(&module);
                self.bindings.extend(body.parameters);
                self.global_names.clear();
                self.in_function = true;
                self.visit_field(body.node, "body");
            }
            if self.found || self.global_updates == previous {
                settled = true;
                break;
            }
        }
        // Cyclic aliases can grow without converging; keep the conflict.
        self.found |= !settled;
        self.in_function = false;
        self.global_names.clear();
        for (node, bindings) in std::mem::take(&mut self.module_calls) {
            self.bindings = bindings;
            for (name, ids) in self.global_updates.clone() {
                self.bindings.entry(name).or_default().extend(ids);
            }
            self.check_call(node);
        }
    }
}
