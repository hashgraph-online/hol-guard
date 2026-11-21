//! The scoped statements `_GuardImportCalls` reads: imports, definitions,
//! comprehensions, branches, handlers and deletions.

use super::*;

impl<'t> Calls<'_, 't> {
    pub(super) fn dotted(&self, node: Node<'_>) -> String {
        let parts: Vec<&str> = kids(node).into_iter().map(|n| text(n, self.src)).collect();
        parts.join(".")
    }

    pub(super) fn import(&mut self, node: Node<'t>) {
        for imported in field_nodes(node, "name") {
            if imported.kind() == "aliased_import" {
                let (Some(name), Some(alias)) = (
                    imported.child_by_field_name("name"),
                    imported.child_by_field_name("alias"),
                ) else {
                    continue;
                };
                let identity = self.dotted(name);
                self.bind(&self.name(alias), Ids::from([identity]));
            } else {
                let full = self.dotted(imported);
                let root = full.split('.').next().unwrap_or_default().to_owned();
                self.bind(&root, Ids::from([root.clone()]));
            }
        }
    }

    pub(super) fn import_from(&mut self, node: Node<'t>) {
        let module = node
            .child_by_field_name("module_name")
            .filter(|n| n.kind() == "dotted_name")
            .map(|n| self.dotted(n));
        for imported in field_nodes(node, "name") {
            let (name, alias) = if imported.kind() == "aliased_import" {
                let name = imported.child_by_field_name("name").map(|n| self.dotted(n));
                let alias = imported.child_by_field_name("alias").map(|n| self.name(n));
                (name.unwrap_or_default(), alias)
            } else {
                (self.dotted(imported), None)
            };
            let identity = module
                .as_ref()
                .map(|m| format!("{m}.{name}"))
                .unwrap_or_default();
            self.bind(&alias.unwrap_or(name), Ids::from([identity]));
        }
    }

    pub(super) fn definition(&mut self, node: Node<'t>) {
        if node.kind() == "class_definition" {
            self.class(node);
        } else {
            self.function(node);
        }
    }

    /// `visit_FunctionDef` and `visit_Lambda`: read the defaults now and the
    /// body once the module bindings it can see are known.
    pub(super) fn function(&mut self, node: Node<'t>) {
        let parameters = node.child_by_field_name("parameters");
        let items = parameters.map(kids).unwrap_or_default();
        for item in &items {
            if matches!(item.kind(), "default_parameter" | "typed_default_parameter") {
                self.visit_field(*item, "value");
            }
        }
        if let Some(name) = node.child_by_field_name("name") {
            self.bindings.insert(self.name(name), Ids::new());
        }
        let mut scope = Scope::new();
        for item in items {
            let (name, ids) = match item.kind() {
                "identifier" => (Some(item), Ids::new()),
                "default_parameter" | "typed_default_parameter" => {
                    let value = item.child_by_field_name("value");
                    let ids = value
                        .map(|v| self.identity(Expr::Node(v)))
                        .unwrap_or_default();
                    (item.child_by_field_name("name"), ids)
                }
                "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
                    let inner = kids(item).into_iter().find(|n| n.kind() != "type");
                    let inner = inner.map(|n| kids(n).first().copied().unwrap_or(n));
                    (inner.filter(|n| n.kind() == "identifier"), Ids::new())
                }
                _ => (None, Ids::new()),
            };
            if let Some(name) = name.filter(|n| n.kind() == "identifier") {
                scope.insert(self.name(name), ids);
            }
        }
        let enclosing = self
            .class_globals
            .clone()
            .unwrap_or_else(|| self.bindings.clone());
        self.deferred.push(Deferred {
            node,
            enclosing,
            parameters: scope,
        });
    }

    pub(super) fn class(&mut self, node: Node<'t>) {
        if let Some(bases) = node.child_by_field_name("superclasses") {
            let bases = kids(bases);
            self.visit_all(
                bases
                    .into_iter()
                    .filter(|n| !matches!(n.kind(), "keyword_argument" | "dictionary_splat")),
            );
        }
        if let Some(name) = node.child_by_field_name("name") {
            self.bindings.insert(self.name(name), Ids::new());
        }
        let outer = self.bindings.clone();
        let enclosing = self.class_globals.replace(outer.clone());
        self.visit_field(node, "body");
        self.bindings = outer;
        self.class_globals = enclosing;
    }

    pub(super) fn comprehension(&mut self, node: Node<'t>) {
        let owner = match self.walrus.last() {
            Some(owner) => *owner,
            None => self.class_globals.is_none().then_some(self.saved.len()),
        };
        self.walrus.push(owner);
        let mut generators: Vec<(Node<'t>, Vec<Node<'t>>)> = Vec::new();
        for item in kids(node) {
            match item.kind() {
                "for_in_clause" => generators.push((item, Vec::new())),
                "if_clause" => {
                    if let Some((_, conditions)) = generators.last_mut() {
                        conditions.extend(kids(item));
                    }
                }
                _ => {}
            }
        }
        if let Some((first, _)) = generators.first() {
            self.visit_field(*first, "right");
        }
        let fresh = self
            .class_globals
            .clone()
            .unwrap_or_else(|| self.bindings.clone());
        let outer = std::mem::replace(&mut self.bindings, fresh);
        self.saved.push(outer);
        let enclosing = self.class_globals.take();
        for (index, (generator, conditions)) in generators.into_iter().enumerate() {
            if index > 0 {
                self.visit_field(generator, "right");
            }
            self.visit_targets(generator, "left");
            self.visit_all(conditions);
        }
        self.visit_field(node, "body");
        if let Some(outer) = self.saved.pop() {
            self.bindings = outer;
        }
        self.class_globals = enclosing;
        self.walrus.pop();
    }

    /// `visit_If`, an `elif` read as the `else` branch's nested `if`.
    pub(super) fn if_chain(&mut self, node: Node<'t>, alternatives: &[Node<'t>]) {
        self.visit_field(node, "condition");
        let before = self.bindings.clone();
        self.visit_field(node, "consequence");
        let positive = std::mem::replace(&mut self.bindings, before);
        if let Some((first, rest)) = alternatives.split_first() {
            if first.kind() == "elif_clause" {
                self.if_chain(*first, rest);
            } else {
                self.visit_field(*first, "body");
            }
        }
        self.merge(&positive);
    }

    pub(super) fn try_statement(&mut self, node: Node<'t>) {
        let parts = kids(node);
        let of = |kind: &str| {
            parts
                .iter()
                .copied()
                .filter(|n| n.kind() == kind)
                .collect::<Vec<_>>()
        };
        if !of("except_group_clause").is_empty() {
            self.visit_all(parts.clone());
            return;
        }
        let before = self.bindings.clone();
        self.visit_field(node, "body");
        let after_body = self.bindings.clone();
        for clause in of("else_clause") {
            self.visit_field(clause, "body");
        }
        let mut alternatives = self.bindings.clone();
        for handler in of("except_clause") {
            self.bindings = before.clone();
            self.merge(&after_body);
            self.handler(handler);
            self.merge(&alternatives);
            alternatives = self.bindings.clone();
        }
        self.bindings = alternatives;
        self.visit_all(of("finally_clause"));
    }

    /// `except Type as name:` parses as an `as_pattern` whose target is the
    /// name the handler binds.
    pub(super) fn handler(&mut self, node: Node<'t>) {
        let mut alias = None;
        for value in field_nodes(node, "value") {
            if value.kind() != "as_pattern" {
                self.visit(value);
                continue;
            }
            for part in kids(value) {
                if part.kind() == "as_pattern_target" {
                    alias = kids(part).first().map(|n| self.name(bare(*n)));
                } else {
                    self.visit(part);
                }
            }
        }
        if let Some(name) = &alias {
            self.bindings.insert(name.clone(), Ids::new());
        }
        self.visit_all(kids(node).into_iter().filter(|n| n.kind() == "block"));
        if let Some(name) = alias {
            self.bindings.remove(&name);
        }
    }

    pub(super) fn with_item(&mut self, node: Node<'t>) {
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        if value.kind() != "as_pattern" {
            self.visit(value);
            return;
        }
        for part in kids(value) {
            if part.kind() == "as_pattern_target" {
                for target in kids(part) {
                    self.target(target);
                }
            } else {
                self.visit(part);
            }
        }
    }

    pub(super) fn delete(&mut self, node: Node<'t>) {
        for item in kids(node) {
            let targets = if item.kind() == "expression_list" {
                kids(item)
            } else {
                vec![item]
            };
            for target in targets {
                if bare(target).kind() == "identifier" {
                    self.bindings.remove(&self.name(bare(target)));
                } else {
                    self.visit(target);
                }
            }
        }
    }
}
