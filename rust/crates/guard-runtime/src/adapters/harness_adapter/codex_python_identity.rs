//! The module identities an expression may hold, and the import calls that
//! load Guard's CLI.

use super::*;

impl<'t> Calls<'_, 't> {
    pub(super) fn call(&mut self, node: Node<'t>) {
        if !self.in_function {
            self.module_calls.push((node, self.bindings.clone()));
        }
        self.check_call(node);
        self.visit_field(node, "function");
        let args = Args::of(node, self.src);
        self.visit_all(args.positional);
        self.visit_all(args.keywords.into_iter().map(|(_, value)| value));
    }

    pub(super) fn check_call(&mut self, node: Node<'t>) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let args = Args::of(node, self.src);
        for identity in self.identity(Expr::Node(function)) {
            let Some(keyword) = import_keyword(&identity) else {
                continue;
            };
            let module = args
                .first_or(keyword)
                .and_then(|m| string_value(m, self.src));
            if module.is_some_and(|m| GUARD_MODULES.contains(&m.as_str())) {
                self.found = true;
            }
        }
    }

    /// `_identity`: the module identities an expression may hold.
    pub(super) fn identity(&mut self, expr: Expr<'_, 't>) -> Ids {
        if !self.enter() {
            return Ids::new();
        }
        let ids = self.identity_of(expr);
        self.depth -= 1;
        ids
    }

    pub(super) fn identity_of(&mut self, expr: Expr<'_, 't>) -> Ids {
        let node = match expr {
            Expr::List(items) => return self.sequence_ids(items),
            Expr::Node(node) => bare(node),
        };
        match node.kind() {
            "identifier" => {
                let name = self.name(node);
                self.bindings
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| default_ids(&name))
            }
            "attribute" => {
                let (Some(object), Some(attribute)) = (
                    node.child_by_field_name("object"),
                    node.child_by_field_name("attribute"),
                ) else {
                    return Ids::new();
                };
                let attribute = self.name(attribute);
                let bases = self.identity(Expr::Node(object));
                bases
                    .into_iter()
                    .map(|base| format!("{base}.{attribute}"))
                    .collect()
            }
            "list" | "tuple" | "expression_list" => {
                let mut values = Vec::new();
                if literal_sequence(Expr::Node(node), &mut values) {
                    self.sequence_ids(&values)
                } else {
                    Ids::new()
                }
            }
            "subscript" => self.subscript_ids(node),
            "call" => self.import_call_ids(node),
            _ => Ids::new(),
        }
    }

    pub(super) fn sequence_ids(&mut self, values: &[Node<'t>]) -> Ids {
        let mut ids = Ids::new();
        for (index, item) in values.iter().enumerate() {
            let mut held = self.identity(Expr::Node(*item));
            if held.is_empty() {
                held.insert(String::new());
            }
            ids.extend(
                held.into_iter()
                    .map(|id| format!("sequence:{}:{index}:{id}", values.len())),
            );
        }
        ids
    }

    pub(super) fn subscript_ids(&mut self, node: Node<'t>) -> Ids {
        let indexes = field_nodes(node, "subscript");
        let (Some(value), [index]) = (node.child_by_field_name("value"), indexes.as_slice()) else {
            return Ids::new();
        };
        let index = bare(*index);
        let negative = index.kind() == "unary_operator"
            && index
                .child_by_field_name("operator")
                .is_some_and(|op| text(op, self.src) == "-");
        let constant = if negative {
            index.child_by_field_name("argument")
        } else {
            Some(index)
        };
        let Some(selected) = constant.and_then(|c| int_value(c, self.src)) else {
            return Ids::new();
        };
        let selected = if negative { -selected } else { selected };
        let mut ids = Ids::new();
        for identity in self.identity(Expr::Node(value)) {
            let parts: Vec<&str> = identity.splitn(4, ':').collect();
            let [kind, length, position, held] = parts.as_slice() else {
                continue;
            };
            let (Ok(length), Ok(position)) = (length.parse::<i128>(), position.parse::<i128>())
            else {
                continue;
            };
            let wanted = if selected < 0 {
                selected + length
            } else {
                selected
            };
            if *kind == "sequence" && position == wanted && !held.is_empty() {
                ids.insert((*held).to_owned());
            }
        }
        ids
    }

    /// `__import__("runpy")` or `importlib.import_module("runpy")` holds the
    /// module it names, when it names an import API's own module.
    pub(super) fn import_call_ids(&mut self, node: Node<'t>) -> Ids {
        let Some(function) = node.child_by_field_name("function") else {
            return Ids::new();
        };
        let args = Args::of(node, self.src);
        for identity in self.identity(Expr::Node(function)) {
            if identity != BUILTIN_IMPORT && identity != "importlib.import_module" {
                continue;
            }
            let module = args.first_or("name");
            let level = args
                .positional
                .get(4)
                .copied()
                .or_else(|| args.keyword("level"));
            let absolute = level.is_none_or(|level| int_value(level, self.src) == Some(0));
            if identity == BUILTIN_IMPORT && !absolute {
                continue;
            }
            if let Some(module) = module.and_then(|m| string_value(m, self.src)) {
                if IMPORT_MODULES.contains(&module.as_str()) {
                    return Ids::from([module]);
                }
            }
        }
        Ids::new()
    }
}
