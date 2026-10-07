//! Lower author-owned inline trees through the existing native node compiler.

use super::*;

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceMatcher {
    pub(super) op: String,
    pub(super) config: Value,
    #[serde(default)]
    pub(super) matchers: Vec<SourceMatcher>,
    pub(super) producer: Option<Box<SourceMatcher>>,
    pub(super) consumer: Option<Box<SourceMatcher>>,
}

pub(super) fn source_matcher_schema() -> Value {
    serde_json::json!({
        "type":"object", "additionalProperties":false, "required":["op","config"],
        "properties": {
            "op":{"type":"string","maxLength":128},
            "config":{"type":"object"},
            "matchers":{"type":"array","maxItems":4096,"items":{"$ref":"#/$defs/matcher"}},
            "producer":{"anyOf":[{"$ref":"#/$defs/matcher"},{"type":"null"}]},
            "consumer":{"anyOf":[{"$ref":"#/$defs/matcher"},{"type":"null"}]}
        }
    })
}

#[derive(Default)]
pub(super) struct SourceGraph {
    nodes: BTreeMap<String, RawNode>,
    occurrences: usize,
    bytes: usize,
}

impl SourceGraph {
    pub(super) fn lower(
        &mut self,
        matcher: SourceMatcher,
        depth: usize,
    ) -> Result<String, &'static str> {
        if depth > MAX_DEPTH || self.occurrences >= MAX_NODES {
            return Err("command_source_matcher_budget_exceeded");
        }
        self.occurrences += 1;
        let mut children = BTreeMap::new();
        match matcher.op.as_str() {
            "any.v1" | "all.v1" => {
                if matcher.producer.is_some()
                    || matcher.consumer.is_some()
                    || matcher.matchers.is_empty()
                {
                    return Err("command_source_combinator_children_invalid");
                }
                let ids = matcher
                    .matchers
                    .into_iter()
                    .map(|child| self.lower(child, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                children.insert("matchers".to_owned(), serde_json::json!(ids));
            }
            "pipeline.v1" => {
                if !matcher.matchers.is_empty() {
                    return Err("command_source_pipeline_children_invalid");
                }
                let producer = matcher
                    .producer
                    .ok_or("command_source_pipeline_children_invalid")?;
                let consumer = matcher
                    .consumer
                    .ok_or("command_source_pipeline_children_invalid")?;
                children.insert(
                    "producer".to_owned(),
                    Value::String(self.lower(*producer, depth + 1)?),
                );
                children.insert(
                    "consumer".to_owned(),
                    Value::String(self.lower(*consumer, depth + 1)?),
                );
            }
            _ => {
                if !matcher.matchers.is_empty()
                    || matcher.producer.is_some()
                    || matcher.consumer.is_some()
                {
                    return Err("command_source_leaf_children_invalid");
                }
            }
        }
        let node = RawNode {
            op: matcher.op,
            config: matcher.config,
            children,
        };
        let canonical = serde_json::to_vec(&node).map_err(|_| "command_source_encoding_failed")?;
        let id = digest_canonical_bytes(NODE_DOMAIN, &canonical);
        if let Some(existing) = self.nodes.get(&id) {
            if serde_json::to_vec(existing).map_err(|_| "command_source_encoding_failed")?
                != canonical
            {
                return Err("command_source_node_identity_conflict");
            }
        } else {
            self.bytes = self
                .bytes
                .checked_add(canonical.len() + id.len())
                .ok_or("command_source_matcher_budget_exceeded")?;
            if self.bytes > MAX_PROGRAM_BYTES {
                return Err("command_source_matcher_budget_exceeded");
            }
            self.nodes.insert(id.clone(), node);
        }
        Ok(id)
    }

    pub(super) fn finish(self) -> Result<Value, &'static str> {
        let indices: BTreeMap<_, _> = self
            .nodes
            .keys()
            .enumerate()
            .map(|(index, id)| (id.clone(), index))
            .collect();
        let output =
            serde_json::to_value(&self.nodes).map_err(|_| "command_source_encoding_failed")?;
        let nodes = self
            .nodes
            .into_values()
            .map(|node| compile_node(node, &indices))
            .collect::<Result<Vec<_>, _>>()?;
        let mut visits = vec![0; nodes.len()];
        let mut heights = vec![0; nodes.len()];
        for index in 0..nodes.len() {
            validate_graph(index, &nodes, &mut visits, &mut heights, 0)?;
        }
        Ok(output)
    }
}
