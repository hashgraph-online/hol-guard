//! Experimental whole-input npm lockfile projection. No policy or trust authority.
//!
//! This example is not installed with the runtime. Its caller owns source identity,
//! the absolute deadline, and explicit Python fallback outside this finite scope.

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 250_000;
const MAX_ENTRIES: usize = 100_000;
// Deeper valid Python inputs explicitly fall back; serde's own recursion guard
// remains enabled. This is a declared pilot scope, not a reduced product limit.
const PILOT_MAX_DEPTH: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_bytes: usize,
    max_nodes: usize,
    max_entries: usize,
    max_depth: usize,
    remaining_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u8,
    request_id: String,
    source_text: String,
    limits: Limits,
}

#[derive(Debug, PartialEq)]
enum Node {
    String(String),
    Object(Vec<(String, Node)>),
    IntegerThree,
    Other,
}

impl Node {
    fn field(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

struct Budget {
    deadline: Instant,
    max_nodes: usize,
    max_depth: usize,
    nodes: usize,
    failure: Option<&'static str>,
}

impl Budget {
    fn admit<E: Error>(&mut self, depth: usize) -> Result<(), E> {
        let reason = if Instant::now() > self.deadline {
            Some("deadline_exceeded")
        } else if depth > self.max_depth {
            Some("depth_outside_pilot_scope")
        } else {
            self.nodes += 1;
            (self.nodes > self.max_nodes).then_some("node_limit_exceeded")
        };
        if let Some(reason) = reason {
            self.failure = Some(reason);
            Err(E::custom(reason))
        } else {
            Ok(())
        }
    }
}

struct NodeSeed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = Node;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        self.budget.admit::<D::Error>(self.depth)?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NodeSeed<'_> {
    type Value = Node;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E: Error>(self, _value: bool) -> Result<Node, E> {
        Ok(Node::Other)
    }

    fn visit_unit<E: Error>(self) -> Result<Node, E> {
        Ok(Node::Other)
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Node, E> {
        Ok(if value == 3 {
            Node::IntegerThree
        } else {
            Node::Other
        })
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Node, E> {
        Ok(if value == 3 {
            Node::IntegerThree
        } else {
            Node::Other
        })
    }

    fn visit_f64<E: Error>(self, _value: f64) -> Result<Node, E> {
        // Python also accepts 3.0 as a version. This pilot declares integer 3;
        // other numeric spellings and extensions take the Python path.
        Ok(Node::Other)
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Node, E> {
        Ok(Node::String(value.to_owned()))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Node, E> {
        Ok(Node::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
        while access
            .next_element_seed(NodeSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        // Arrays cannot contribute package fields, but every descendant above
        // still receives duplicate, depth, node and deadline validation.
        Ok(Node::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
        let mut fields = Vec::new();
        let mut names = HashSet::new();
        while let Some(name) = access.next_key::<String>()? {
            if !names.insert(name.clone()) {
                self.budget.failure = Some("duplicate_key");
                return Err(A::Error::custom("duplicate_key"));
            }
            let value = access.next_value_seed(NodeSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            fields.push((name, value));
        }
        Ok(Node::Object(fields))
    }
}

#[derive(Debug, PartialEq, Serialize)]
struct Entry(String, String, String, bool);

#[derive(Serialize)]
struct Response {
    schema_version: u8,
    request_id: String,
    status: &'static str,
    reason: Option<&'static str>,
    entries: Vec<Entry>,
}

impl Response {
    fn fallback(request_id: String, reason: &'static str) -> Self {
        Self {
            schema_version: 1,
            request_id,
            status: "fallback",
            reason: Some(reason),
            entries: Vec::new(),
        }
    }
}

fn python_trim(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&character)
    })
}

fn project(request: Request) -> Response {
    let limits = &request.limits;
    if request.schema_version != 1
        || request.request_id.len() != 64
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || limits.max_bytes == 0
        || limits.max_bytes > MAX_SOURCE_BYTES
        || limits.max_nodes == 0
        || limits.max_nodes > MAX_NODES
        || limits.max_entries == 0
        || limits.max_entries > MAX_ENTRIES
        || limits.max_depth > PILOT_MAX_DEPTH
        || limits.remaining_ms == 0
        || limits.remaining_ms > 1500
    {
        return Response::fallback(request.request_id, "invalid_request");
    }
    if request.source_text.len() > limits.max_bytes {
        return Response::fallback(request.request_id, "byte_limit_exceeded");
    }
    let mut budget = Budget {
        deadline: Instant::now() + Duration::from_millis(limits.remaining_ms),
        max_nodes: limits.max_nodes,
        max_depth: limits.max_depth,
        nodes: 0,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_str(&request.source_text);
    let parsed = NodeSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer);
    let Ok(document) = parsed else {
        return Response::fallback(request.request_id, budget.failure.unwrap_or("invalid_json"));
    };
    if deserializer.end().is_err() {
        return Response::fallback(request.request_id, "invalid_json");
    }
    if document.field("lockfileVersion") != Some(&Node::IntegerThree) {
        return Response::fallback(request.request_id, "version_outside_pilot_scope");
    }
    let Some(Node::Object(packages)) = document.field("packages") else {
        return Response::fallback(request.request_id, "shape_outside_pilot_scope");
    };
    if document
        .field("dependencies")
        .is_some_and(|value| !matches!(value, Node::Object(_)))
    {
        return Response::fallback(request.request_id, "shape_outside_pilot_scope");
    }
    let mut entries = Vec::new();
    for (path, package) in packages {
        if Instant::now() > budget.deadline {
            return Response::fallback(request.request_id, "deadline_exceeded");
        }
        let Some(dependency_path) = path.strip_prefix("node_modules/") else {
            continue;
        };
        let Some(version) = package.field("version").and_then(Node::string) else {
            continue;
        };
        if entries.len() >= limits.max_entries {
            return Response::fallback(request.request_id, "entry_limit_exceeded");
        }
        let explicit_name = package
            .field("name")
            .and_then(Node::string)
            .map(python_trim);
        let package_name = explicit_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                dependency_path
                    .rsplit_once("node_modules/")
                    .map_or(dependency_path, |(_, tail)| tail)
            });
        entries.push(Entry(
            dependency_path.to_owned(),
            package_name.to_owned(),
            version.to_owned(),
            !dependency_path.contains("node_modules/"),
        ));
    }
    // With nonempty package entries both Python projections are the same ordered
    // path/version view. The empty-view legacy-dependencies fallback is separate.
    if entries.is_empty()
        && document.field("dependencies").is_some_and(
            |value| matches!(value, Node::Object(dependencies) if !dependencies.is_empty()),
        )
    {
        return Response::fallback(request.request_id, "legacy_fallback_outside_pilot_scope");
    }
    if Instant::now() > budget.deadline {
        return Response::fallback(request.request_id, "deadline_exceeded");
    }
    Response {
        schema_version: 1,
        request_id: request.request_id,
        status: "complete",
        reason: None,
        entries,
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(io::Error::other("request envelope exceeded its byte limit"));
    }
    let response = match serde_json::from_slice::<Request>(&input) {
        Ok(request) => project(request),
        Err(_) => Response::fallback(String::new(), "invalid_request"),
    };
    let output = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if output.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::other("response exceeded its byte limit"));
    }
    io::stdout().lock().write_all(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(source: &str) -> Request {
        Request {
            schema_version: 1,
            request_id: "a".repeat(64),
            source_text: source.to_owned(),
            limits: Limits {
                max_bytes: MAX_SOURCE_BYTES,
                max_nodes: MAX_NODES,
                max_entries: MAX_ENTRIES,
                max_depth: PILOT_MAX_DEPTH,
                remaining_ms: 1500,
            },
        }
    }

    #[test]
    fn preserves_order_names_nested_paths_and_exact_versions() {
        let response = project(request(
            r#"{"lockfileVersion":3,"packages":{
            "node_modules/z":{"name":" \u001c@scope/alias\u001f ","version":"1.0.0-beta+build"},
            "ignored":{"version":"8"},
            "node_modules/a/node_modules/b":{"name":"  ","version":""},
            "node_modules/link":{"link":true},
            "node_modules/b":{"version":"2"}}}"#,
        ));
        assert_eq!(response.status, "complete");
        assert_eq!(
            response.entries,
            vec![
                Entry(
                    "z".into(),
                    "@scope/alias".into(),
                    "1.0.0-beta+build".into(),
                    true
                ),
                Entry("a/node_modules/b".into(), "b".into(), "".into(), false),
                Entry("b".into(), "b".into(), "2".into(), true),
            ]
        );
    }

    #[test]
    fn duplicate_keys_in_unused_nested_metadata_never_publish_partial_entries() {
        let response = project(request(
            r#"{"lockfileVersion":3,"packages":{
            "node_modules/a":{"version":"1"}},"metadata":[{"a":1,"\u0061":2}]}"#,
        ));
        assert_eq!(response.reason, Some("duplicate_key"));
        assert!(response.entries.is_empty());
    }

    #[test]
    fn entry_and_node_limits_discard_every_partial_projection() {
        let source = r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1"},"node_modules/b":{"version":"2"}}}"#;
        let mut limited = request(source);
        limited.limits.max_entries = 1;
        let response = project(limited);
        assert_eq!(response.reason, Some("entry_limit_exceeded"));
        assert!(response.entries.is_empty());
        let mut limited = request(source);
        limited.limits.max_nodes = 4;
        let response = project(limited);
        assert_eq!(response.reason, Some("node_limit_exceeded"));
        assert!(response.entries.is_empty());
    }

    #[test]
    fn unsupported_numeric_spellings_and_empty_legacy_projection_fall_back() {
        assert_eq!(
            project(request(r#"{"lockfileVersion":3.0,"packages":{}}"#)).status,
            "fallback"
        );
        let response = project(request(
            r#"{"lockfileVersion":3,"packages":{},"dependencies":{"a":{"version":"1"}}}"#,
        ));
        assert_eq!(response.reason, Some("legacy_fallback_outside_pilot_scope"));
        assert!(response.entries.is_empty());
    }
}
