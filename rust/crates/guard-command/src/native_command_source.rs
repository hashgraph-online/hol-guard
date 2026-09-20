//! Additive build-time source compiler. Never invoked by hook evaluation.

use super::*;

#[path = "native_command_source_capabilities.rs"]
mod capabilities;
#[path = "native_command_source_catalog.rs"]
mod catalog;
#[path = "native_command_source_contract.rs"]
mod contract;
#[path = "native_command_source_evaluation_batch.rs"]
mod evaluation_batch;
#[path = "native_command_source_fixtures.rs"]
mod fixtures;
#[path = "native_command_source_hints.rs"]
mod hints;
#[path = "native_command_source_json.rs"]
mod json;
#[path = "native_command_source_matcher.rs"]
mod matcher;
#[path = "native_command_source_mcp.rs"]
mod mcp;
#[path = "native_command_source_parity.rs"]
mod parity;
#[path = "native_command_source_validation.rs"]
mod validation;
pub use catalog::{
    compile_addition, compile_addition_with_mcp, compile_catalog, compile_catalog_with_mcp,
    CompiledSourceCatalog,
};
pub use contract::{descriptor_schema, source_schema};
pub use evaluation_batch::evaluate_batch;
pub use fixtures::run_fixtures;
pub use parity::compare_programs;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRequest {
    schema: String,
    sources: Vec<Value>,
    #[serde(default)]
    mcp_sources: Vec<Value>,
    trust: Value,
    base: Option<BaseProgram>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum BaseProgram {
    Packaged,
}

/// Decode an owned build envelope. Sources cannot contain file/remote includes;
/// callers supply the separately reviewed trust input outside each source.
pub fn compile_build_request(bytes: &[u8]) -> Result<CompiledSourceCatalog, &'static str> {
    let request: BuildRequest = serde_json::from_value(json::decode(bytes)?)
        .map_err(|_| "command_source_build_contract_invalid")?;
    if request.schema != "guard.command-extension-build.v1" {
        return Err("command_source_build_version_unsupported");
    }
    let sources: Vec<Vec<u8>> = request
        .sources
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<_, _>>()
        .map_err(|_| "command_source_encoding_failed")?;
    let trust = serde_json::to_vec(&request.trust).map_err(|_| "command_source_encoding_failed")?;
    let borrowed = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let mcp_sources = request
        .mcp_sources
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "command_source_encoding_failed")?;
    let mcp_borrowed = mcp_sources.iter().map(Vec::as_slice).collect::<Vec<_>>();
    match request.base {
        Some(BaseProgram::Packaged) => compile_addition_with_mcp(&borrowed, &mcp_borrowed, &trust),
        None => compile_catalog_with_mcp(&borrowed, &mcp_borrowed, &trust),
    }
}
#[cfg(test)]
#[path = "native_command_source_tests.rs"]
mod catalog_tests;

/// Content-addressed matcher graph produced exclusively by native validation.
/// Rule, catalog and trust admission are separate from this matcher primitive.
#[derive(Debug, serde::Serialize)]
pub struct CompiledSourceMatcher {
    pub root: String,
    pub nodes: Value,
}

/// Lower a bounded inline matcher into existing native wire nodes.
/// This function grants no activation or policy authority.
pub fn compile_matcher(bytes: &[u8]) -> Result<CompiledSourceMatcher, &'static str> {
    let value = json::decode(bytes)?;
    let source: matcher::SourceMatcher =
        serde_json::from_value(value).map_err(|_| "command_source_matcher_contract_invalid")?;
    let mut graph = matcher::SourceGraph::default();
    let root = graph.lower(source, 0)?;
    Ok(CompiledSourceMatcher {
        root,
        nodes: graph.finish()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_source_supplied_hints_callbacks_and_unknown_operations() {
        for value in [
            serde_json::json!({"op":"unknown.v1", "config":{}}),
            serde_json::json!({"op":"arguments.v1", "config":{}, "candidate_unindexed":false}),
            serde_json::json!({"op":"arguments.v1", "config":{}, "callback":"allow"}),
            serde_json::json!({"op":"any.v1", "config":{}, "matchers":[]}),
            serde_json::json!({"op":"pipeline.v1", "config":{}}),
        ] {
            assert!(compile_matcher(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn source_config_is_checked_by_the_existing_node_compiler() {
        let mut value = serde_json::json!({"op":"arguments.v1", "config": {
            "executables": ["example-cli"], "required_arguments": ["destroy"]
        }});
        let compiled = compile_matcher(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(compiled.nodes.as_object().unwrap().len(), 1);
        value["config"]["execute"] = Value::Bool(true);
        assert_eq!(
            compile_matcher(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "native_command_arguments_invalid"
        );
        value["config"].as_object_mut().unwrap().remove("execute");
        value["config"]["executables"] = serde_json::json!(["éxample-cli"]);
        assert_eq!(
            compile_matcher(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "native_command_ascii_configuration_required"
        );
    }

    #[test]
    fn every_baseline_node_tree_lowers_to_its_original_content_identity() {
        let program: Value = serde_json::from_slice(EMBEDDED_PROGRAM).unwrap();
        fn inline(id: &str, nodes: &Value) -> Value {
            let node = &nodes[id];
            let mut result = serde_json::json!({"op":node["op"], "config":node["config"]});
            for (field, value) in node["children"].as_object().unwrap() {
                result[field] = if let Some(ids) = value.as_array() {
                    Value::Array(
                        ids.iter()
                            .map(|id| inline(id.as_str().unwrap(), nodes))
                            .collect(),
                    )
                } else {
                    inline(value.as_str().unwrap(), nodes)
                };
            }
            result
        }
        for (id, _) in program["nodes"].as_object().unwrap() {
            let source = inline(id, &program["nodes"]);
            let compiled = compile_matcher(&serde_json::to_vec(&source).unwrap())
                .unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(&compiled.root, id);
            assert_eq!(compiled.nodes[id], program["nodes"][id]);
        }
        for rule in program["rules"].as_array().unwrap() {
            let derived = if let Some(id) = rule["matcher"].as_str() {
                let source = serde_json::from_value(inline(id, &program["nodes"])).unwrap();
                hints::derive(&source)
            } else {
                hints::Hints::default()
            };
            assert_eq!(
                serde_json::json!(derived.executables),
                rule["candidate_executables"],
                "{}",
                rule["rule_id"]
            );
            assert_eq!(
                serde_json::json!(derived.keywords),
                rule["candidate_keywords"],
                "{}",
                rule["rule_id"]
            );
            assert_eq!(
                derived.unindexed(),
                rule["candidate_unindexed"].as_bool().unwrap(),
                "{}",
                rule["rule_id"]
            );
        }
    }
}
