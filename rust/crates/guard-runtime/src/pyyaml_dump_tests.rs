use super::dump;
use crate::pyjson::{self, PyVal};

/// `[json.dumps(doc), yaml.dump(doc, default_flow_style=False, sort_keys=False)]`
/// pairs recorded from PyYAML 6.
const VECTORS: &str = include_str!("pyyaml_dump_vectors.json");

#[test]
fn every_recorded_document_dumps_as_pyyaml_wrote_it() {
    let PyVal::List(pairs) = pyjson::parse(VECTORS).expect("vectors are JSON") else {
        panic!("vectors are a list");
    };
    assert!(pairs.len() >= 10);
    for pair in pairs {
        let PyVal::List(pair) = pair else {
            panic!("each vector is a pair");
        };
        let (PyVal::Str(source), PyVal::Str(expected)) = (&pair[0], &pair[1]) else {
            panic!("each vector holds two strings");
        };
        let doc = pyjson::parse(source).expect("document is JSON");
        assert_eq!(dump(&doc), *expected, "document {source}");
    }
}

#[test]
fn hermes_config_with_a_guard_hook_keeps_its_key_order() {
    let doc = pyjson::parse(
        r#"{"model": "m", "hooks": {"pre_tool_call": [{"command": "/opt/hol guard/bin/hook", "timeout": 30}]}, "mcp_servers": {}}"#,
    )
    .expect("document is JSON");
    assert_eq!(
        dump(&doc),
        "model: m\nhooks:\n  pre_tool_call:\n  - command: /opt/hol guard/bin/hook\n    timeout: 30\nmcp_servers: {}\n"
    );
}
