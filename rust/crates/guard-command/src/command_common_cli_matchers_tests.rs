//! Python reference vectors for the focused common-CLI matcher interpreters.

use super::*;
use crate::{parse_command, CommandModelRequestV1, CommandSegmentV1, CommandSpanV1};

#[derive(Clone, Deserialize)]
struct OracleSegment {
    executable: Option<String>,
    arguments: Vec<String>,
}

#[derive(Deserialize)]
struct OracleCase {
    op: String,
    config: serde_json::Value,
    segments: Vec<OracleSegment>,
    expected: Vec<usize>,
}

#[derive(Deserialize)]
struct OracleCorpus {
    source: String,
    cases: Vec<OracleCase>,
}

fn command(segments: &[OracleSegment]) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: false,
        normalized_text: String::new(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
        wrapper_chain: Vec::new(),
        segments: segments
            .iter()
            .map(|segment| CommandSegmentV1 {
                text: String::new(),
                tokens: Vec::new(),
                executable: segment.executable.clone(),
                arguments: segment.arguments.clone(),
                environment_names: Vec::new(),
                wrapper_chain: Vec::new(),
                path_overridden: false,
                execution_context: "root".to_owned(),
                pipeline_index: 0,
                span: CommandSpanV1 {
                    source: "normalized".to_owned(),
                    start: 0,
                    end: 0,
                },
            })
            .collect(),
        confidence: "exact".to_owned(),
        uncertainty_reason: None,
        path_overridden: false,
        parser_profile: "common-cli-oracle".to_owned(),
    }
}

#[test]
fn seven_operations_match_python_reference_vectors_in_segment_order() {
    let corpus: OracleCorpus = serde_json::from_str(include_str!(
        "../tests/fixtures/common-cli-matchers-v1.json"
    ))
    .expect("valid Python oracle corpus");
    assert_eq!(corpus.source, "c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8");
    assert_eq!(corpus.cases.len(), 212);
    let mut operations = std::collections::BTreeSet::new();
    for case in corpus.cases {
        let matcher =
            CommonCliMatcher::from_config(&case.op, case.config).expect("reviewed typed config");
        let model = command(&case.segments);
        assert_eq!(
            matcher.match_segments(&model),
            Ok(case.expected),
            "{}: {:?}",
            case.op,
            model.segments
        );
        operations.insert(case.op);
    }
    assert_eq!(operations.len(), 7);
}

#[test]
fn unknown_operations_and_incompatible_configs_are_explicit_errors() {
    assert!(CommonCliMatcher::from_config("future-cli.v2", serde_json::json!({})).is_err());
    for op in [
        "ansible-execution.v1",
        "dotnet-project-package.v1",
        "mongo-eval-mutation.v1",
        "sqlite-mutation.v1",
        "openshift-delete-drain.v1",
        "openshift-mutation.v1",
    ] {
        assert!(
            CommonCliMatcher::from_config(op, serde_json::json!({"new_semantics": true})).is_err()
        );
        assert!(CommonCliMatcher::from_config(op, serde_json::Value::Null).is_err());
    }
    for config in [
        serde_json::json!({}),
        serde_json::json!({"executable": "psql", "long_option": "--command", "short_option": "-c", "extra": 1}),
        serde_json::json!({"executable": "psql", "long_option": "--command", "short_option": 1}),
        serde_json::json!({"executable": "psql", "long_option": "", "short_option": "-c"}),
        serde_json::json!({"executable": "psql", "long_option": "--command", "short_option": ""}),
        serde_json::json!({"executable": "psql", "long_option": "--command", "short_option": "-é"}),
    ] {
        assert!(CommonCliMatcher::from_config("sql-option-mutation.v1", config).is_err());
    }
}

#[test]
fn uncertain_or_oversized_commands_do_not_become_empty_match_results() {
    let matcher =
        CommonCliMatcher::from_config("sqlite-mutation.v1", serde_json::json!({})).unwrap();
    let segment = OracleSegment {
        executable: Some("sqlite3".to_owned()),
        arguments: vec!["DROP TABLE items".to_owned()],
    };
    let mut model = command(std::slice::from_ref(&segment));
    model.confidence = "uncertain".to_owned();
    assert!(matcher.match_segments(&model).is_err());
    model = command(&vec![segment.clone(); MAX_COMMAND_SEGMENTS + 1]);
    assert!(matcher.match_segments(&model).is_err());
    model = command(std::slice::from_ref(&segment));
    model.segments[0].arguments = vec!["--option".to_owned(); MAX_COMMAND_TOKENS];
    assert!(matcher.match_segments(&model).is_err());
    model.segments[0].arguments = vec!["x".repeat(MAX_COMMAND_BYTES + 1)];
    assert!(matcher.match_segments(&model).is_err());
}

#[test]
fn canonical_shell_parser_feeds_typed_common_cli_matchers() {
    for (op, config, source, expected) in [
        (
            "ansible-execution.v1",
            serde_json::json!({}),
            "ansible-playbook playbook.yml --check",
            vec![0],
        ),
        (
            "ansible-execution.v1",
            serde_json::json!({}),
            "ansible-playbook playbook.yml --syntax-check",
            vec![],
        ),
        (
            "sql-option-mutation.v1",
            serde_json::json!({"executable": "psql", "long_option": "--command", "short_option": "-c"}),
            "psql -c 'DELETE FROM items'",
            vec![0],
        ),
        (
            "dotnet-project-package.v1",
            serde_json::json!({}),
            "dotnet add project.csproj package Example",
            vec![0],
        ),
        (
            "mongo-eval-mutation.v1",
            serde_json::json!({}),
            "mongosh --eval 'db.items.deleteMany({})'",
            vec![0],
        ),
        (
            "sqlite-mutation.v1",
            serde_json::json!({}),
            "sqlite3 database.db '.restore backup.db'",
            vec![0],
        ),
        (
            "openshift-delete-drain.v1",
            serde_json::json!({}),
            "oc delete pod item --dry-run=client",
            vec![],
        ),
        (
            "openshift-mutation.v1",
            serde_json::json!({}),
            "oc rollout restart deployment item",
            vec![0],
        ),
    ] {
        let model = parse_command(&CommandModelRequestV1 {
            command: source.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        let matcher = CommonCliMatcher::from_config(op, config).unwrap();
        assert_eq!(matcher.match_segments(&model), Ok(expected), "{source}");
    }
}
