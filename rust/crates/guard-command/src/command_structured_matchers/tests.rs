use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use super::StructuredMatcher;
use crate::command_operand_matchers::OperandMatcher;
use crate::{CanonicalCommandV1, CommandSegmentV1, CommandSpanV1};

type SegmentInput = (Option<String>, Vec<String>, Vec<String>);

#[derive(Deserialize)]
struct OracleDefinition {
    op: String,
    config: Value,
}

#[derive(Deserialize)]
struct OracleCase {
    m: usize,
    s: Vec<SegmentInput>,
    matches: Vec<usize>,
}

#[derive(Deserialize)]
struct Oracle {
    matchers: Vec<OracleDefinition>,
    cases: Vec<OracleCase>,
}

fn command(segments: Vec<SegmentInput>) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: false,
        normalized_text: String::new(),
        dialect: "argv".into(),
        transport: "argv".into(),
        extraction_provenance: "specialized-matcher-oracle".into(),
        wrapper_chain: Vec::new(),
        segments: segments
            .into_iter()
            .enumerate()
            .map(
                |(index, (executable, arguments, environment_names))| CommandSegmentV1 {
                    text: String::new(),
                    tokens: Vec::new(),
                    executable,
                    arguments,
                    environment_names,
                    wrapper_chain: Vec::new(),
                    path_overridden: false,
                    execution_context: "top".into(),
                    pipeline_index: index,
                    span: CommandSpanV1 {
                        source: "normalized".into(),
                        start: 0,
                        end: 0,
                    },
                },
            )
            .collect(),
        confidence: "exact".into(),
        uncertainty_reason: None,
        path_overridden: false,
        parser_profile: "oracle.v1".into(),
    }
}

fn segment(executable: &str, arguments: &[&str], names: &[&str]) -> SegmentInput {
    (
        Some(executable.into()),
        arguments
            .iter()
            .map(|argument| (*argument).into())
            .collect(),
        names.iter().map(|name| (*name).into()).collect(),
    )
}

#[test]
fn matches_python_specialized_oracle_for_all_eight_operations() {
    let oracle: Oracle =
        serde_json::from_str(include_str!("../../testdata/specialized-matchers.v1.json")).unwrap();
    assert_eq!(oracle.cases.len(), 1571);
    for (index, case) in oracle.cases.into_iter().enumerate() {
        let definition = &oracle.matchers[case.m];
        let model = command(case.s);
        let result = match StructuredMatcher::from_config(&definition.op, definition.config.clone())
        {
            Ok(matcher) => matcher.match_segments(&model),
            Err("unsupported_structured_matcher") => {
                OperandMatcher::from_config(&definition.op, definition.config.clone())
                    .unwrap()
                    .match_segments(&model)
            }
            Err(error) => panic!("oracle config {index}: {error}"),
        };
        assert_eq!(
            result,
            Ok(case.matches),
            "oracle case {index}, operation {}, arguments {:?}",
            definition.op,
            model.segments
        );
    }
}

#[test]
fn rejects_unknown_fields_and_invalid_matcher_grammars_before_admission() {
    let oracle: Oracle =
        serde_json::from_str(include_str!("../../testdata/specialized-matchers.v1.json")).unwrap();
    for definition in oracle.matchers {
        for field in ["unexpected", "all_value_options", "ordered_options"] {
            let mut config = definition.config.clone();
            config[field] = json!([]);
            assert!(StructuredMatcher::from_config(&definition.op, config.clone()).is_err());
            assert!(OperandMatcher::from_config(&definition.op, config).is_err());
        }
        for executables in [json!([]), json!([" ", "\u{1c}"]), json!("tool"), json!([0])] {
            let mut config = definition.config.clone();
            config["executables"] = executables;
            assert!(StructuredMatcher::from_config(&definition.op, config.clone()).is_err());
            assert!(OperandMatcher::from_config(&definition.op, config).is_err());
        }
    }
    for count in [json!(-1), json!(0), json!(true), json!(1.5), json!("2")] {
        assert!(StructuredMatcher::from_config(
            "leading-operand-count.v1",
            json!({"executables":["tool"], "minimum_operands":count})
        )
        .is_err());
        assert!(OperandMatcher::from_config(
            "trailing-operand-host-target.v1",
            json!({"executables":["tool"], "minimum_operands":count})
        )
        .is_err());
    }
    for config in [
        json!({"executables":["tool"]}),
        json!({"executables":["tool"], "required_flags":[]}),
        json!({"executables":["tool"], "required_flags":[" "]}),
    ] {
        assert!(OperandMatcher::from_config("operand-gated-flags.v1", config).is_err());
    }
    assert!(OperandMatcher::from_config(
        "trailing-operand-prefix.v1",
        json!({"executables":["tool"],"operand_prefixes":[""]})
    )
    .is_err());
    assert!(StructuredMatcher::from_config(
        "subcommand-operand-prefix.v1",
        json!({"executables":["tool"],"subcommands":["push"],"operand_prefixes":["@"],
               "leading_operands_to_skip":-1})
    )
    .is_err());
    assert!(StructuredMatcher::from_config("leading-operand-count.v2", json!({})).is_err());
    assert!(OperandMatcher::from_config("trailing-operand-prefix.v2", json!({})).is_err());
}

#[test]
fn unsupported_unicode_case_mapping_is_error_not_a_negative_match() {
    let config = json!({"executables":["tool"],"minimum_operands":1});
    let matcher = StructuredMatcher::from_config("leading-operand-count.v1", config).unwrap();
    for (executable, arguments) in [("tÖol", vec!["source"]), ("tool", vec!["--SÄFE", "source"])]
    {
        assert_eq!(
            matcher.match_segments(&command(vec![segment(executable, &arguments, &[])])),
            Err("unsupported_unicode_case_mapping")
        );
    }
    assert!(matches!(
        StructuredMatcher::from_config(
            "leading-operand-count.v1",
            json!({"executables":["K"],"minimum_operands":1})
        ),
        Err("unsupported_unicode_case_mapping")
    ));
    let matcher = StructuredMatcher::from_config(
        "environment-name.v1",
        json!({"executables":["tool"],"environment_names":["SS"]}),
    )
    .unwrap();
    assert_eq!(
        matcher.match_segments(&command(vec![segment("tool", &[], &["ß"])])),
        Err("unsupported_unicode_case_mapping")
    );
    let matcher = StructuredMatcher::from_config(
        "option-value-key.v1",
        json!({"executables":["tool"],"option_names":["-o"],"value_keys":["key"]}),
    )
    .unwrap();
    assert_eq!(
        matcher.match_segments(&command(vec![segment("tool", &["-o", "KEY=Σ"], &[])])),
        Err("unsupported_unicode_case_mapping")
    );
}

#[test]
fn opaque_unicode_operands_and_python_whitespace_are_supported() {
    let matcher = OperandMatcher::from_config(
        "trailing-operand-prefix.v1",
        json!({"executables":["\u{1c}TOOL\u{85}"],"operand_prefixes":["界:"]}),
    )
    .unwrap();
    assert_eq!(
        matcher.match_segments(&command(vec![segment("tool", &["source", "界:先"], &[])])),
        Ok(vec![0])
    );
    let matcher = OperandMatcher::from_config(
        "trailing-operand-host-target.v1",
        json!({"executables":["tool"]}),
    )
    .unwrap();
    assert_eq!(
        matcher.match_segments(&command(vec![
            segment("tool", &["source", "\u{345}:path"], &[]),
            segment("tool", &["source", "é:path"], &[]),
            segment("tool", &["source", "host\u{1c}name:path"], &[]),
            segment("tool", &["source", "[ ]:path"], &[]),
        ])),
        Ok(vec![0, 3])
    );
}

#[test]
fn expired_deadline_never_returns_empty_or_partial_evidence() {
    let oracle: Oracle =
        serde_json::from_str(include_str!("../../testdata/specialized-matchers.v1.json")).unwrap();
    for definition in oracle.matchers {
        for model in [
            command(Vec::new()),
            command(vec![segment("tool", &["source", "s3://bucket"], &[])]),
        ] {
            let expired = Some(Instant::now());
            let future = Some(Instant::now() + Duration::from_secs(10));
            match StructuredMatcher::from_config(&definition.op, definition.config.clone()) {
                Ok(matcher) => {
                    assert_eq!(
                        matcher.match_segments_with_deadline(&model, expired),
                        Err("matcher_deadline_exceeded")
                    );
                    assert_eq!(
                        matcher.match_segments_with_deadline(&model, future),
                        matcher.match_segments(&model)
                    );
                }
                Err("unsupported_structured_matcher") => {
                    let matcher =
                        OperandMatcher::from_config(&definition.op, definition.config.clone())
                            .unwrap();
                    assert_eq!(
                        matcher.match_segments_with_deadline(&model, expired),
                        Err("matcher_deadline_exceeded")
                    );
                    assert_eq!(
                        matcher.match_segments_with_deadline(&model, future),
                        matcher.match_segments(&model)
                    );
                }
                Err(error) => panic!("invalid oracle config: {error}"),
            }
        }
    }
}
