//! CPython oracle vectors for the final eight reviewed IR operations.
use super::*;
use crate::command_database_matchers::DatabaseMatcher;
use crate::{
    parse_command, CommandModelRequestV1, CommandSpanV1, MAX_COMMAND_BYTES, MAX_COMMAND_SEGMENTS,
    MAX_COMMAND_TOKENS,
};

#[derive(Deserialize)]
struct Definition {
    op: String,
    config: Value,
}
#[derive(Deserialize)]
struct Case {
    definition: usize,
    segments: Vec<(Option<String>, Vec<String>)>,
    expected: Vec<usize>,
    raw: Option<String>,
    native_error: Option<String>,
}
#[derive(Deserialize)]
struct Corpus {
    semantic_profile: String,
    definitions: Vec<Definition>,
    cases: Vec<Case>,
}

fn corpus() -> Corpus {
    serde_json::from_str(include_str!("../testdata/remaining-matchers.v1.json")).unwrap()
}
fn model(segments: &[(Option<String>, Vec<String>)], raw: Option<&str>) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: raw.is_some_and(|raw| raw == raw.trim()),
        normalized_text: raw.unwrap_or("").trim().to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "remaining-matchers-oracle".to_owned(),
        wrapper_chain: Vec::new(),
        segments: segments
            .iter()
            .map(|(executable, arguments)| CommandSegmentV1 {
                text: String::new(),
                tokens: executable
                    .iter()
                    .cloned()
                    .chain(arguments.iter().cloned())
                    .collect(),
                executable: executable.clone(),
                arguments: arguments.clone(),
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
        parser_profile: "remaining-matchers-oracle".to_owned(),
    }
}
fn shell(source: &str) -> CanonicalCommandV1 {
    parse_command(&CommandModelRequestV1 {
        command: source.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}
fn evaluate(
    op: &str,
    config: Value,
    command: &CanonicalCommandV1,
) -> Result<Vec<usize>, &'static str> {
    match op {
        "argument-command.v1" | "command-sequence.v1" | "leading-subcommand.v1" => {
            DatabaseMatcher::from_config(op, config)
                .unwrap()
                .match_segments(command)
        }
        _ => SpecializedMatcher::from_config(op, config)
            .unwrap()
            .match_segments(command),
    }
}

#[test]
fn eight_operations_match_python_or_report_declared_capability_misses() {
    let corpus = corpus();
    assert_eq!(corpus.semantic_profile, "cpython-3.12-ucd-15.0.0");
    assert_eq!(corpus.cases.len(), 721);
    let mut operations = BTreeSet::new();
    let mut misses = 0;
    for (index, case) in corpus.cases.into_iter().enumerate() {
        let definition = &corpus.definitions[case.definition];
        let command = model(&case.segments, case.raw.as_deref());
        let result = evaluate(&definition.op, definition.config.clone(), &command);
        if let Some(error) = case.native_error {
            assert_eq!(
                result,
                Err(error.as_str()),
                "case {index}: {} {:?}",
                definition.op,
                command.segments
            );
            misses += 1;
        } else {
            assert_eq!(
                result,
                Ok(case.expected),
                "case {index}: {} {:?}",
                definition.op,
                command.segments
            );
        }
        operations.insert(&definition.op);
    }
    assert_eq!(operations.len(), 8);
    assert_eq!(misses, 7);
}

#[test]
fn config_admission_rejects_unknown_or_invalid_semantics() {
    assert!(DatabaseMatcher::from_config("future.v1", serde_json::json!({})).is_err());
    assert!(SpecializedMatcher::from_config("future.v1", serde_json::json!({})).is_err());
    for definition in corpus().definitions {
        let mut config = definition.config;
        config
            .as_object_mut()
            .unwrap()
            .insert("unreviewed_behavior".to_owned(), Value::Bool(true));
        assert!(DatabaseMatcher::from_config(&definition.op, config.clone()).is_err());
        assert!(SpecializedMatcher::from_config(&definition.op, config).is_err());
    }
    for config in [
        serde_json::json!({"executables":[],"command":"reset","minimum_abbreviation_length":1}),
        serde_json::json!({"executables":["db"],"command":"reset","minimum_abbreviation_length":0}),
        serde_json::json!({"executables":["db"],"command":"reset","minimum_abbreviation_length":6}),
        serde_json::json!({"executables":["db"],"command":"reset","minimum_abbreviation_length":1,"minimum_position":-1}),
    ] {
        assert!(DatabaseMatcher::from_config("argument-command.v1", config).is_err());
    }
    for config in [
        serde_json::json!({"executables":["db"],"command_arities":[["get",1],["GET",2]],"target_commands":["get"]}),
        serde_json::json!({"executables":["db"],"command_arities":[["get",-1]],"target_commands":["get"]}),
        serde_json::json!({"executables":["db"],"command_arities":[["get",1]],"target_commands":["reset"]}),
    ] {
        assert!(DatabaseMatcher::from_config("command-sequence.v1", config).is_err());
    }
    assert!(SpecializedMatcher::from_config(
        "repo2nb-expansion.v1",
        serde_json::json!({"launchers":[[]]})
    )
    .is_err());
    assert!(SpecializedMatcher::from_config(
        "curl-elasticsearch-delete.v1",
        serde_json::json!({"service_ports":[65536]})
    )
    .is_err());
}

#[test]
fn literal_evidence_requires_parser_provenance_and_exact_semantic_shape() {
    let matcher = SpecializedMatcher::from_config(
        "reviewed-literal.v1",
        serde_json::json!({"executable":"tool","arguments":["--help"]}),
    )
    .unwrap();
    for source in ["tool --help", "  tool --help \t\n"] {
        // Python records command.strip() as raw_text; outer padding is allowed.
        assert_eq!(matcher.match_segments(&shell(source)), Ok(vec![0]));
    }
    for source in [
        "tool  --help",
        "tool '--help'",
        "tool --help extra",
        "tool --HELP",
        "tool --help; tool --help",
        "tool --help | cat",
        "tool --help > output",
        "env tool --help",
        "FLAG=x tool --help",
    ] {
        assert_ne!(
            matcher.match_segments(&shell(source)),
            Ok(vec![0]),
            "{source}"
        );
    }
    let good = shell("tool --help");
    let serialized = serde_json::to_value(&good).unwrap();
    assert!(serialized.get("exact_raw_text").is_none());
    let mut forged = serialized.clone();
    forged["exact_raw_text"] = Value::Bool(true);
    for serialized in [serialized, forged] {
        let command: CanonicalCommandV1 = serde_json::from_value(serialized).unwrap();
        assert!(!command.exact_raw_text);
        assert_eq!(matcher.match_segments(&command), Ok(vec![]));
    }
    for mutation in 0..10 {
        let mut command = good.clone();
        match mutation {
            0 => command.exact_raw_text = false,
            1 => command.dialect = "powershell".to_owned(),
            2 => command.transport = "argv".to_owned(),
            3 => command.wrapper_chain.push("env".to_owned()),
            4 => command.path_overridden = true,
            5 => command.segments[0]
                .environment_names
                .push("FLAG".to_owned()),
            6 => command.segments[0].wrapper_chain.push("env".to_owned()),
            7 => command.segments[0].path_overridden = true,
            8 => command.segments[0].pipeline_index = 1,
            _ => command.segments[0].tokens.clear(),
        }
        assert_eq!(
            matcher.match_segments(&command),
            Ok(vec![]),
            "mutation {mutation}"
        );
    }
}

#[test]
fn literal_configuration_preserves_the_reviewed_ascii_grammar_and_limits() {
    for argument in [
        "-",
        "--",
        "--help",
        "-X",
        "--name=value",
        "--opt=x:/a@b+z",
        "path/to/file",
        "foo.bar",
        "-n.0",
        "--name=x-y",
    ] {
        assert!(
            SpecializedMatcher::from_config(
                "reviewed-literal.v1",
                serde_json::json!({"executable":"tool","arguments":[argument]})
            )
            .is_ok(),
            "{argument}"
        );
    }
    for argument in [
        "",
        "---",
        "--=x",
        "--name=",
        "--name=x=y",
        "--name=$value",
        "$(cmd)",
        "a b",
        "é",
        "_value",
        "-n+1",
        "a;b",
        "a\nb",
        "--name=/path",
    ] {
        assert!(
            SpecializedMatcher::from_config(
                "reviewed-literal.v1",
                serde_json::json!({"executable":"tool","arguments":[argument]})
            )
            .is_err(),
            "{argument}"
        );
    }
    for config in [
        serde_json::json!({"executable":"/bin/tool","arguments":["--help"]}),
        serde_json::json!({"executable":"tool","arguments":[]}),
        serde_json::json!({"executable":"tool","arguments":vec!["x";17]}),
        serde_json::json!({"executable":"tool","arguments":["x".repeat(65)]}),
        serde_json::json!({"executable":"x".repeat(64),"arguments":["x".repeat(64)]}),
        serde_json::json!({"executable":"tool","arguments":["--help"],"expected":"anything"}),
    ] {
        assert!(SpecializedMatcher::from_config("reviewed-literal.v1", config).is_err());
    }
}

#[test]
fn inherited_deadline_confidence_and_size_limits_propagate_errors() {
    let database = DatabaseMatcher::from_config(
        "argument-command.v1",
        serde_json::json!({"executables":["db"],"command":"reset","minimum_abbreviation_length":1}),
    )
    .unwrap();
    let specialized =
        SpecializedMatcher::from_config("curl-elasticsearch-delete.v1", serde_json::json!({}))
            .unwrap();
    for mut command in [
        model(&[], None),
        shell("db 'reset payload'"),
        shell("curl -XDELETE http://localhost:9200/items"),
    ] {
        let expired = Instant::now()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap();
        assert!(database
            .match_segments_with_deadline(&command, Some(expired))
            .is_err());
        assert!(specialized
            .match_segments_with_deadline(&command, Some(expired))
            .is_err());
        command.confidence = "uncertain".to_owned();
        assert!(database.match_segments(&command).is_err());
        assert!(specialized.match_segments(&command).is_err());
    }
    for command in [
        model(
            &vec![(Some("db".to_owned()), vec![]); MAX_COMMAND_SEGMENTS + 1],
            None,
        ),
        model(
            &[(
                Some("db".to_owned()),
                vec!["x".to_owned(); MAX_COMMAND_TOKENS],
            )],
            None,
        ),
        model(
            &[(
                Some("db".to_owned()),
                vec!["x".repeat(MAX_COMMAND_BYTES + 1)],
            )],
            None,
        ),
    ] {
        assert!(database.match_segments(&command).is_err());
        assert!(specialized.match_segments(&command).is_err());
    }
}

#[test]
fn canonical_parser_feeds_database_php_curl_and_expansion_matchers() {
    for (op, config, source, expected) in [
        (
            "argument-command.v1",
            serde_json::json!({"executables":["db"],"command":"reset","minimum_abbreviation_length":3}),
            "db 'res payload'",
            vec![0],
        ),
        (
            "command-sequence.v1",
            serde_json::json!({"executables":["db"],"command_arities":[["get",1],["reset",0]],"target_commands":["reset"]}),
            "db get reset",
            vec![],
        ),
        (
            "leading-subcommand.v1",
            serde_json::json!({"executables":["db"],"subcommands":["delete"],"options_with_values":["-H"]}),
            "db -H host delete",
            vec![0],
        ),
        (
            "php-artisan-script.v1",
            serde_json::json!({"subcommands":["migrate:fresh"]}),
            "php -c config.ini /srv/artisan migrate:fresh",
            vec![0],
        ),
        (
            "curl-elasticsearch-delete.v1",
            serde_json::json!({}),
            "curl --header '-XDELETE' http://localhost:9200/items",
            vec![],
        ),
        (
            "curl-elasticsearch-delete.v1",
            serde_json::json!({}),
            "curl -vXDELETE http://localhost:9200/items",
            vec![0],
        ),
        (
            "repo2nb-expansion.v1",
            serde_json::json!({}),
            "repo2nb reverse '$FLAGS'",
            vec![0],
        ),
        (
            "repo2nb-expansion.v1",
            serde_json::json!({}),
            "printf café",
            vec![],
        ),
        (
            "zero-operand-flags.v1",
            serde_json::json!({"executables":["deploy"],"required_flags":["--prod"],"options_with_values":["--cwd"]}),
            "deploy --cwd project --prod",
            vec![0],
        ),
    ] {
        let command = shell(source);
        assert_eq!(command.confidence, "exact", "{source}");
        assert_eq!(evaluate(op, config, &command), Ok(expected), "{source}");
    }
}
