//! Regression cases for opaque Unicode operands around admitted ASCII grammars.
use super::*;
use crate::{parse_command, CommandModelRequestV1};

#[derive(Deserialize)]
struct Definition {
    op: String,
    config: Value,
}
#[derive(Deserialize)]
struct Corpus {
    definitions: Vec<Definition>,
    unicode_parser_cases: Vec<(usize, String, Vec<usize>)>,
}

#[test]
fn unicode_operands_keep_python_and_php_launcher_classification_exact() {
    let corpus: Corpus =
        serde_json::from_str(include_str!("../testdata/remaining-matchers.v1.json")).unwrap();
    assert_eq!(corpus.unicode_parser_cases.len(), 46);
    for (index, source, expected) in corpus.unicode_parser_cases {
        let definition = &corpus.definitions[index];
        let command = parse_command(&CommandModelRequestV1 {
            command: source.clone(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "unicode-oracle".to_owned(),
        })
        .unwrap();
        assert_eq!(command.confidence, "exact", "{source}");
        let matcher =
            SpecializedMatcher::from_config(&definition.op, definition.config.clone()).unwrap();
        assert_eq!(
            matcher.match_segments(&command),
            Ok(expected),
            "{}: {source}",
            definition.op
        );
    }
}

#[test]
fn unicode_configurations_cannot_enter_the_ascii_comparison_contract() {
    for config in [
        serde_json::json!({"subcommands":["migrate:é"]}),
        serde_json::json!({"subcommands":["migrate:fresh"],"required_flags":["--hélp"]}),
    ] {
        assert_eq!(
            SpecializedMatcher::from_config("php-artisan-script.v1", config).unwrap_err(),
            "unsupported_specialized_unicode_config"
        );
    }
    for config in [
        serde_json::json!({"subcommand":"réverse"}),
        serde_json::json!({"launchers":[["python","-m","répo2nb"]]}),
        serde_json::json!({"leading_options_with_values":["--é"]}),
        serde_json::json!({"expansion_markers":["é"]}),
    ] {
        assert_eq!(
            SpecializedMatcher::from_config("repo2nb-expansion.v1", config).unwrap_err(),
            "unsupported_specialized_unicode_config"
        );
    }
}

#[test]
fn ascii_projection_preserves_unicode_boundaries_and_special_lowercase_mappings() {
    for (source, expected) in [
        ("İ", "i\u{0307}"),
        ("K", "k"),
        ("KİHELLO", "ki\u{0307}hello"),
        ("café", "café"),
        ("CAFÉ", "cafÉ"),
        ("ΟΣ", "ΟΣ"),
        ("数据", "数据"),
    ] {
        assert_eq!(lowercase_for_ascii_comparison(source), expected);
    }
    assert_ne!(lowercase_for_ascii_comparison("İ"), "i");
    assert_eq!(lowercase_for_ascii_comparison("-İh"), "-i\u{0307}h");
}
