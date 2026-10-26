//! Lone surrogates through the native bounded hook bridge, against vectors
//! recorded from Python's renderers: forwarded, rendered and failed as
//! `json.dumps` writes them, with stderr as `print` writes it under
//! `errors="backslashreplace"`.

use super::*;
use crate::pyjson::{self, PyVal, SurrogateMapped};

const SURROGATES: &str = include_str!("../testdata/bounded_hook_bridge/surrogates.json");

fn section(name: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(SURROGATES).unwrap();
    all[name].as_array().unwrap().clone()
}

fn mapped(source: &str) -> SurrogateMapped {
    let Ok(parsed) = pyjson::parse_mapping_lone_surrogates(source) else {
        panic!("vector JSON does not parse: {source}");
    };
    parsed
}

fn vector_exit_code(case: &Value) -> i32 {
    i32::try_from(case["exit_code"].as_i64().unwrap()).unwrap()
}

#[test]
fn answers_with_lone_surrogates_render_as_python_renders_them() {
    let cases = section("render");
    assert!(cases
        .iter()
        .any(|case| text(case, "stderr").contains("\\ud800")));
    for case in cases {
        let event = mapped(&text(&case, "event_json"));
        let PyVal::Str(event_name) = event.value else {
            panic!("{case}");
        };
        let prepared = Prepared {
            data: "{}".to_owned(),
            event_name,
            mapped: event.mapped,
            collision: false,
        };
        let answer = mapped(&text(&case, "response"));
        let expected = Rendered {
            stdout: text(&case, "stdout"),
            stderr: text(&case, "stderr"),
            exit_code: vector_exit_code(&case),
        };
        let rendered = prepared.render(&text(&case, "harness"), &answer);
        assert_eq!(rendered, Some(expected), "{case}");
    }
}

#[test]
fn hooks_with_lone_surrogates_fail_closed_as_python_fails_them() {
    for case in section("failures") {
        let prepared = prepare(text(&case, "input").as_bytes()).unwrap();
        assert!(prepared.mapped, "{case}");
        let failed = failure_output(&text(&case, "harness"), &prepared.event_name, true);
        assert_eq!(
            failed,
            (text(&case, "stdout"), vector_exit_code(&case)),
            "{case}"
        );
    }
}

#[test]
fn a_lone_surrogate_beside_its_mapped_range_is_not_rendered() {
    let answer = mapped("{\"policy_action\":\"block\",\"reason\":\"\\ud800\"}");
    let genuine = mapped("{\"policy_action\":\"block\",\"reason\":\"\u{f0000}\"}");
    let prepared = |is_mapped, collision| Prepared {
        data: "{}".to_owned(),
        event_name: "PreToolUse".to_owned(),
        mapped: is_mapped,
        collision,
    };
    assert_eq!(prepared(false, true).render("kimi", &answer), None);
    assert_eq!(prepared(true, false).render("kimi", &genuine), None);
    let rendered = prepared(false, false).render("kimi", &genuine).unwrap();
    assert!(rendered.stdout.contains("\\udb80\\udc00"), "{rendered:?}");
    assert_eq!(rendered.stderr, "\u{f0000}");
}
