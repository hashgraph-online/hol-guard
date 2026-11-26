use std::collections::BTreeMap;

use guard_contracts::ProviderVerdictV1 as V;

use super::*;

fn table() -> BTreeMap<String, V> {
    BTreeMap::from([
        ("clean".to_owned(), V::Ok),
        ("suspicious".to_owned(), V::Caution),
        ("malicious".to_owned(), V::Danger),
        ("unrated".to_owned(), V::Unknown),
    ])
}

fn allow() -> Vec<String> {
    [
        "phishing",
        "new_domain",
        "credential_form",
        "known_bad_script",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn map(body: &str) -> Result<MappedAnswer, AnswerError> {
    let table = table();
    let allow = allow();
    map_answer(
        body.as_bytes(),
        &AnswerMapping {
            verdict_pointer: "/result/verdict",
            verdict_map: &table,
            reason_codes: Some(ReasonCodeMapping {
                pointer: "/result/reasons",
                allow: &allow,
            }),
            ttl: Some(TtlMapping {
                pointer: "/ttl",
                min_seconds: 60,
                max_seconds: 3600,
            }),
        },
    )
}

#[test]
fn declared_values_map_onto_the_closed_verdicts() {
    for (sent, expected) in [
        ("clean", V::Ok),
        ("suspicious", V::Caution),
        ("malicious", V::Danger),
        ("unrated", V::Unknown),
    ] {
        let answer = map(&format!(r#"{{"result":{{"verdict":"{sent}"}},"ttl":600}}"#)).unwrap();
        assert_eq!(answer.verdict, expected, "{sent}");
        assert_eq!(answer.ttl_seconds, Some(600));
    }
}

#[test]
fn an_unlisted_missing_or_odd_verdict_reads_unknown() {
    for body in [
        r#"{"result":{"verdict":"safe"}}"#,
        r#"{"result":{"verdict":"Malicious"}}"#,
        r#"{"result":{"verdict":"allow"}}"#,
        r#"{"result":{"verdict":true}}"#,
        r#"{"result":{"verdict":["malicious"]}}"#,
        r#"{"result":{}}"#,
        r#"{"verdict":"malicious"}"#,
        r#"[]"#,
    ] {
        assert_eq!(map(body).unwrap().verdict, V::Unknown, "{body}");
    }
    let long = format!(r#"{{"result":{{"verdict":"{}"}}}}"#, "m".repeat(65));
    assert_eq!(map(&long).unwrap().verdict, V::Unknown);
}

#[test]
fn only_declared_reason_codes_are_kept_in_order_up_to_eight() {
    let answer = map(r#"{"result":{"verdict":"malicious","reasons":[
            "undeclared","new_domain","Phishing","phishing","new_domain",
            "phishing<b>","credential_form",7,"known_bad_script"]}}"#)
    .unwrap();
    assert_eq!(
        answer.reason_codes,
        [
            "new_domain",
            "phishing",
            "credential_form",
            "known_bad_script"
        ]
    );

    let many: Vec<String> = (0..20).map(|n| format!("code_{n}")).collect();
    let table = table();
    let body = format!(
        r#"{{"result":{{"verdict":"suspicious","reasons":{}}}}}"#,
        serde_json::to_string(&many).unwrap()
    );
    let answer = map_answer(
        body.as_bytes(),
        &AnswerMapping {
            verdict_pointer: "/result/verdict",
            verdict_map: &table,
            reason_codes: Some(ReasonCodeMapping {
                pointer: "/result/reasons",
                allow: &many,
            }),
            ttl: None,
        },
    )
    .unwrap();
    assert_eq!(answer.reason_codes, many[..8].to_vec());
    assert_eq!(answer.ttl_seconds, None);
}

#[test]
fn undeclared_codes_ahead_of_declared_ones_do_not_crowd_them_out() {
    let mut reasons: Vec<String> = (0..40).map(|n| format!("noise_{n}")).collect();
    reasons.push("phishing".to_owned());
    let body = format!(
        r#"{{"result":{{"verdict":"malicious","reasons":{}}}}}"#,
        serde_json::to_string(&reasons).unwrap()
    );
    assert_eq!(map(&body).unwrap().reason_codes, ["phishing"]);

    let mut crowded: Vec<String> = (0..64).map(|n| format!("n{n}")).collect();
    crowded.push("phishing".to_owned());
    let body = format!(
        r#"{{"result":{{"verdict":"malicious","reasons":{}}}}}"#,
        serde_json::to_string(&crowded).unwrap()
    );
    assert_eq!(map(&body).unwrap().reason_codes, ["phishing"]);
}

#[test]
fn reason_codes_that_are_not_an_array_are_ignored() {
    for body in [
        r#"{"result":{"verdict":"malicious","reasons":"phishing"}}"#,
        r#"{"result":{"verdict":"malicious","reasons":{"phishing":true}}}"#,
        r#"{"result":{"verdict":"malicious"}}"#,
    ] {
        let answer = map(body).unwrap();
        assert_eq!(answer.verdict, V::Danger);
        assert!(answer.reason_codes.is_empty(), "{body}");
    }
}

#[test]
fn the_lifetime_is_clamped_into_the_declared_bounds() {
    for (ttl, expected) in [
        ("600", 600),
        ("5", 60),
        ("999999999", 3600),
        ("0", 60),
        ("-30", 60),
        ("12.5", 60),
        (r#""600""#, 60),
        ("null", 60),
        ("18446744073709551616", 3600),
        ("1e3", 60),
    ] {
        let answer = map(&format!(
            r#"{{"result":{{"verdict":"clean"}},"ttl":{ttl}}}"#
        ))
        .unwrap();
        assert_eq!(answer.ttl_seconds, Some(expected), "{ttl}");
    }
    assert_eq!(
        map(r#"{"result":{"verdict":"clean"}}"#)
            .unwrap()
            .ttl_seconds,
        Some(60)
    );
}

#[test]
fn a_body_that_is_not_strict_json_is_refused() {
    for body in [
        "",
        "not json",
        r#"{"result":{"verdict":"clean"}} trailing"#,
        r#"{"result":{"verdict":"clean","verdict":"malicious"}}"#,
        r#"{"result":{"verdict":"malicious"},"result":{"verdict":"clean"}}"#,
    ] {
        assert_eq!(map(body), Err(AnswerError::BodyInvalid), "{body}");
    }
    assert_eq!(AnswerError::BodyInvalid.code(), "provider_answer_invalid");
}

#[test]
fn the_mapped_answer_never_carries_provider_text() {
    let answer = map(r#"{"result":{"verdict":"malicious","reasons":["phishing"],
            "message":"call 555 to unlock"},"ttl":120}"#)
    .unwrap();
    assert!(!format!("{answer:?}").contains("unlock"));
}
