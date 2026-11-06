use serde_json::Value;

use super::python_canonical;

const VECTORS: &str = include_str!("../../../../tests/fixtures/mcp_relay/python_wire_vectors.json");

/// What the child reads: the resident decodes the frame it is handed and
/// writes it with `serde_json::to_vec` (`LiveMcpSession::write`).
fn child_bytes(frame: &Value) -> Vec<u8> {
    serde_json::to_vec(frame).unwrap()
}

#[test]
fn the_child_reads_the_bytes_the_proxy_would_send() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 14);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let host = vector["host"].as_str().unwrap();
        let relayed = serde_json::from_str::<Value>(host)
            .ok()
            .and_then(|frame| python_canonical(&frame));
        match vector["python"].as_str() {
            Some(python) => {
                let proxied: Value = serde_json::from_str(python).unwrap();
                let relayed = relayed.unwrap_or_else(|| panic!("{name} deferred"));
                assert_eq!(child_bytes(&relayed), child_bytes(&proxied), "{name}");
            }
            None => assert!(relayed.is_none(), "{name} was not deferred"),
        }
    }
}

#[test]
fn numbers_take_their_python_text() {
    for (text, python) in [
        ("1.00", "1.0"),
        ("1e5", "100000.0"),
        ("1E-7", "1e-07"),
        ("2.5E+3", "2500.0"),
        ("-0", "0"),
        ("-0.0", "-0.0"),
        ("1e16", "1e+16"),
        ("5e-324", "5e-324"),
        ("1e-400", "0.0"),
        ("-17", "-17"),
        ("12345678901234567890", "12345678901234567890"),
    ] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            python_canonical(&value).unwrap().to_string(),
            python,
            "{text}"
        );
    }
}

#[test]
fn numbers_the_proxy_cannot_carry_defer() {
    let limit = "9".repeat(4_300);
    let past = "9".repeat(4_301);
    let at_limit: Value = serde_json::from_str(&format!("[{limit}, -{limit}]")).unwrap();
    assert_eq!(python_canonical(&at_limit), Some(at_limit.clone()));
    for text in ["1e400", "-1e400", "[1, {\"a\": 1e309}]", past.as_str()] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(python_canonical(&value), None, "{text}");
    }
    // `json.loads` reads these literals; the relay's parser refuses the frame.
    for text in ["NaN", "Infinity", "-Infinity"] {
        assert!(serde_json::from_str::<Value>(text).is_err(), "{text}");
    }
}

#[test]
fn keys_and_strings_pass_through() {
    let value: Value =
        serde_json::from_str(r#"{"z":"1.00","a":["é",{"y":null,"b":true}]}"#).unwrap();
    let canonical = python_canonical(&value).unwrap();
    // The relay's parser keeps keys sorted, as the resident's does when it
    // decodes the proxy's frame, so the child reads them in the same order.
    assert_eq!(
        serde_json::to_string(&canonical).unwrap(),
        r#"{"a":["é",{"b":true,"y":null}],"z":"1.00"}"#
    );
}
