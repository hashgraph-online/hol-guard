//! Golden bytes from `ci/gauntlet/benchmark/json_data.py` in Gauntlet PR #5263.
//! Source commit: b4efd8171b06d0e13cbe12a077c376ecdc891fd1.
//! Source file SHA-256: 5d7a9b3b350ac5a7c318f02af8916101551371459f487cc0e5abd037792f817e.

use gauntlet_contracts::{canonical_sha256, canonicalize, ContractError, MAX_RECORD_BYTES};

#[test]
fn python_canonical_bytes_and_digests() {
    let cases = [
        (
            r#"{"z":1,"a":"café","bool":true}"#,
            r#"{"a":"café","bool":true,"z":1}"#,
            "62b0dadc8186955c89b6711b05777790780aca240812e8f07667af6080a480fa",
        ),
        (
            r#"{"escaped":"line\nbreak","emoji":"\ud83d\ude00","slash":"a/b"}"#,
            r#"{"emoji":"😀","escaped":"line\nbreak","slash":"a/b"}"#,
            "12bb32e30b95076aba22351453e5c08b96901d6965a4e622a534cba0b141207c",
        ),
        (
            "[1.0,-0.0,1e20,1e-5,0.0001,1000000000000000.0,1e16]",
            "[1.0,-0.0,1e+20,1e-05,0.0001,1000000000000000.0,1e+16]",
            "50614fe4feb39a00fef33d9d7ca6acdf47455142b90be838ca1428562e9a5452",
        ),
        (
            r#"{"int":9223372036854775808,"negzero":-0}"#,
            r#"{"int":9223372036854775808,"negzero":0}"#,
            "443a822090374900827d117b6e4ee3fa2388db15a362c71ab5282e4720e27b1c",
        ),
        (
            r#"{"nested":{"x":[true,null,{"a":2}]}}"#,
            r#"{"nested":{"x":[true,null,{"a":2}]}}"#,
            "046c79c5d280f1145d5621bc112c759b0e7fd4206038ab3c5052a7ef01872fbb",
        ),
        (
            "[1e-4,1e-5,1e-6,1e+15,1e+16]",
            "[0.0001,1e-05,1e-06,1000000000000000.0,1e+16]",
            "0eeb96d3e63cc8be3f334e4133523d5338c66029dbff7f512392328addf60a28",
        ),
        (
            "{ \"b\" : 2, \"a\" : 1 }",
            r#"{"a":1,"b":2}"#,
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
        ),
        (
            "[5e-324,1e-323,2.2250738585072014e-308,1.7976931348623157e308]",
            "[5e-324,1e-323,2.2250738585072014e-308,1.7976931348623157e+308]",
            "a891d4bb17acc135b7687228166d8138a5653d5788efa479430f818607f4bb91",
        ),
        (
            "[1.2345678901234567,999999999999999.9,1000000000000000.1,9.999999999999999e15]",
            "[1.2345678901234567,999999999999999.9,1000000000000000.1,1e+16]",
            "c2e5bc138c8a27081b1273486b7951e8e7605feffcc8cb49535886704ad2295d",
        ),
        (
            "[1e-4,9.999e-5,1e-5,-1e-5,9.999999999999999e-5]",
            "[0.0001,9.999e-05,1e-05,-1e-05,9.999999999999999e-05]",
            "49d8d2fa05028e2dc9440c4f46882bce1b0f33ac2ecac9f0c4a0d41c434719d6",
        ),
        (
            "[1e15,9.99999999999999e15,1e16,-1e16,1.1e16]",
            "[1000000000000000.0,9999999999999990.0,1e+16,-1e+16,1.1e+16]",
            "87a0c136ef61dfc176d103ef8d5d6de4472f4478c788379c251ddd8789d49ed4",
        ),
        (
            "[0.00009999999999999999,0.00010000000000000002]",
            "[9.999999999999999e-05,0.00010000000000000002]",
            "66a793bbadafeda43869145a352e88c9b58d6667aa5e037d3ca74a47d87c25b7",
        ),
    ];

    for (raw, expected, expected_digest) in cases {
        assert_eq!(
            canonicalize(raw.as_bytes()).unwrap(),
            expected.as_bytes(),
            "{raw}"
        );
        assert_eq!(
            canonical_sha256(raw.as_bytes()).unwrap(),
            expected_digest,
            "{raw}"
        );
    }
}

#[test]
fn finite_float_vectors_match_python() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("python_float_vectors.json")).unwrap();
    assert_eq!(
        vectors["source_commit"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    assert_eq!(
        vectors["source_sha256"],
        "5d7a9b3b350ac5a7c318f02af8916101551371459f487cc0e5abd037792f817e"
    );
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 256);
    for case in cases {
        let raw = case["raw"].as_str().unwrap();
        let expected = case["canonical"].as_str().unwrap();
        assert_eq!(
            canonicalize(raw.as_bytes()).unwrap(),
            expected.as_bytes(),
            "{raw}"
        );
    }
}

#[test]
fn accepts_python_json_byte_encodings() {
    let json = r#"{"a":"é"}"#;
    let expected = json.as_bytes();
    let utf16_be: Vec<u8> = json.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let utf16_le: Vec<u8> = json.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let utf32_be: Vec<u8> = json
        .chars()
        .flat_map(|ch| u32::from(ch).to_be_bytes())
        .collect();
    let utf32_le: Vec<u8> = json
        .chars()
        .flat_map(|ch| u32::from(ch).to_le_bytes())
        .collect();
    let cases = [
        [&[0xef, 0xbb, 0xbf][..], expected].concat(),
        utf16_be.clone(),
        utf16_le.clone(),
        utf32_be.clone(),
        utf32_le.clone(),
        [&[0xfe, 0xff][..], &utf16_be].concat(),
        [&[0xff, 0xfe][..], &utf16_le].concat(),
        [&[0, 0, 0xfe, 0xff][..], &utf32_be].concat(),
        [&[0xff, 0xfe, 0, 0][..], &utf32_le].concat(),
    ];
    for raw in cases {
        assert_eq!(canonicalize(&raw).unwrap(), expected, "{raw:?}");
    }
}

#[test]
fn rejects_ambiguous_or_invalid_input() {
    let cases: &[(&[u8], ContractError)] = &[
        (br#"{"x":1,"x":2}"#, ContractError::DuplicateKey),
        (br#"{"x":1,"\u0078":2}"#, ContractError::DuplicateKey),
        (b"NaN", ContractError::InvalidJson),
        (b"Infinity", ContractError::InvalidJson),
        (b"1e400", ContractError::NonFiniteNumber),
        (b"[1,]", ContractError::InvalidJson),
        (br#"{"a":1,}"#, ContractError::InvalidJson),
        (b"01", ContractError::InvalidJson),
        (br#""\ud800""#, ContractError::InvalidJson),
        (b"{\"a\":\xff}", ContractError::InvalidJson),
        (&[0xff, 0xfe, 0, 0, 0x7b], ContractError::InvalidJson),
    ];
    for (raw, expected) in cases {
        assert_eq!(canonicalize(raw), Err(*expected), "{raw:?}");
    }
}

#[test]
fn enforces_python_resource_bounds() {
    let deep = format!("{}null{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(canonicalize(deep.as_bytes()), Err(ContractError::TooDeep));

    let many_nodes = format!("[{}]", vec!["null"; 500_000].join(","));
    assert_eq!(
        canonicalize(many_nodes.as_bytes()),
        Err(ContractError::TooManyNodes)
    );

    let huge = vec![b' '; MAX_RECORD_BYTES + 1];
    assert_eq!(canonicalize(&huge), Err(ContractError::TooManyBytes));

    let huge_integer = "9".repeat(4_301);
    assert_eq!(
        canonicalize(huge_integer.as_bytes()),
        Err(ContractError::TooManyIntegerDigits)
    );
}
