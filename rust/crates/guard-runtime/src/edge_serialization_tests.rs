use super::*;
use serde_json::json;

#[test]
fn borrowed_canonical_values_match_existing_bytes_for_every_json_kind() {
    let mut cases = vec![
        Value::Null,
        json!(true),
        json!(false),
        json!(i64::MIN),
        json!(u64::MAX),
        json!(-0.0),
        json!([null, true, false, -1, 0, 1, 0.000_001, 1e30]),
        json!({"🦀":"café", "z":"\u{0000}\n\r\t\"\\/", "a":{"timestamp":7,"é":["中", "\u{2028}", "\u{2029}"]}}),
    ];
    // Exercise finite IEEE-754 magnitudes, signs, normal and subnormal values
    // against the existing Number::to_string-based canonical implementation.
    let mut state = 0x9287_42ad_6735_1801_u64;
    for _ in 0..4096 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        if let Some(number) = serde_json::Number::from_f64(f64::from_bits(state)) {
            cases.push(Value::Number(number));
        }
    }
    for case in cases {
        let expected = guard_policy_snapshot::canonical_json_bytes(&case).unwrap();
        let actual = serde_json::to_vec(&Canonical(&case)).unwrap();
        assert_eq!(actual, expected, "canonical value: {case:?}");
        assert_eq!(
            serialized_size_within(&case, expected.len()).unwrap(),
            expected.len()
        );
        assert!(serialized_size_within(&case, expected.len() - 1).is_err());
    }
}

#[test]
fn counting_rejects_overflow_and_excess_without_partial_success() {
    let mut counter = BoundedCount {
        bytes: usize::MAX,
        maximum: usize::MAX,
    };
    assert_eq!(
        counter.write(b"x").unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(counter.bytes, usize::MAX);
    let mut counter = BoundedCount {
        bytes: 2,
        maximum: 3,
    };
    assert!(counter.write(b"ab").is_err());
    assert_eq!(counter.bytes, 2);
    assert_eq!(counter.write(b"a").unwrap(), 1);
    assert_eq!(counter.bytes, 3);
    assert_eq!(counter.write(b"").unwrap(), 0);
}

#[test]
fn serializer_failure_is_not_accepted_as_a_short_encoding() {
    struct Invalid;
    impl Serialize for Invalid {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("deliberate fixture failure"))
        }
    }
    assert!(serialized_size_within(&Invalid, usize::MAX).is_err());
}
