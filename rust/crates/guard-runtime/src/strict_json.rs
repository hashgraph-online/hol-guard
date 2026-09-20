#![forbid(unsafe_code)]

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::fmt;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
    mode: Projection,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Projection {
    Full,
    DeadlineBudget,
    Discard,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom("native_json_depth_exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor {
            depth: self.depth,
            mode: self.mode,
        })
    }
}

struct StrictJsonVisitor {
    depth: usize,
    mode: Projection,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_json_number_invalid"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("native_json_string_too_large"));
        }
        if self.mode == Projection::Discard {
            Ok(Value::Null)
        } else {
            Ok(Value::String(value.to_owned()))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("native_json_string_too_large"));
        }
        Ok(if self.mode == Projection::Discard {
            Value::Null
        } else {
            Value::String(value)
        })
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonSeed {
            depth: self.depth,
            mode: self.mode,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        let mut items_seen = 0usize;
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
            mode: if self.mode == Projection::Full {
                Projection::Full
            } else {
                Projection::Discard
            },
        })? {
            if items_seen >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_array_too_wide"));
            }
            items_seen += 1;
            if self.mode == Projection::Full {
                output.push(value);
            }
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_JSON_STRING_BYTES {
                return Err(serde::de::Error::custom("native_json_key_too_large"));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("native_json_duplicate_key"));
            }
            if seen.len() > MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_object_too_wide"));
            }
            let retain = self.mode == Projection::Full
                || (self.mode == Projection::DeadlineBudget && key == "deadline_budget_ms");
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
                mode: if retain {
                    Projection::Full
                } else {
                    Projection::Discard
                },
            })?;
            if retain {
                output.insert(key, value);
            }
        }
        Ok(Value::Object(output))
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    parse_projected(bytes, Projection::Full)
}

/// Validate the same complete JSON contract as `parse`, while retaining only
/// the root timeout field. Nested strings, arrays and objects still pass all
/// duplicate-key, depth, width and string-size checks before the helper uses
/// this transport hint; they are not materialized as a second payload tree.
pub(crate) fn deadline_budget_ms(bytes: &[u8]) -> Result<Option<u64>, String> {
    let value = parse_projected(bytes, Projection::DeadlineBudget)?;
    Ok(value.get("deadline_budget_ms").and_then(Value::as_u64))
}

fn parse_projected(bytes: &[u8], mode: Projection) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed { depth: 0, mode }
        .deserialize(&mut deserializer)
        .map_err(|_| "native_request_invalid_json".to_owned())?;
    deserializer
        .end()
        .map_err(|_| "native_request_trailing_json".to_owned())?;
    Ok(value)
}

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_DEPTH: usize = MAX_JSON_DEPTH;

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_COLLECTION_ITEMS: usize = MAX_JSON_COLLECTION_ITEMS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_projection_obeys_the_full_strict_json_contract() {
        let mut fixtures: Vec<Vec<u8>> = vec![
            br#"{"deadline_budget_ms":250,"request":{"text":"hello"}}"#.to_vec(),
            br#"{"request":{"deadline_budget_ms":1},"deadline_budget_ms":750}"#.to_vec(),
            br#"{"deadline_budget_ms":null}"#.to_vec(),
            br#"{"deadline_budget_ms":"250"}"#.to_vec(),
            br#"{"deadline_budget_ms":-1}"#.to_vec(),
            br#"{"deadline_budget_ms":250,"request":{"x":1,"x":2}}"#.to_vec(),
            br#"{"deadline_budget_ms":250,"deadline_budget_ms":1}"#.to_vec(),
            br#"{"deadline_budget_ms":250,"request":{"x":1,"\u0078":2}}"#.to_vec(),
            br#"{"deadline_budget_ms":250} {}"#.to_vec(),
            b"{\"request\":\"\xff\"}".to_vec(),
        ];
        fixtures.push(
            format!(
                r#"{{"request":"{}"}}"#,
                "x".repeat(MAX_JSON_STRING_BYTES + 1)
            )
            .into_bytes(),
        );
        fixtures.push(
            format!(
                r#"{{"request":{}0{}}}"#,
                "[".repeat(MAX_JSON_DEPTH + 1),
                "]".repeat(MAX_JSON_DEPTH + 1)
            )
            .into_bytes(),
        );
        fixtures.push(
            serde_json::to_vec(
                &serde_json::json!({"request": vec![0; MAX_JSON_COLLECTION_ITEMS + 1]}),
            )
            .unwrap(),
        );
        let wide: Map<String, Value> = (0..MAX_JSON_COLLECTION_ITEMS + 1)
            .map(|index| (index.to_string(), Value::Null))
            .collect();
        fixtures.push(serde_json::to_vec(&serde_json::json!({"request": wide})).unwrap());
        for (index, fixture) in fixtures.iter().enumerate() {
            let reference =
                parse(fixture).map(|value| value.get("deadline_budget_ms").and_then(Value::as_u64));
            assert_eq!(deadline_budget_ms(fixture), reference, "fixture {index}");
        }
    }

    #[test]
    #[ignore = "diagnostic release microbenchmark; not an installed latency gate"]
    fn benchmark_timeout_projection() {
        use std::hint::black_box;
        use std::time::Instant;
        for (name, size) in [
            ("small_16k", 16 * 1024),
            ("maximum_string", MAX_JSON_STRING_BYTES),
        ] {
            let payload = serde_json::to_vec(&serde_json::json!({
                "deadline_budget_ms": 750, "request": {"text": "x".repeat(size)}
            }))
            .unwrap();
            let mut baseline = Vec::new();
            let mut candidate = Vec::new();
            for round in 0..5 {
                for _ in 0..20 {
                    for optimized in [round % 2 == 0, round % 2 != 0] {
                        let started = Instant::now();
                        let budget = if optimized {
                            deadline_budget_ms(black_box(&payload)).unwrap()
                        } else {
                            parse(black_box(&payload))
                                .unwrap()
                                .get("deadline_budget_ms")
                                .and_then(Value::as_u64)
                        };
                        assert_eq!(black_box(budget), Some(750));
                        let micros = started.elapsed().as_secs_f64() * 1_000_000.0;
                        if optimized {
                            candidate.push(micros);
                        } else {
                            baseline.push(micros);
                        }
                    }
                }
            }
            baseline.sort_by(f64::total_cmp);
            candidate.sort_by(f64::total_cmp);
            println!("{{\"benchmark\":\"timeout_projection\",\"fixture\":\"{name}\",\"samples\":100,\"baseline_p95_us\":{},\"candidate_p95_us\":{}}}", baseline[94], candidate[94]);
        }
    }
}
