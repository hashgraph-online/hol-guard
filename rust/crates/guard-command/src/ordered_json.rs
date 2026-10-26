//! JSON parse that keeps object keys in document order.
//!
//! Python's `json.loads` returns dicts that iterate in insertion order, and a
//! repeated key keeps its first position while taking the last value.
//! `serde_json::Value` objects sort their keys instead, which changes the order
//! dependencies reach the workspace inventory. Only objects need ordering here:
//! arrays and scalars are carried as plain `serde_json::Value`.

use std::collections::HashMap;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;

const NUMBER_TOKEN: &str = "$serde_json::private::Number";

#[derive(Debug, Clone, PartialEq)]
pub enum Ordered {
    Object(OrderedObject),
    Other(Value),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrderedObject {
    entries: Vec<(String, Ordered)>,
}

impl Ordered {
    pub fn as_object(&self) -> Option<&OrderedObject> {
        match self {
            Self::Object(object) => Some(object),
            Self::Other(_) => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Other(value) => value.as_str(),
            Self::Object(_) => None,
        }
    }
}

impl OrderedObject {
    pub fn get(&self, key: &str) -> Option<&Ordered> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Entries in document order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Ordered)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }
}

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor;

        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = Ordered;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut entries: Vec<(String, Ordered)> = Vec::new();
                let mut positions: HashMap<String, usize> = HashMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    // `arbitrary_precision` hands numbers over as a one-entry
                    // map holding the literal text. A genuine object that merely
                    // uses the same key (extra keys, or a non-numeric value) is
                    // kept as an ordinary entry.
                    if entries.is_empty() && key == NUMBER_TOKEN {
                        let first = map.next_value::<Ordered>()?;
                        let literal_number = first
                            .as_str()
                            .and_then(|text| serde_json::from_str::<Value>(text).ok())
                            .filter(Value::is_number);
                        let next = map.next_key::<String>()?;
                        match (literal_number, next) {
                            (Some(number), None) => return Ok(Ordered::Other(number)),
                            (_, None) => {
                                positions.insert(key.clone(), 0);
                                entries.push((key, first));
                            }
                            (_, Some(next_key)) => {
                                positions.insert(key.clone(), entries.len());
                                entries.push((key, first));
                                let value = map.next_value::<Ordered>()?;
                                match positions.get(&next_key).copied() {
                                    Some(position) => entries[position].1 = value,
                                    None => {
                                        positions.insert(next_key.clone(), entries.len());
                                        entries.push((next_key, value));
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    let value = map.next_value::<Ordered>()?;
                    match positions.get(&key) {
                        Some(position) => entries[*position].1 = value,
                        None => {
                            positions.insert(key.clone(), entries.len());
                            entries.push((key, value));
                        }
                    }
                }
                Ok(Ordered::Object(OrderedObject { entries }))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Value>()? {
                    items.push(item);
                }
                Ok(Ordered::Other(Value::Array(items)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::from(value)))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::from(value)))
            }

            fn visit_bool<E>(self, value: bool) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::Bool(value)))
            }

            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::Null))
            }

            fn visit_str<E>(self, value: &str) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Ordered, E> {
                Ok(Ordered::Other(Value::String(value)))
            }
        }

        deserializer.deserialize_any(OrderedVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Ordered {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn keeps_document_order_and_first_position_of_repeated_keys() {
        let parsed = parse(r#"{"b": "1", "a": "2", "b": "3"}"#);
        let entries: Vec<(&str, &str)> = parsed
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str().unwrap()))
            .collect();
        assert_eq!(entries, [("b", "3"), ("a", "2")]);
    }

    #[test]
    fn accepts_every_scalar_and_nested_container() {
        let parsed = parse(
            r#"{"n": 3, "f": 1.5, "big": 123456789012345678901234567890, "t": true,
                "z": null, "s": "x", "a": [1, {"k": 2}], "o": {"i": 4}}"#,
        );
        let object = parsed.as_object().unwrap();
        assert_eq!(object.iter().count(), 8);
        assert_eq!(object.get("n"), Some(&Ordered::Other(serde_json::json!(3))));
        assert_eq!(object.get("t"), Some(&Ordered::Other(Value::Bool(true))));
        assert!(object.get("o").unwrap().as_object().is_some());
    }

    #[test]
    fn object_reusing_the_number_token_key_stays_an_object() {
        let parsed = parse(r#"{"$serde_json::private::Number": "x", "b": "2"}"#);
        let keys: Vec<&str> = parsed
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(keys, ["$serde_json::private::Number", "b"]);
        let parsed = parse(
            r#"{"$serde_json::private::Number": "1", "dependencies": {"left-pad": "1.0.0"}, "name": "app"}"#,
        );
        let object = parsed.as_object().unwrap();
        let keys: Vec<&str> = object.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            ["$serde_json::private::Number", "dependencies", "name"]
        );
        assert_eq!(
            object
                .get("dependencies")
                .unwrap()
                .as_object()
                .unwrap()
                .get("left-pad")
                .unwrap()
                .as_str(),
            Some("1.0.0")
        );
        let parsed = parse(r#"{"$serde_json::private::Number": {"a": "1"}}"#);
        assert!(parsed.as_object().is_some());
    }
}
