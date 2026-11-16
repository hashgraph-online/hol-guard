//! The state-tagged fact wrapper used by `guard.action-facts.v2`.

use serde::de::{DeserializeOwned, Deserializer, Error as _, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;

/// A fact whose value may be unavailable. `unsupported` means the producer
/// cannot know it for this action; consumers treat it like `unknown`.
///
/// The wire form is `{"state": "known", "value": ...}`, `{"state": "unknown"}`
/// or `{"state": "unsupported"}`. Decoding is strict: no other key, a value
/// only with `known`, and no `"value": null` on an unknown fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Fact<T> {
    Known(T),
    Unknown,
    Unsupported,
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Fact<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(FactVisitor(PhantomData))
    }
}

struct FactVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeOwned> Visitor<'de> for FactVisitor<T> {
    type Value = Fact<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a fact object with a state and, when known, a value")
    }

    /// Walks the entries itself so a repeated `state` or `value` is refused
    /// rather than resolved to whichever copy a map keeps.
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        const FIELDS: &[&str] = &["state", "value"];
        let mut state: Option<String> = None;
        let mut value: Option<serde_json::Value> = None;
        while let Some(key) = access.next_key::<String>()? {
            match key.as_str() {
                "state" if state.is_some() => return Err(A::Error::duplicate_field("state")),
                "state" => state = Some(access.next_value()?),
                "value" if value.is_some() => return Err(A::Error::duplicate_field("value")),
                "value" => value = Some(access.next_value()?),
                other => return Err(A::Error::unknown_field(other, FIELDS)),
            }
        }
        let state = state.ok_or_else(|| A::Error::missing_field("state"))?;
        match (state.as_str(), value) {
            ("known", Some(value)) => serde_json::from_value(value)
                .map(Fact::Known)
                .map_err(A::Error::custom),
            ("known", None) => Err(A::Error::missing_field("value")),
            ("unknown", None) => Ok(Fact::Unknown),
            ("unsupported", None) => Ok(Fact::Unsupported),
            ("unknown" | "unsupported", Some(_)) => {
                Err(A::Error::custom("only a known fact carries a value"))
            }
            _ => Err(A::Error::custom(
                "fact state must be known, unknown or unsupported",
            )),
        }
    }
}

impl<T> Fact<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown | Self::Unsupported => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Fact;

    fn decode(text: &str) -> Result<Fact<String>, serde_json::Error> {
        serde_json::from_str(text)
    }

    #[test]
    fn a_repeated_state_or_value_is_refused() {
        for text in [
            r#"{"state":"unknown","state":"known","value":"message"}"#,
            r#"{"state":"known","value":"message","value":"thread"}"#,
        ] {
            let error = decode(text).unwrap_err().to_string();
            assert!(error.contains("duplicate field"), "{text}: {error}");
        }
    }

    #[test]
    fn each_state_decodes_once() {
        assert_eq!(
            decode(r#"{"value":"message","state":"known"}"#).unwrap(),
            Fact::Known("message".to_owned())
        );
        assert_eq!(decode(r#"{"state":"unknown"}"#).unwrap(), Fact::Unknown);
        assert_eq!(
            decode(r#"{"state":"unsupported"}"#).unwrap(),
            Fact::Unsupported
        );
        assert!(decode(r#"{"state":"unknown","value":null}"#).is_err());
        assert!(decode(r#"{"state":"maybe"}"#).is_err());
    }
}
