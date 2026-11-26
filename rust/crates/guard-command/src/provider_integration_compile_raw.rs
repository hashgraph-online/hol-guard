//! Raw `guard.provider-integration.v1` shapes. Unknown fields are refused, derived struct decoding
//! refuses a repeated key, and [`UniqueMap`] does the same for the free-form objects.

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserializer, Error, MapAccess, Visitor};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawManifest {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub publisher: RawPublisher,
    pub summary: String,
    pub surfaces: Vec<String>,
    pub auth: RawAuth,
    pub hosts: Vec<String>,
    pub capabilities: Vec<RawCapability>,
    #[serde(default, deserialize_with = "present")]
    pub verify: Option<RawRequest>,
    pub limits: RawLimits,
    pub privacy_url: String,
    pub terms_url: String,
    #[serde(default, deserialize_with = "present")]
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawPublisher {
    pub name: String,
    #[serde(default, deserialize_with = "present")]
    pub url: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawAuth {
    pub kind: String,
    pub header: String,
    pub key_format: RawKeyFormat,
    #[serde(default, deserialize_with = "present")]
    pub obtain_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawKeyFormat {
    pub min_length: u32,
    pub max_length: u32,
    pub charset: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCapability {
    pub id: String,
    pub request: RawRequest,
    pub response: RawResponse,
    pub shares: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRequest {
    pub method: String,
    #[serde(default, deserialize_with = "present")]
    pub host: Option<String>,
    pub path: String,
    #[serde(default, deserialize_with = "present")]
    pub body: Option<UniqueMap<RawFactRef>>,
}

/// A request body value. Only a named fact is accepted, so a body cannot carry a literal, a
/// template or a user-supplied value.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawFactRef {
    pub fact: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawResponse {
    pub verdict: RawVerdict,
    #[serde(default, deserialize_with = "present")]
    pub reason_codes: Option<RawReasonCodes>,
    #[serde(default, deserialize_with = "present")]
    pub ttl_seconds: Option<RawTtl>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVerdict {
    pub pointer: String,
    pub map: UniqueMap<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawReasonCodes {
    pub pointer: String,
    pub allow: Vec<String>,
    #[serde(default, deserialize_with = "present")]
    pub labels: Option<UniqueMap<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTtl {
    pub pointer: String,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawLimits {
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
    pub max_requests_per_minute: u64,
}

/// An optional field that, when present, must hold a value. `null` is refused.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// A JSON object kept in source order whose keys must be unique.
#[derive(Debug)]
pub(super) struct UniqueMap<V>(Vec<(String, V)>);

impl<V> UniqueMap<V> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.0.iter().map(|(key, value)| (key, value))
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for UniqueMap<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueMapVisitor<V>(PhantomData<V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for UniqueMapVisitor<V> {
            type Value = UniqueMap<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique keys")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                let mut entries = Vec::new();
                while let Some((key, value)) = access.next_entry::<String, V>()? {
                    if !seen.insert(key.clone()) {
                        return Err(A::Error::custom("duplicate key"));
                    }
                    entries.push((key, value));
                }
                Ok(UniqueMap(entries))
            }
        }

        deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
    }
}
