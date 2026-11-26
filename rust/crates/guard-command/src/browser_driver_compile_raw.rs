//! Raw `guard.browser-driver.v1` shapes. Unknown fields are refused, and derived struct decoding
//! refuses a repeated key. [`UniqueMap`] does the same for the free-form `cases` object.

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserializer, Error, MapAccess, Visitor};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawDriver {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub publisher: RawPublisher,
    #[serde(default)]
    pub reference_urls: Vec<String>,
    #[serde(default)]
    pub reference_version: Option<String>,
    #[serde(rename = "match")]
    pub matches: RawMatch,
    pub profile_mode: RawProfileMode,
    pub tools: Vec<RawTool>,
    #[serde(default)]
    pub volatile_fields: Vec<String>,
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawPublisher {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawMatch {
    pub mcp_server_names: Vec<String>,
    pub packages: Vec<String>,
    pub tool_namespaces: Vec<String>,
    pub harness_tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawProfileMode {
    pub default: String,
    #[serde(default)]
    pub flags: Option<RawProfileFlags>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawProfileFlags {
    #[serde(default)]
    pub isolated: Vec<String>,
    #[serde(default)]
    pub dedicated: Vec<String>,
    #[serde(default)]
    pub shared: Vec<String>,
    #[serde(default)]
    pub remote_debugging: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawElement {
    pub name: Vec<String>,
}

/// A tool entry. The compiler accepts exactly one of three shapes; see `compile_tool`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RawTool {
    pub name: String,
    #[serde(default)]
    pub verb: Option<String>,
    #[serde(default)]
    pub url: Option<Vec<String>>,
    #[serde(default)]
    pub element: Option<RawElement>,
    #[serde(default)]
    pub text: Option<Vec<String>>,
    #[serde(default)]
    pub script: Option<Vec<String>>,
    #[serde(default)]
    pub file: Option<Vec<String>>,
    #[serde(default)]
    pub discriminator: Option<String>,
    #[serde(default)]
    pub cases: Option<UniqueMap<RawOperation>>,
    #[serde(default)]
    pub cdp_passthrough: Option<RawCdpPassthrough>,
}

/// The tool's parts: a fixed operation (any operation field present), a discriminator, cases, and
/// a passthrough.
pub(super) type RawToolParts = (
    Option<RawOperation>,
    Option<String>,
    Option<UniqueMap<RawOperation>>,
    Option<RawCdpPassthrough>,
);

impl RawTool {
    pub fn into_parts(self) -> RawToolParts {
        let has_operation = self.verb.is_some()
            || self.url.is_some()
            || self.element.is_some()
            || self.text.is_some()
            || self.script.is_some()
            || self.file.is_some();
        let operation = has_operation.then_some(RawOperation {
            verb: self.verb,
            url: self.url,
            element: self.element,
            text: self.text,
            script: self.script,
            file: self.file,
        });
        (
            operation,
            self.discriminator,
            self.cases,
            self.cdp_passthrough,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawOperation {
    #[serde(default)]
    pub verb: Option<String>,
    #[serde(default)]
    pub url: Option<Vec<String>>,
    #[serde(default)]
    pub element: Option<RawElement>,
    #[serde(default)]
    pub text: Option<Vec<String>>,
    #[serde(default)]
    pub script: Option<Vec<String>>,
    #[serde(default)]
    pub file: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawCdpPassthrough {
    pub method: Vec<String>,
    #[serde(default)]
    pub params: Option<Vec<String>>,
}

/// An object whose keys are unique. A repeated key is a decode error, never a silent overwrite.
#[derive(Debug)]
pub(super) struct UniqueMap<V>(Vec<(String, V)>);

impl<V> UniqueMap<V> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_entries(self) -> Vec<(String, V)> {
        self.0
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

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                let mut entries: Vec<(String, V)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(A::Error::custom("duplicate key"));
                    }
                    let value = map.next_value()?;
                    entries.push((key, value));
                }
                Ok(UniqueMap(entries))
            }
        }

        deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
    }
}
