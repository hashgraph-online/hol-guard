//! Cloud action packs: provider actions described as data.
//!
//! A pack (`guard.cloud-action-pack.v1`) names one provider, the hosts its
//! requests may reach, how it signs in, and each action it offers: the exact
//! request, the arguments a caller may set and their bounds, the facts Guard
//! derives from those arguments, the response fields that come back, and the
//! safety limits a host must enforce. The language has no expressions, no
//! loops beyond a bounded copy of one array argument, no free-form headers and
//! no network reference outside the declared hosts, so a third-party pack can
//! be reviewed as data.
//!
//! Everything here is pure: rendering builds a request but never sends it, and
//! projection reads a response the host already received.

use crate::cloud_action_binding::{ActionEffect, TargetCapability};
use crate::effect_decision::GuardAction;
use guard_contracts::{ActionClassV2, SensitivityV2};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const PACK_SCHEMA: &str = "guard.cloud-action-pack.v1";
/// Largest pack document accepted, fixtures included.
pub const MAX_PACK_BYTES: usize = 1024 * 1024;
pub const MAX_ACTIONS: usize = 256;
pub const MAX_HOSTS: usize = 16;
pub const MAX_ARGUMENTS: usize = 32;
pub const MAX_FIXTURES: usize = 32;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_TEMPLATE_DEPTH: usize = 8;
pub const MAX_PAGES: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudActionPack {
    pub schema: String,
    pub provider: Provider,
    /// Exact API host names; requests may reach no other host.
    pub hosts: Vec<String>,
    pub auth: Auth,
    pub actions: Vec<PackAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub publisher: Publisher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Publisher {
    pub name: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    Oauth2,
    GithubApp,
    ApiKey,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Auth {
    pub mode: AuthMode,
    /// Every provider permission any action needs, in the provider's terms.
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackAction {
    pub action_id: String,
    pub title: String,
    /// The local command permission or MCP tool this action shares a policy name with.
    pub link: Option<ActionLink>,
    pub executor: Executor,
    pub arguments: BTreeMap<String, ArgumentSpec>,
    pub facts: FactSpec,
    pub response: ResponseSpec,
    pub safety: Safety,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixtures: Vec<Fixture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionLink {
    pub permission_id: Option<String>,
    pub tool: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Executor {
    DeclarativeHttp { request: RequestTemplate },
    RemoteMcp { tool: String },
    Broker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "DELETE")]
    Delete,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestTemplate {
    pub method: HttpMethod,
    pub host: String,
    /// `/literal/{arg}/literal`; `{arg*}` spans segments split on `/`.
    pub path: String,
    #[serde(default)]
    pub query: Vec<QueryParam>,
    /// Constant headers only; credential-bearing names are refused.
    #[serde(default)]
    pub headers: Vec<HeaderParam>,
    pub body: Option<Template>,
    pub max_pages: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryParam {
    pub name: String,
    pub value: ValueSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ValueSource {
    /// A caller argument; omitted when absent and no default is set.
    Arg {
        name: String,
        default: Option<Value>,
    },
    /// A fixed value callers cannot set.
    Const(Value),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeaderParam {
    pub name: String,
    pub value: String,
}

/// A JSON body template, written in the order it is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Template {
    /// A caller argument; an object field holding an absent one is left out.
    Arg(String),
    Const(Value),
    Object(Vec<TemplateField>),
    Array(Vec<Template>),
    /// One `item` per element of an array argument, bounded by its `maxItems`.
    Each {
        arg: String,
        item: Box<Template>,
    },
    /// The current element inside `each`; must be `true`.
    Element(bool),
    /// A base64url plain-text message built from recipient and text arguments.
    Rfc822(crate::cloud_pack_mail::MailTemplate),
    /// A one-field object whose field name is a required, pattern-bound string argument.
    Keyed {
        key: String,
        value: Box<Template>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateField {
    pub name: String,
    pub value: Template,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ArgumentSpec {
    #[serde(rename_all = "camelCase")]
    String {
        required: bool,
        pattern: Option<String>,
        max_length: u32,
        forbidden: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Integer {
        required: bool,
        minimum: i64,
        maximum: i64,
    },
    #[serde(rename_all = "camelCase")]
    Boolean { required: bool },
    #[serde(rename_all = "camelCase")]
    Array {
        required: bool,
        min_items: u32,
        max_items: u32,
        items: TextRule,
    },
}

impl ArgumentSpec {
    /// The string bounds of a `string` argument or of each `array` item.
    pub fn text_rule(&self) -> Option<TextRule> {
        match self {
            Self::String {
                pattern,
                max_length,
                forbidden,
                ..
            } => Some(TextRule {
                pattern: pattern.clone(),
                max_length: *max_length,
                forbidden: forbidden.clone(),
            }),
            Self::Array { items, .. } => Some(items.clone()),
            Self::Integer { .. } | Self::Boolean { .. } => None,
        }
    }

    pub const fn required(&self) -> bool {
        match self {
            Self::String { required, .. }
            | Self::Integer { required, .. }
            | Self::Boolean { required }
            | Self::Array { required, .. } => *required,
        }
    }
}

/// Bounds on one string. `pattern` must be anchored (`^...$`); `forbidden`
/// matches content the action never sends. Both use the linear-time engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextRule {
    pub pattern: Option<String>,
    pub max_length: u32,
    pub forbidden: Option<String>,
}

/// How each fact is derived. A fact left out is `unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactSpec {
    pub class: ActionClassV2,
    pub object: Option<Extractor>,
    pub reversibility: Option<Extractor>,
    pub scope: Option<Extractor>,
    pub record_count: Option<Extractor>,
    pub recipient_count: Option<Extractor>,
    pub byte_count: Option<Extractor>,
    pub audience_kind: Option<Extractor>,
    pub recipient_domains: Option<Extractor>,
    pub environment: Option<Extractor>,
    pub sensitivity: Option<Extractor>,
    /// A read action in this pack the gateway may run to learn the volume.
    pub count_readback: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Extractor {
    Const(Value),
    /// A boolean argument picks one value; an absent one picks `whenAbsent` or is unknown.
    #[serde(rename_all = "camelCase")]
    Flag {
        argument: String,
        when_true: Value,
        when_false: Value,
        when_absent: Option<Value>,
    },
    /// The summed length of array arguments; an absent one counts zero.
    Count {
        arguments: Vec<String>,
    },
    /// An integer argument, known only within `0..=max`.
    #[serde(rename_all = "camelCase")]
    Argument {
        name: String,
        max: u64,
        default: Option<u64>,
    },
    /// The lowercased domains of the addresses in these arguments.
    Domains {
        arguments: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseSpec {
    pub max_bytes: u64,
    /// A success with no body (HTTP 204, or an empty 200) projects as if the
    /// provider had sent `{}`. Off by default, so a read that comes back
    /// empty still fails instead of passing as an empty result.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub empty_ok: bool,
    pub fields: Vec<ResponseField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseField {
    pub name: String,
    pub value: FieldSource,
    /// Provider content a model must treat as data, never as instructions.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub untrusted: bool,
    pub sensitivity: Option<SensitivityV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum FieldSource {
    /// A scalar at this dotted path.
    From(String),
    /// Whether this dotted path is present and not null.
    Exists(String),
    #[serde(rename_all = "camelCase")]
    List {
        from: String,
        max_items: u32,
        fields: Vec<ResponseField>,
    },
    Object {
        from: String,
        fields: Vec<ResponseField>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Idempotency {
    SafeRead,
    ProviderKey,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Safety {
    pub effect: ActionEffect,
    pub required_capabilities: BTreeSet<TargetCapability>,
    pub resource: Option<ResourceRef>,
    pub idempotency: Idempotency,
    pub scopes: BTreeSet<String>,
    pub max_items: u32,
    pub min_interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRef {
    pub kind: String,
    pub argument: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureKind {
    Safe,
    Risky,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fixture {
    pub name: String,
    pub kind: FixtureKind,
    pub arguments: Value,
    pub expect: FixtureExpect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureExpect {
    /// The argument error code the call is refused with.
    pub error: Option<String>,
    /// Facts to compare by top-level key with the extracted facts.
    pub facts: Option<serde_json::Map<String, Value>>,
    /// The exact request the executor sends (`declarative-http` only).
    pub request: Option<Value>,
    /// A recorded provider response body and the projection it yields.
    pub response: Option<String>,
    pub projection: Option<Value>,
    /// The policy decision under each shipped preset, from the extracted
    /// facts with a clean session and zeroed usage windows.
    pub decisions: Option<PresetDecisions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetDecisions {
    pub relaxed: Option<GuardAction>,
    pub balanced: Option<GuardAction>,
    pub strict: Option<GuardAction>,
}

/// A pack error: a stable code and the JSON pointer it applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError {
    pub code: &'static str,
    pub pointer: String,
}

impl PackError {
    pub fn new(code: &'static str, pointer: impl Into<String>) -> Self {
        Self {
            code,
            pointer: pointer.into(),
        }
    }
}

/// Parse a pack strictly (duplicate keys, depth and unknown fields refused) and validate it.
pub fn parse_pack(bytes: &[u8]) -> Result<CloudActionPack, PackError> {
    if bytes.len() > MAX_PACK_BYTES {
        return Err(PackError::new("cloud_pack_too_large", ""));
    }
    let value = crate::cloud_action_canonical::parse_strict(bytes)
        .map_err(|_| PackError::new("cloud_pack_json_invalid", ""))?;
    pack_from_value(value)
}

pub fn pack_from_value(value: Value) -> Result<CloudActionPack, PackError> {
    within_limit(&value)?;
    let pack: CloudActionPack = serde_json::from_value(value)
        .map_err(|_| PackError::new("cloud_pack_shape_invalid", ""))?;
    crate::cloud_pack_validate::validate(&pack)?;
    Ok(pack)
}

/// Refuse an already-parsed value whose serialized form exceeds [`MAX_PACK_BYTES`].
pub(crate) fn within_limit(value: &Value) -> Result<(), PackError> {
    let len = serde_json::to_vec(value)
        .map_err(|_| PackError::new("cloud_pack_json_invalid", ""))?
        .len();
    if len > MAX_PACK_BYTES {
        return Err(PackError::new("cloud_pack_too_large", ""));
    }
    Ok(())
}

impl CloudActionPack {
    pub fn action(&self, action_id: &str) -> Option<&PackAction> {
        self.actions
            .iter()
            .find(|action| action.action_id == action_id)
    }
}
