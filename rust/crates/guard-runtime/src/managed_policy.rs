//! The machine-managed policy document (`mdm/policy.py` `parse_managed_policy`).
//!
//! Machine authority reaches Guard as one JSON (or plist) document an
//! administrator installs. Python parses it, and everything downstream of the
//! parse — the effective Guard config, the policy-bundle trust anchors, the
//! managed network policy the caller performs egress under — reads the parsed
//! document, never the raw file. The native runtime needs the same answer
//! without asking Python: the relay loads Guard config and performs brokered
//! egress in-process, and both of those are machine-managed inputs.
//!
//! The parse is strict and all-or-nothing, exactly as Python's is. An unknown
//! key, a proxy URL carrying credentials or a locked setting with no managed
//! value rejects the whole document, which the loader records as an invalid
//! managed state rather than a partially honoured policy.

// The parse lands ahead of its callers: the native guard-config load and the
// relay's egress caller read it next.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use guard_command::egress_caller_policy::{ManagedNetworkPolicy, ProxyMode};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::context_digest::python_strip;

/// `MDM_POLICY_SCHEMA_VERSION` (mdm/contracts.py:12).
pub(crate) const POLICY_SCHEMA_VERSION: &str = "hol-guard-mdm-policy.v1";

/// `_TOP_LEVEL_KEYS` (mdm/policy.py:34).
const TOP_LEVEL_KEYS: [&str; 9] = [
    "schemaVersion",
    "settings",
    "lockedSettings",
    "requiredHarnesses",
    "policyBundleKeyring",
    "network",
    "update",
    "daemonStartup",
    "integrityTrust",
];
/// `_NETWORK_KEYS` (mdm/policy.py:45).
const NETWORK_KEYS: [&str; 4] = [
    "proxyMode",
    "proxyUrl",
    "caBundlePath",
    "allowPublicRegistries",
];
const INTEGRITY_KEYS: [&str; 3] = [
    "releasePublicKeys",
    "macosTeamId",
    "windowsSignerThumbprints",
];
/// Ed25519 public keys are 32 bytes.
const RELEASE_KEY_BYTES: usize = 32;
/// A SHA-1 certificate thumbprint in hex.
const THUMBPRINT_CHARS: usize = 40;

/// `base64.b64decode(..., validate=True)`: the standard alphabet, canonical
/// padding required, and — as CPython does — a final character whose unused
/// bits are not zero still decodes. Since 3.11, `validate=True` is
/// `a2b_base64(..., strict_mode=True)`, which rejects surplus `=` that an
/// older non-strict decoder ignored.
const PYTHON_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical),
);

/// Why a managed policy failed strict validation (`ManagedPolicyError`). The
/// text is the detail the loader records on an invalid managed state.
pub(crate) type PolicyError = String;

type PolicyResult<T> = Result<T, PolicyError>;

/// `ManagedUpdatePolicy` (mdm/contracts.py:345).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedUpdatePolicy {
    pub(crate) owner: InstallOwner,
    pub(crate) channel: String,
    pub(crate) minimum_version: Option<String>,
    pub(crate) maximum_version: Option<String>,
    pub(crate) allow_downgrade: bool,
    pub(crate) index_url: Option<String>,
}

impl Default for ManagedUpdatePolicy {
    fn default() -> Self {
        Self {
            owner: InstallOwner::User,
            channel: "stable".to_owned(),
            minimum_version: None,
            maximum_version: None,
            allow_downgrade: false,
            index_url: None,
        }
    }
}

/// `InstallOwner` (mdm/contracts.py:17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InstallOwner {
    #[default]
    User,
    Mdm,
}

impl InstallOwner {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mdm => "mdm",
        }
    }
}

/// `daemonStartup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum DaemonStartup {
    #[default]
    OnDemand,
    Login,
}

impl DaemonStartup {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OnDemand => "on-demand",
            Self::Login => "login",
        }
    }
}

/// `ManagedIntegrityTrust` (mdm/contracts.py:365).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ManagedIntegrityTrust {
    /// Key id to the 32-byte Ed25519 public key it names.
    pub(crate) release_public_keys: BTreeMap<String, Vec<u8>>,
    pub(crate) macos_team_id: Option<String>,
    /// Sorted, upper-case, space-free SHA-1 thumbprints.
    pub(crate) windows_signer_thumbprints: Vec<String>,
}

/// `ManagedPolicy` (mdm/contracts.py:379).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManagedPolicy {
    pub(crate) schema_version: String,
    pub(crate) settings: Map<String, Value>,
    pub(crate) locked_settings: BTreeSet<String>,
    /// Sorted and deduplicated, as Python's `tuple(sorted(set(...)))`.
    pub(crate) required_harnesses: Vec<String>,
    pub(crate) network: ManagedNetworkPolicy,
    pub(crate) update: ManagedUpdatePolicy,
    pub(crate) integrity_trust: ManagedIntegrityTrust,
    pub(crate) daemon_startup: DaemonStartup,
    /// `canonical_payload_hash` of the document as installed.
    pub(crate) content_hash: String,
    /// The keyring payload `policy_bundle_keyring_payload` builds, absent when
    /// the document does not configure one.
    pub(crate) policy_bundle_keyring: Option<Value>,
}

impl ManagedPolicy {
    pub(crate) fn install_owner(&self) -> InstallOwner {
        self.update.owner
    }
}

/// `parse_managed_policy` (mdm/policy.py:162).
pub(crate) fn parse_managed_policy(payload: &Value) -> PolicyResult<ManagedPolicy> {
    let root = expect_mapping(Some(payload), "policy")?;
    let unknown = unknown_keys(root, &TOP_LEVEL_KEYS);
    if !unknown.is_empty() {
        return Err(format!("unknown policy keys: {}", unknown.join(", ")));
    }
    if root.get("schemaVersion").and_then(Value::as_str) != Some(POLICY_SCHEMA_VERSION) {
        return Err("unsupported managed policy schema".to_owned());
    }

    let settings = validate_settings(root.get("settings"))?;
    let policy_bundle_keyring = match root.get("policyBundleKeyring") {
        Some(value) => Some(validate_policy_bundle_keyring(value)?),
        None => None,
    };
    let locked = locked_settings(root.get("lockedSettings"), &settings)?;
    let required_harnesses = required_harnesses(root.get("requiredHarnesses"))?;
    let network = parse_network(root.get("network"))?;
    let update = parse_update(root.get("update"))?;
    let daemon_startup = match root.get("daemonStartup") {
        None => DaemonStartup::OnDemand,
        Some(Value::String(text)) if text == "on-demand" => DaemonStartup::OnDemand,
        Some(Value::String(text)) if text == "login" => DaemonStartup::Login,
        _ => return Err("daemonStartup is invalid".to_owned()),
    };
    let integrity_trust = parse_integrity_trust(root.get("integrityTrust"))?;

    Ok(ManagedPolicy {
        schema_version: POLICY_SCHEMA_VERSION.to_owned(),
        settings,
        locked_settings: locked,
        required_harnesses,
        network,
        update,
        integrity_trust,
        daemon_startup,
        content_hash: canonical_payload_hash(root),
        policy_bundle_keyring,
    })
}

/// `canonical_payload_hash` (mdm/contracts.py:437).
pub(crate) fn canonical_payload_hash(payload: &Map<String, Value>) -> String {
    let mut encoded = Vec::new();
    // The document was parsed from JSON or a plist, so it holds no value the
    // canonical codec cannot write; an unencodable one hashes as empty rather
    // than passing a half-written buffer on.
    if guard_contracts::write_canonical_json(&Value::Object(payload.clone()), &mut encoded).is_err()
    {
        encoded.clear();
    }
    hex::encode(Sha256::digest(&encoded))
}

/// `_expect_mapping` (mdm/policy.py:52). An absent key reads as `{}`, as
/// Python's `root.get(name, {})` does.
fn expect_mapping<'a>(
    value: Option<&'a Value>,
    name: &str,
) -> PolicyResult<&'a Map<String, Value>> {
    match value {
        None => Err(format!("{name} must be an object")),
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(format!("{name} must be an object")),
    }
}

fn mapping_or_empty<'a>(
    value: Option<&'a Value>,
    name: &str,
) -> PolicyResult<Option<&'a Map<String, Value>>> {
    match value {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(format!("{name} must be an object")),
    }
}

fn unknown_keys(map: &Map<String, Value>, known: &[&str]) -> Vec<String> {
    let mut unknown: Vec<String> = map
        .keys()
        .filter(|key| !known.contains(&key.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    unknown
}

/// `_optional_string` (mdm/policy.py:58): the value is kept unstripped.
fn optional_string(value: Option<&Value>, name: &str) -> PolicyResult<Option<String>> {
    match value {
        // Python's `.get(name)` hands this helper `None` for both an absent key
        // and an explicit null, and the optional fields accept either.
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !python_strip(text).is_empty() => Ok(Some(text.clone())),
        _ => Err(format!("{name} must be a non-empty string or null")),
    }
}

/// `_optional_https_url` (mdm/policy.py:66).
fn optional_https_url(value: Option<&Value>, name: &str) -> PolicyResult<Option<String>> {
    let Some(url) = optional_string(value, name)? else {
        return Ok(None);
    };
    let invalid = || format!("{name} must be an absolute HTTPS URL");
    if url != python_strip(&url) || url.chars().any(python_is_space) {
        return Err(invalid());
    }
    let split = UrlSplit::parse(&url).ok_or_else(invalid)?;
    // `parsed.port` performs urllib's numeric and range validation.
    if split.port().is_err() {
        return Err(invalid());
    }
    if !split.scheme.eq_ignore_ascii_case("https") || split.netloc.is_empty() {
        return Err(invalid());
    }
    if split.hostname().is_none() {
        return Err(invalid());
    }
    if split.has_userinfo() {
        if name == "network.proxyUrl" {
            return Err("network proxy credentials are forbidden in managed policy".to_owned());
        }
        return Err(format!(
            "{name} credentials are forbidden in managed policy"
        ));
    }
    if url.contains('?') || url.contains('#') {
        return Err(format!("{name} must not contain a query or fragment"));
    }
    Ok(Some(url))
}

/// `_optional_proxy_url` (mdm/policy.py:89).
fn optional_proxy_url(value: Option<&Value>) -> PolicyResult<Option<String>> {
    let Some(url) = optional_https_url(value, "network.proxyUrl")? else {
        return Ok(None);
    };
    let split =
        UrlSplit::parse(&url).ok_or("network.proxyUrl must be an absolute HTTPS proxy origin")?;
    let rooted = split.path.is_empty() || split.path == "/";
    let port_zero = matches!(split.port(), Ok(Some(0)));
    if !rooted || split.netloc.ends_with(':') || port_zero {
        return Err("network.proxyUrl must be an absolute HTTPS proxy origin".to_owned());
    }
    Ok(Some(url))
}

/// `str.isspace`: CPython counts the Unicode whitespace property and the file
/// and record separators `U+001C`–`U+001F`, which Rust's `char` does not.
fn python_is_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `_validate_settings` (mdm/policy.py:99). A document parsed from JSON holds
/// only JSON values; a plist that carried a date or binary blob is rejected by
/// the loader before it reaches the parse.
fn validate_settings(value: Option<&Value>) -> PolicyResult<Map<String, Value>> {
    Ok(mapping_or_empty(value, "settings")?
        .cloned()
        .unwrap_or_default())
}

fn locked_settings(
    value: Option<&Value>,
    settings: &Map<String, Value>,
) -> PolicyResult<BTreeSet<String>> {
    let locked = match value {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(text) if !text.is_empty() => paths.push(text.to_owned()),
                    _ => {
                        return Err("lockedSettings must be an array of setting paths".to_owned());
                    }
                }
            }
            paths
        }
        _ => return Err("lockedSettings must be an array of setting paths".to_owned()),
    };
    let locked: BTreeSet<String> = locked.into_iter().collect();
    for path in &locked {
        if setting_at_path(settings, path).is_none() {
            return Err(format!("locked setting has no managed value: {path}"));
        }
    }
    Ok(locked)
}

/// `_get_path` (mdm/policy.py:406).
pub(crate) fn setting_at_path<'a>(
    settings: &'a Map<String, Value>,
    path: &str,
) -> Option<&'a Value> {
    let mut current: Option<&Value> = None;
    for part in path.split('.') {
        let map = match current {
            None => settings,
            Some(Value::Object(map)) => map,
            Some(_) => return None,
        };
        current = Some(map.get(part)?);
    }
    current
}

fn required_harnesses(value: Option<&Value>) -> PolicyResult<Vec<String>> {
    let names = match value {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        _ => return Err("requiredHarnesses must be an array of names".to_owned()),
    };
    let mut unique = BTreeSet::new();
    for item in names {
        match item.as_str() {
            Some(text) if !text.is_empty() => {
                unique.insert(text.to_owned());
            }
            _ => return Err("requiredHarnesses must be an array of names".to_owned()),
        }
    }
    Ok(unique.into_iter().collect())
}

fn parse_network(value: Option<&Value>) -> PolicyResult<ManagedNetworkPolicy> {
    let Some(raw) = mapping_or_empty(value, "network")? else {
        return Ok(ManagedNetworkPolicy::unmanaged_default());
    };
    let unknown = unknown_keys(raw, &NETWORK_KEYS);
    if !unknown.is_empty() {
        return Err(format!("unknown network keys: {}", unknown.join(", ")));
    }
    let proxy_mode = match raw.get("proxyMode") {
        None => ProxyMode::System,
        Some(Value::String(text)) if text == "system" => ProxyMode::System,
        Some(Value::String(text)) if text == "explicit" => ProxyMode::Explicit,
        Some(Value::String(text)) if text == "none" => ProxyMode::None,
        _ => return Err("network.proxyMode is invalid".to_owned()),
    };
    let proxy_url = optional_proxy_url(raw.get("proxyUrl"))?;
    if proxy_mode == ProxyMode::Explicit && proxy_url.is_none() {
        return Err("network.proxyUrl is required for explicit proxy mode".to_owned());
    }
    if proxy_mode != ProxyMode::Explicit && proxy_url.is_some() {
        return Err("network.proxyUrl is only valid for explicit proxy mode".to_owned());
    }
    let ca_bundle_path = optional_string(raw.get("caBundlePath"), "network.caBundlePath")?;
    if let Some(path) = ca_bundle_path.as_deref() {
        if !Path::new(path).is_absolute() {
            return Err("network.caBundlePath must be absolute".to_owned());
        }
    }
    let allow_public_registries = match raw.get("allowPublicRegistries") {
        None => true,
        Some(Value::Bool(allowed)) => *allowed,
        _ => return Err("network.allowPublicRegistries must be boolean".to_owned()),
    };
    Ok(ManagedNetworkPolicy {
        proxy_mode,
        proxy_url,
        ca_bundle_path: ca_bundle_path.map(PathBuf::from),
        // Python's contract has no trust-root field; the native TLS stack
        // materialises the managed roots from the CA bundle when it dials out.
        trust_roots_path: None,
        allow_public_registries,
    })
}

fn parse_update(value: Option<&Value>) -> PolicyResult<ManagedUpdatePolicy> {
    let Some(raw) = mapping_or_empty(value, "update")? else {
        return Ok(ManagedUpdatePolicy::default());
    };
    let owner = match raw.get("owner") {
        None => InstallOwner::User,
        Some(Value::String(text)) if text == "user" => InstallOwner::User,
        Some(Value::String(text)) if text == "mdm" => InstallOwner::Mdm,
        _ => return Err("update.owner is invalid".to_owned()),
    };
    let channel = match raw.get("channel") {
        None => "stable".to_owned(),
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => return Err("update.channel must be a non-empty string".to_owned()),
    };
    let allow_downgrade = match raw.get("allowDowngrade") {
        None => false,
        Some(Value::Bool(allowed)) => *allowed,
        _ => return Err("update.allowDowngrade must be boolean".to_owned()),
    };
    Ok(ManagedUpdatePolicy {
        owner,
        channel,
        minimum_version: optional_string(raw.get("minimumVersion"), "update.minimumVersion")?,
        maximum_version: optional_string(raw.get("maximumVersion"), "update.maximumVersion")?,
        allow_downgrade,
        index_url: optional_https_url(raw.get("indexUrl"), "update.indexUrl")?,
    })
}

/// `_parse_integrity_trust` (mdm/policy.py:108).
fn parse_integrity_trust(value: Option<&Value>) -> PolicyResult<ManagedIntegrityTrust> {
    let Some(raw) = mapping_or_empty(value, "integrityTrust")? else {
        return Ok(ManagedIntegrityTrust::default());
    };
    let unknown = unknown_keys(raw, &INTEGRITY_KEYS);
    if !unknown.is_empty() {
        return Err(format!(
            "unknown integrityTrust keys: {}",
            unknown.join(", ")
        ));
    }
    let mut release_public_keys = BTreeMap::new();
    if let Some(keys_raw) = mapping_or_empty(
        raw.get("releasePublicKeys"),
        "integrityTrust.releasePublicKeys",
    )? {
        for (key_id, encoded) in keys_raw {
            let Some(encoded) = encoded.as_str().filter(|_| !key_id.is_empty()) else {
                return Err(
                    "release public keys must map non-empty ids to base64 strings".to_owned(),
                );
            };
            let decoded = PYTHON_BASE64
                .decode(encoded)
                .map_err(|_| "release public key is not valid base64".to_owned())?;
            if decoded.len() != RELEASE_KEY_BYTES {
                return Err("release public keys must be 32-byte Ed25519 keys".to_owned());
            }
            release_public_keys.insert(key_id.clone(), decoded);
        }
    }
    let thumbprints = match raw.get("windowsSignerThumbprints") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut normalized = BTreeSet::new();
            for item in items {
                match item.as_str() {
                    Some(text) if !text.is_empty() => {
                        normalized.insert(text.replace(' ', "").to_uppercase());
                    }
                    _ => {
                        return Err(
                            "integrityTrust.windowsSignerThumbprints must be an array of strings"
                                .to_owned(),
                        );
                    }
                }
            }
            normalized.into_iter().collect()
        }
        _ => {
            return Err(
                "integrityTrust.windowsSignerThumbprints must be an array of strings".to_owned(),
            );
        }
    };
    if thumbprints.iter().any(|item| {
        item.len() != THUMBPRINT_CHARS || !item.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("Windows signer thumbprints must be SHA-1 certificate thumbprints".to_owned());
    }
    Ok(ManagedIntegrityTrust {
        release_public_keys,
        macos_team_id: optional_string(raw.get("macosTeamId"), "integrityTrust.macosTeamId")?,
        windows_signer_thumbprints: thumbprints,
    })
}

/// `_validate_policy_bundle_keyring` (mdm/policy.py:141). The native runtime
/// is the policy-bundle authority Python delegates to, so the keyring is
/// loaded here under the same strict contract.
fn validate_policy_bundle_keyring(value: &Value) -> PolicyResult<Value> {
    let keys = crate::policy_bundle_keys::load_keys(value, true)
        .map_err(|_| "policyBundleKeyring is invalid".to_owned())?;
    let workspace_id = value
        .get("workspaceId")
        .and_then(Value::as_str)
        .map(|text| python_strip(text).to_owned())
        .filter(|text| !text.is_empty())
        .ok_or_else(|| "policyBundleKeyring is invalid".to_owned())?;
    let mut payload = Map::new();
    payload.insert(
        "contractVersion".to_owned(),
        Value::String(crate::policy_bundle_keys::KEYRING_CONTRACT_VERSION.to_owned()),
    );
    payload.insert(
        "purpose".to_owned(),
        Value::String(crate::policy_bundle_keys::KEY_PURPOSE.to_owned()),
    );
    payload.insert("workspaceId".to_owned(), Value::String(workspace_id));
    payload.insert(
        "keys".to_owned(),
        crate::policy_bundle_keys::keys_to_value(&keys),
    );
    Ok(Value::Object(payload))
}

/// Just enough of `urllib.parse.urlsplit` for the URL rules the document's
/// contract states: the scheme, the authority and the path it keeps apart.
struct UrlSplit<'a> {
    scheme: &'a str,
    netloc: &'a str,
    path: &'a str,
}

impl<'a> UrlSplit<'a> {
    /// `None` is urlsplit's own `ValueError` (an IPv6 authority with no
    /// closing bracket).
    fn parse(url: &'a str) -> Option<UrlSplit<'a>> {
        let (scheme, rest) = match url.split_once(':') {
            Some((scheme, rest)) if is_scheme(scheme) => (scheme, rest),
            _ => ("", url),
        };
        let (netloc, remainder) = match rest.strip_prefix("//") {
            Some(authority) => {
                let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
                authority.split_at(end)
            }
            None => ("", rest),
        };
        // CPython raises ValueError unless a bracketed authority is an IPv6
        // address or an IPvFuture (`v` + hex + `.` + rest). Balanced brackets
        // alone would accept `https://[not-an-ip]/`, which urlsplit refuses.
        if !bracketed_authority_ok(netloc) {
            return None;
        }
        let path = remainder.split(['?', '#']).next().unwrap_or(remainder);
        Some(UrlSplit {
            scheme,
            netloc,
            path,
        })
    }

    /// The authority with any userinfo removed, as `_hostinfo` reads it.
    fn hostinfo(&self) -> &'a str {
        match self.netloc.rsplit_once('@') {
            Some((_, hostinfo)) => hostinfo,
            None => self.netloc,
        }
    }

    /// `SplitResult.hostname`: an empty host reads as `None`.
    fn hostname(&self) -> Option<String> {
        let hostinfo = self.hostinfo();
        let host = match hostinfo.split_once(']') {
            Some((bracketed, _)) => bracketed.trim_start_matches('['),
            None => hostinfo.split(':').next().unwrap_or(""),
        };
        (!host.is_empty()).then(|| host.to_lowercase())
    }

    /// `SplitResult.username is not None`: an `@` in the authority means the
    /// URL carries userinfo, even when it is empty.
    fn has_userinfo(&self) -> bool {
        self.netloc.contains('@')
    }

    /// `SplitResult.port`: `Err` is urllib's `ValueError`.
    fn port(&self) -> Result<Option<u32>, ()> {
        let hostinfo = self.hostinfo();
        let port = match hostinfo.split_once(']') {
            Some((_, after)) => after.strip_prefix(':').unwrap_or(""),
            None => match hostinfo.split_once(':') {
                Some((_, port)) => port,
                None => "",
            },
        };
        if port.is_empty() {
            return Ok(None);
        }
        // `port.isdigit() and port.isascii()`, then the 0-65535 range.
        if !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        match port.parse::<u32>() {
            Ok(value) if value <= 65_535 => Ok(Some(value)),
            _ => Err(()),
        }
    }
}

/// `urllib.parse.urlsplit`'s bracket check. `false` is its `ValueError`.
fn bracketed_authority_ok(netloc: &str) -> bool {
    let open = netloc.contains('[');
    let close = netloc.contains(']');
    if open != close {
        return false;
    }
    if !open {
        return true;
    }
    let hostinfo = match netloc.rsplit_once('@') {
        Some((_, hostinfo)) => hostinfo,
        None => netloc,
    };
    let Some((before, rest)) = hostinfo.split_once('[') else {
        return false;
    };
    if !before.is_empty() {
        return false;
    }
    let Some((hostname, after)) = rest.split_once(']') else {
        return false;
    };
    if hostname.contains('[') || after.contains('[') || after.contains(']') {
        return false;
    }
    if !after.is_empty() && !after.starts_with(':') {
        return false;
    }
    bracketed_host_ok(hostname)
}

/// `_check_bracketed_host`: IPvFuture, or an IPv6 address. An IPv4 literal in
/// brackets is a `ValueError`, and so is an empty zone id (`::1%`).
fn bracketed_host_ok(hostname: &str) -> bool {
    if let Some(rest) = hostname.strip_prefix('v') {
        let Some((hex, tail)) = rest.split_once('.') else {
            return false;
        };
        return !hex.is_empty()
            && !tail.is_empty()
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    let address = match hostname.split_once('%') {
        Some((address, zone)) if !zone.is_empty() => address,
        Some(_) => return false,
        None => hostname,
    };
    address.parse::<std::net::Ipv6Addr>().is_ok()
}

/// A scheme urlsplit recognises: a letter followed by letters, digits, `+`,
/// `-` or `.`.
fn is_scheme(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

#[cfg(test)]
#[path = "managed_policy_tests.rs"]
mod tests;
