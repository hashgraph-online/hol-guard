//! Compiler for `guard.browser-driver.v1` driver profiles.
//!
//! A driver profile maps a browser driver's tools to Guard's closed browser verbs. The compiler
//! enforces every cross-field rule the JSON schema cannot (PRD section 5.2):
//!
//! - `match` holds literal, bounded, lowercase lists. Reserved generic names (`browser`, `chrome`,
//!   `playwright`, shells, interpreters) are claimable only by first-party profiles.
//! - `publisher.verified` is honored only for publishers on the maintainer-owned verified list.
//! - Tool names are unique, and each tool has exactly one shape: a fixed verb, a discriminator with
//!   cases, or a DevTools protocol passthrough.
//! - The verb decides the intent through [`browser_verb_intent`]. A profile cannot name an intent.
//!
//! Duplicate JSON keys are rejected at every level, so a profile cannot carry two readings of one
//! field. A compiled profile is evidence only: it never clears a sensitive surface or grants.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{
    BrowserDriverTrustClassV1, BrowserIntentV1, BrowserProfileModeV1, BrowserVerbV1,
};
use serde::Deserialize;

#[path = "browser_driver_compile_error.rs"]
mod error;
#[path = "browser_driver_compile_raw.rs"]
mod raw;
#[path = "browser_driver_compile_text.rs"]
mod text;

pub use error::BrowserDriverCompileError;
use raw::{RawDriver, RawOperation, RawTool};

/// The only accepted `schemaVersion`.
pub const BROWSER_DRIVER_SCHEMA_VERSION: &str = "guard.browser-driver.v1";
/// Largest accepted profile, in bytes.
pub const BROWSER_DRIVER_MAX_BYTES: usize = 256 * 1024;

const MAX_MATCH_ENTRIES: usize = 32;
const MAX_TOOLS: usize = 256;
const MAX_CASES: usize = 64;
const MAX_POINTERS: usize = 8;
const MAX_FLAGS: usize = 8;
const MAX_REFERENCE_URLS: usize = 8;
const MAX_VOLATILE_FIELDS: usize = 32;
const MAX_DISPLAY_CHARS: usize = 80;
const MAX_REFERENCE_VERSION_CHARS: usize = 64;

/// Where a profile came from. Only profiles shipped with Guard are first-party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDriverOrigin {
    /// Shipped with Guard and reviewed by maintainers.
    FirstParty,
    /// From `contributions/browser-drivers/`, enabled by the user.
    Contributed,
}

type CompileResult<T> = Result<T, BrowserDriverCompileError>;

/// The intent a verb carries. This is the only place a verb becomes an intent.
pub fn browser_verb_intent(verb: BrowserVerbV1) -> BrowserIntentV1 {
    match verb {
        BrowserVerbV1::Navigate => BrowserIntentV1::Navigation,
        BrowserVerbV1::Read | BrowserVerbV1::Screenshot | BrowserVerbV1::Scroll => {
            BrowserIntentV1::Inspect
        }
        BrowserVerbV1::Click | BrowserVerbV1::Type | BrowserVerbV1::Key | BrowserVerbV1::Select => {
            BrowserIntentV1::Interact
        }
        BrowserVerbV1::Upload | BrowserVerbV1::Download => BrowserIntentV1::Transfer,
        BrowserVerbV1::Evaluate
        | BrowserVerbV1::CookieRead
        | BrowserVerbV1::CookieWrite
        | BrowserVerbV1::StorageRead
        | BrowserVerbV1::StorageWrite
        | BrowserVerbV1::Intercept
        | BrowserVerbV1::Permission
        | BrowserVerbV1::TabControl
        | BrowserVerbV1::Attach
        | BrowserVerbV1::Other => BrowserIntentV1::Privileged,
    }
}

/// Argument names a tool's fields are read from. Every list is literal and bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledBrowserPointersV1 {
    pub url: Vec<String>,
    pub element_name: Vec<String>,
    pub text: Vec<String>,
    pub script: Vec<String>,
    pub file: Vec<String>,
}

/// One classified operation: the verb, the intent the native table gave it, and its pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBrowserOperationV1 {
    pub verb: BrowserVerbV1,
    pub intent: BrowserIntentV1,
    pub pointers: CompiledBrowserPointersV1,
}

/// How a tool resolves to an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledBrowserToolV1 {
    Fixed(CompiledBrowserOperationV1),
    /// The `discriminator` argument picks a case. A value outside `cases` is unclassified.
    Discriminated {
        discriminator: String,
        cases: BTreeMap<String, CompiledBrowserOperationV1>,
    },
    /// Forwards raw DevTools protocol frames. Classified per frame, privileged until then.
    CdpPassthrough {
        method: Vec<String>,
        params: Vec<String>,
    },
}

/// Literal identities a profile claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledBrowserDriverMatchV1 {
    pub mcp_server_names: Vec<String>,
    pub packages: Vec<String>,
    pub tool_namespaces: Vec<String>,
    pub harness_tools: Vec<String>,
}

/// Launch flags that reveal the browser profile mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledBrowserProfileFlagsV1 {
    pub isolated: Vec<String>,
    pub dedicated: Vec<String>,
    pub shared: Vec<String>,
    pub remote_debugging: Vec<String>,
}

/// A profile that passed every compiler rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledBrowserDriverV1 {
    pub id: String,
    pub name: String,
    pub publisher_name: String,
    /// True only when the manifest said so and the publisher is on the verified list.
    pub publisher_verified: bool,
    pub trust_class: BrowserDriverTrustClassV1,
    pub matches: CompiledBrowserDriverMatchV1,
    pub profile_mode_default: BrowserProfileModeV1,
    pub profile_flags: CompiledBrowserProfileFlagsV1,
    pub tools: BTreeMap<String, CompiledBrowserToolV1>,
    pub volatile_fields: Vec<String>,
}

/// Compile one profile.
///
/// `verified_publishers` is the maintainer-owned list. A manifest that claims `verified: true` for
/// a publisher outside it is refused rather than silently downgraded, so the contributor sees why.
pub fn compile_browser_driver(
    bytes: &[u8],
    origin: BrowserDriverOrigin,
    verified_publishers: &[&str],
) -> CompileResult<CompiledBrowserDriverV1> {
    if bytes.is_empty() || bytes.len() > BROWSER_DRIVER_MAX_BYTES {
        return Err(BrowserDriverCompileError::SourceBytesInvalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let driver =
        RawDriver::deserialize(&mut decoder).map_err(|_| BrowserDriverCompileError::JsonInvalid)?;
    decoder
        .end()
        .map_err(|_| BrowserDriverCompileError::JsonInvalid)?;
    compile_raw(driver, origin, verified_publishers)
}

/// Compile a set of profiles. Ids are unique across the set, and no two contributed profiles may
/// claim one identity. A first-party profile may share an identity with a contributed one: the
/// matcher prefers first-party.
pub fn compile_browser_driver_set(
    sources: &[(&[u8], BrowserDriverOrigin)],
    verified_publishers: &[&str],
) -> CompileResult<Vec<CompiledBrowserDriverV1>> {
    let mut ids = BTreeSet::new();
    let mut contributed_claims = BTreeSet::new();
    let mut compiled = Vec::with_capacity(sources.len());
    for (bytes, origin) in sources {
        let driver = compile_browser_driver(bytes, *origin, verified_publishers)?;
        if !ids.insert(driver.id.clone()) {
            return Err(BrowserDriverCompileError::DriverIdDuplicate);
        }
        if driver.trust_class == BrowserDriverTrustClassV1::Contributed {
            for claim in identity_claims(&driver.matches) {
                if !contributed_claims.insert(claim) {
                    return Err(BrowserDriverCompileError::DriverIdentityConflict);
                }
            }
        }
        compiled.push(driver);
    }
    Ok(compiled)
}

fn identity_claims(matches: &CompiledBrowserDriverMatchV1) -> Vec<(u8, String)> {
    let lists = [
        &matches.mcp_server_names,
        &matches.packages,
        &matches.tool_namespaces,
        &matches.harness_tools,
    ];
    lists
        .iter()
        .enumerate()
        .flat_map(|(kind, list)| list.iter().map(move |entry| (kind as u8, entry.clone())))
        .collect()
}

fn compile_raw(
    driver: RawDriver,
    origin: BrowserDriverOrigin,
    verified_publishers: &[&str],
) -> CompileResult<CompiledBrowserDriverV1> {
    use BrowserDriverCompileError as E;
    if driver.schema_version != BROWSER_DRIVER_SCHEMA_VERSION {
        return Err(E::SchemaVersionUnsupported);
    }
    if !text::is_driver_id(&driver.id) {
        return Err(E::IdInvalid);
    }
    if !text::is_display_text(&driver.name, MAX_DISPLAY_CHARS) {
        return Err(E::NameInvalid);
    }
    let publisher = driver.publisher;
    if !text::is_display_text(&publisher.name, MAX_DISPLAY_CHARS)
        || publisher
            .url
            .as_deref()
            .is_some_and(|url| !text::is_https_url(url))
    {
        return Err(E::PublisherInvalid);
    }
    if publisher.verified && !verified_publishers.contains(&publisher.name.as_str()) {
        return Err(E::PublisherVerificationUnproven);
    }
    check_list(
        &driver.reference_urls,
        MAX_REFERENCE_URLS,
        text::is_https_url,
        E::ReferenceInvalid,
    )?;
    if driver
        .reference_version
        .as_deref()
        .is_some_and(|version| !text::is_display_text(version, MAX_REFERENCE_VERSION_CHARS))
    {
        return Err(E::ReferenceInvalid);
    }
    let matches = compile_match(driver.matches, origin)?;
    let (profile_mode_default, profile_flags) = compile_profile_mode(driver.profile_mode)?;
    let tools = compile_tools(driver.tools)?;
    check_list(
        &driver.volatile_fields,
        MAX_VOLATILE_FIELDS,
        text::is_pointer,
        E::VolatileFieldInvalid,
    )?;
    if driver
        .icon
        .as_deref()
        .is_some_and(|icon| !text::is_icon(icon))
    {
        return Err(E::IconInvalid);
    }
    Ok(CompiledBrowserDriverV1 {
        id: driver.id,
        name: driver.name,
        publisher_name: publisher.name,
        publisher_verified: publisher.verified,
        trust_class: match origin {
            BrowserDriverOrigin::FirstParty => BrowserDriverTrustClassV1::FirstParty,
            BrowserDriverOrigin::Contributed => BrowserDriverTrustClassV1::Contributed,
        },
        matches,
        profile_mode_default,
        profile_flags,
        tools,
        volatile_fields: driver.volatile_fields,
    })
}

fn check_list(
    entries: &[String],
    max: usize,
    valid: fn(&str) -> bool,
    error: BrowserDriverCompileError,
) -> CompileResult<()> {
    let unique: BTreeSet<&str> = entries.iter().map(String::as_str).collect();
    if entries.len() > max || unique.len() != entries.len() || !entries.iter().all(|e| valid(e)) {
        return Err(error);
    }
    Ok(())
}

fn compile_match(
    raw: raw::RawMatch,
    origin: BrowserDriverOrigin,
) -> CompileResult<CompiledBrowserDriverMatchV1> {
    use BrowserDriverCompileError as E;
    type TextRule = fn(&str) -> bool;
    let lists: [(&Vec<String>, TextRule, TextRule); 4] = [
        (&raw.mcp_server_names, text::is_slug, text::is_reserved),
        (&raw.packages, text::is_package, text::package_is_reserved),
        (
            &raw.tool_namespaces,
            text::is_tool_namespace,
            text::namespace_is_reserved,
        ),
        (&raw.harness_tools, text::is_slug, text::is_reserved),
    ];
    for (entries, valid, reserved) in lists {
        if entries.len() > MAX_MATCH_ENTRIES || !entries.iter().all(|entry| valid(entry)) {
            return Err(E::MatchEntryInvalid);
        }
        let unique: BTreeSet<&str> = entries.iter().map(String::as_str).collect();
        if unique.len() != entries.len() {
            return Err(E::MatchEntryDuplicate);
        }
        if origin != BrowserDriverOrigin::FirstParty && entries.iter().any(|entry| reserved(entry))
        {
            return Err(E::ReservedNameClaimed);
        }
    }
    if raw.mcp_server_names.is_empty()
        && raw.packages.is_empty()
        && raw.tool_namespaces.is_empty()
        && raw.harness_tools.is_empty()
    {
        return Err(E::MatchEmpty);
    }
    Ok(CompiledBrowserDriverMatchV1 {
        mcp_server_names: raw.mcp_server_names,
        packages: raw.packages,
        tool_namespaces: raw.tool_namespaces,
        harness_tools: raw.harness_tools,
    })
}

fn compile_profile_mode(
    raw: raw::RawProfileMode,
) -> CompileResult<(BrowserProfileModeV1, CompiledBrowserProfileFlagsV1)> {
    use BrowserDriverCompileError as E;
    let default = match raw.default.as_str() {
        "isolated" => BrowserProfileModeV1::Isolated,
        "dedicated" => BrowserProfileModeV1::Dedicated,
        "remote-debugging" => BrowserProfileModeV1::RemoteDebugging,
        "shared" => BrowserProfileModeV1::Shared,
        "unknown" => BrowserProfileModeV1::Unknown,
        _ => return Err(E::ProfileModeInvalid),
    };
    let flags = raw.flags.unwrap_or_default();
    for list in [
        &flags.isolated,
        &flags.dedicated,
        &flags.shared,
        &flags.remote_debugging,
    ] {
        check_list(list, MAX_FLAGS, text::is_flag, E::ProfileModeInvalid)?;
    }
    Ok((
        default,
        CompiledBrowserProfileFlagsV1 {
            isolated: flags.isolated,
            dedicated: flags.dedicated,
            shared: flags.shared,
            remote_debugging: flags.remote_debugging,
        },
    ))
}

fn compile_tools(raw: Vec<RawTool>) -> CompileResult<BTreeMap<String, CompiledBrowserToolV1>> {
    use BrowserDriverCompileError as E;
    if raw.is_empty() || raw.len() > MAX_TOOLS {
        return Err(E::ToolsInvalid);
    }
    let mut tools = BTreeMap::new();
    for tool in raw {
        if !text::is_slug(&tool.name) {
            return Err(E::ToolNameInvalid);
        }
        let name = tool.name.clone();
        let compiled = compile_tool(tool)?;
        if tools.insert(name, compiled).is_some() {
            return Err(E::ToolNameDuplicate);
        }
    }
    Ok(tools)
}

fn compile_tool(tool: RawTool) -> CompileResult<CompiledBrowserToolV1> {
    use BrowserDriverCompileError as E;
    match tool.into_parts() {
        (Some(operation), None, None, None) => {
            Ok(CompiledBrowserToolV1::Fixed(compile_operation(operation)?))
        }
        (None, Some(discriminator), Some(cases), None) => {
            if !text::is_pointer(&discriminator) {
                return Err(E::PointerInvalid);
            }
            if cases.is_empty() || cases.len() > MAX_CASES {
                return Err(E::CasesInvalid);
            }
            let mut compiled = BTreeMap::new();
            for (key, operation) in cases.into_entries() {
                if !text::is_case_key(&key) {
                    return Err(E::CasesInvalid);
                }
                compiled.insert(key, compile_operation(operation)?);
            }
            Ok(CompiledBrowserToolV1::Discriminated {
                discriminator,
                cases: compiled,
            })
        }
        (None, None, None, Some(passthrough)) => Ok(CompiledBrowserToolV1::CdpPassthrough {
            method: pointers(Some(passthrough.method))?,
            params: pointers(passthrough.params)?,
        }),
        _ => Err(E::ToolShapeInvalid),
    }
}

fn compile_operation(raw: RawOperation) -> CompileResult<CompiledBrowserOperationV1> {
    let verb = raw
        .verb
        .as_deref()
        .and_then(text::verb_from_manifest)
        .ok_or(BrowserDriverCompileError::VerbInvalid)?;
    Ok(CompiledBrowserOperationV1 {
        verb,
        intent: browser_verb_intent(verb),
        pointers: CompiledBrowserPointersV1 {
            url: pointers(raw.url)?,
            element_name: pointers(raw.element.map(|element| element.name))?,
            text: pointers(raw.text)?,
            script: pointers(raw.script)?,
            file: pointers(raw.file)?,
        },
    })
}

/// An absent pointer list is empty; a present one holds 1 to 8 unique argument names.
fn pointers(raw: Option<Vec<String>>) -> CompileResult<Vec<String>> {
    let Some(list) = raw else {
        return Ok(Vec::new());
    };
    if list.is_empty() {
        return Err(BrowserDriverCompileError::PointerInvalid);
    }
    check_list(
        &list,
        MAX_POINTERS,
        text::is_pointer,
        BrowserDriverCompileError::PointerInvalid,
    )?;
    Ok(list)
}

#[cfg(test)]
#[path = "browser_driver_compile_tests.rs"]
mod tests;
