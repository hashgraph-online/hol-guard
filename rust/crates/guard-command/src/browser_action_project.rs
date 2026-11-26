//! Project a resolved browser tool call into [`BrowserActionV2`].
//!
//! The verb comes from the driver profile, and the intent comes from [`browser_verb_intent`].
//! Sensitive-surface flags are the union of what the verb implies, what the arguments show (a
//! `javascript:` URL, a password-named element, a script argument) and the flags the native screens
//! found, which the caller passes in. A flag can only raise the intent: a profile that labels a
//! script-running tool `Read` still projects as privileged. A profile never removes a flag.
//!
//! A discriminator value the profile does not list, or a tool the profile does not list, is
//! unclassified: the call keeps Guard's normal MCP review.

use guard_contracts::{
    BrowserActionV2, BrowserCdpCommandV1, BrowserDriverKindV1, BrowserDriverV2, BrowserElementV1,
    BrowserInputKindV1, BrowserInputV1, BrowserIntentV1, BrowserProfileModeV1,
    BrowserSensitiveSurfaceV1, BrowserSessionV2, BrowserVerbV1, BROWSER_ACTION_OPERATION_MAX_BYTES,
    BROWSER_ACTION_V2_VERSION,
};
use serde_json::{Map, Value};

use crate::browser_action_target::{
    browser_target, digest, element_preview, empty_target, input_preview_class,
    name_looks_like_password, name_looks_like_payment, url_runs_script,
};
use crate::browser_driver_compile::{
    browser_verb_intent, CompiledBrowserOperationV1, CompiledBrowserToolV1,
};
use crate::browser_driver_match::{BrowserDriverMatch, BrowserDriverMatchKind};
use crate::browser_mcp_intent::browser_sensitive_surfaces;

/// Session facts the projection cannot read from the call itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserProjectionContext<'a> {
    pub harness: &'a str,
    /// SHA-256 of the harness session reference, never the reference.
    pub session_ref_digest: Option<&'a str>,
    /// The profile mode Guard observed at launch. `None` uses the profile's default.
    pub profile_mode: Option<BrowserProfileModeV1>,
    /// Guard's own origins, `scheme://host:port`.
    pub guard_origins: &'a [&'a str],
    /// Flags the native sensitive-surface screens found for this call.
    pub screened_surfaces: &'a [BrowserSensitiveSurfaceV1],
}

/// Why a matched call has no action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserUnclassifiedReason {
    /// The profile does not list the tool.
    ToolNotListed,
    /// The discriminator argument is missing, not a string, or not a listed case.
    CaseNotListed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserProjection {
    Classified(Box<BrowserActionV2>),
    Unclassified {
        driver_id: String,
        tool_name: String,
        reason: BrowserUnclassifiedReason,
    },
}

/// Project one matched call and union the native sensitive-surface screens into it. `metadata`
/// carries the tool description and schema the screens read. This is the entry point for runtime
/// callers: the screens stay authoritative after profile projection.
pub fn project_screened_browser_action(
    matched: &BrowserDriverMatch<'_, '_>,
    arguments: &Map<String, Value>,
    metadata: &Map<String, Value>,
    context: &BrowserProjectionContext<'_>,
) -> BrowserProjection {
    let mut screened = browser_sensitive_surfaces(matched.tool_name, arguments, metadata);
    for surface in context.screened_surfaces {
        if !screened.contains(surface) {
            screened.push(*surface);
        }
    }
    let context = BrowserProjectionContext {
        screened_surfaces: &screened,
        ..*context
    };
    project_browser_action(matched, arguments, &context)
}

/// Project one matched call with its arguments.
pub fn project_browser_action(
    matched: &BrowserDriverMatch<'_, '_>,
    arguments: &Map<String, Value>,
    context: &BrowserProjectionContext<'_>,
) -> BrowserProjection {
    let unclassified = |reason| BrowserProjection::Unclassified {
        driver_id: matched.driver.id.clone(),
        tool_name: matched.tool_name.to_owned(),
        reason,
    };
    let Some(tool) = matched.tool else {
        return unclassified(BrowserUnclassifiedReason::ToolNotListed);
    };
    let (operation, compiled, cdp) = match tool {
        CompiledBrowserToolV1::Fixed(operation) => {
            (matched.tool_name.to_owned(), Some(operation), None)
        }
        CompiledBrowserToolV1::Discriminated {
            discriminator,
            cases,
        } => {
            let case = arguments.get(discriminator).and_then(Value::as_str);
            let Some((key, operation)) = case.and_then(|case| cases.get_key_value(case)) else {
                return unclassified(BrowserUnclassifiedReason::CaseNotListed);
            };
            (
                case_operation(matched.tool_name, key),
                Some(operation),
                None,
            )
        }
        CompiledBrowserToolV1::CdpPassthrough { method, .. } => (
            matched.tool_name.to_owned(),
            None,
            Some(cdp_command(first_string(arguments, method))),
        ),
    };
    let (verb, intent) = match compiled {
        Some(operation) => (operation.verb, operation.intent),
        None => (
            BrowserVerbV1::Other,
            browser_verb_intent(BrowserVerbV1::Other),
        ),
    };
    let mut surfaces = Vec::new();
    let mut flag = |surface| {
        if !surfaces.contains(&surface) {
            surfaces.push(surface);
        }
    };
    verb_surfaces(verb).iter().copied().for_each(&mut flag);
    if cdp.is_some() {
        flag(BrowserSensitiveSurfaceV1::Cdp);
    }

    let url = compiled.and_then(|operation| first_string(arguments, &operation.pointers.url));
    let target = url.map_or_else(empty_target, |url| {
        browser_target(url, context.guard_origins)
    });
    if url.is_some_and(url_runs_script) {
        flag(BrowserSensitiveSurfaceV1::ScriptEval);
    }
    let element = compiled.and_then(|operation| element(operation, verb, arguments));
    if element.as_ref().is_some_and(|element| element.is_password) {
        flag(BrowserSensitiveSurfaceV1::PasswordField);
    }
    let input = compiled.and_then(|operation| input(operation, verb, arguments));
    if input
        .as_ref()
        .is_some_and(|input| input.kind == BrowserInputKindV1::Script)
    {
        flag(BrowserSensitiveSurfaceV1::ScriptEval);
    }
    context
        .screened_surfaces
        .iter()
        .copied()
        .for_each(&mut flag);

    let intent = if surfaces.is_empty() {
        intent
    } else {
        stronger_intent(intent, &surfaces)
    };
    BrowserProjection::Classified(Box::new(BrowserActionV2 {
        version: BROWSER_ACTION_V2_VERSION,
        driver: BrowserDriverV2 {
            id: matched.driver.id.clone(),
            kind: match matched.kind {
                BrowserDriverMatchKind::HarnessTool => BrowserDriverKindV1::HarnessTool,
                _ => BrowserDriverKindV1::Mcp,
            },
            identity_hash: None,
            trust_class: matched.driver.trust_class,
        },
        session: BrowserSessionV2 {
            harness: context.harness.to_owned(),
            session_ref_digest: context.session_ref_digest.map(str::to_owned),
            profile_mode: context
                .profile_mode
                .unwrap_or(matched.driver.profile_mode_default),
        },
        intent,
        operation,
        verb,
        target,
        element,
        input,
        sensitive_surface_flags: surfaces,
        cdp,
        volatile_fields_dropped: matched
            .driver
            .volatile_fields
            .iter()
            .filter(|field| arguments.contains_key(field.as_str()))
            .cloned()
            .collect(),
    }))
}

/// `tool.case` when it fits the operation bound, else the case alone.
fn case_operation(tool: &str, case: &str) -> String {
    let joined = format!("{tool}.{case}");
    if joined.len() <= BROWSER_ACTION_OPERATION_MAX_BYTES {
        joined
    } else {
        case.to_owned()
    }
}

/// A flagged surface never leaves the action in a weaker intent than the flag implies.
pub(crate) fn stronger_intent(
    intent: BrowserIntentV1,
    surfaces: &[BrowserSensitiveSurfaceV1],
) -> BrowserIntentV1 {
    use BrowserSensitiveSurfaceV1 as S;
    let privileged = surfaces.iter().any(|surface| {
        matches!(
            surface,
            S::Cookies | S::Storage | S::AuthHeaders | S::Cdp | S::ScriptEval | S::NetworkIntercept
        )
    });
    if privileged {
        return BrowserIntentV1::Privileged;
    }
    let transfer = surfaces
        .iter()
        .any(|surface| matches!(surface, S::Upload | S::Download));
    match intent {
        BrowserIntentV1::Privileged => BrowserIntentV1::Privileged,
        _ if transfer => BrowserIntentV1::Transfer,
        other => other,
    }
}

pub(crate) fn verb_surfaces(verb: BrowserVerbV1) -> &'static [BrowserSensitiveSurfaceV1] {
    use BrowserSensitiveSurfaceV1 as S;
    match verb {
        BrowserVerbV1::Evaluate => &[S::ScriptEval],
        BrowserVerbV1::Upload => &[S::Upload],
        BrowserVerbV1::Download => &[S::Download],
        BrowserVerbV1::CookieRead | BrowserVerbV1::CookieWrite => &[S::Cookies],
        BrowserVerbV1::StorageRead | BrowserVerbV1::StorageWrite => &[S::Storage],
        BrowserVerbV1::Intercept => &[S::NetworkIntercept],
        BrowserVerbV1::Attach => &[S::Cdp],
        _ => &[],
    }
}

fn first_string<'a>(arguments: &'a Map<String, Value>, pointers: &[String]) -> Option<&'a str> {
    pointers
        .iter()
        .find_map(|pointer| arguments.get(pointer).and_then(Value::as_str))
}

fn cdp_command(method: Option<&str>) -> BrowserCdpCommandV1 {
    let method = method.unwrap_or("");
    let (domain, name) = method.split_once('.').unwrap_or(("", method));
    let bounded = |text: &str| text.chars().take(64).collect::<String>();
    BrowserCdpCommandV1 {
        domain: bounded(domain),
        method: bounded(name),
        classified: false,
    }
}

fn element(
    operation: &CompiledBrowserOperationV1,
    verb: BrowserVerbV1,
    arguments: &Map<String, Value>,
) -> Option<BrowserElementV1> {
    let pointers = &operation.pointers.element_name;
    let name = first_string(arguments, pointers)?;
    // A drag names a source and a destination: either one can be the sensitive field, so every
    // named element is screened while the first one is shown.
    let names = || {
        pointers
            .iter()
            .filter_map(|pointer| arguments.get(pointer).and_then(Value::as_str))
    };
    Some(BrowserElementV1 {
        role: None,
        name_digest: Some(digest(name)),
        name_preview: Some(element_preview(name)),
        is_password: names().any(name_looks_like_password),
        is_payment: names().any(name_looks_like_payment),
        is_file_input: verb == BrowserVerbV1::Upload,
    })
}

fn input(
    operation: &CompiledBrowserOperationV1,
    verb: BrowserVerbV1,
    arguments: &Map<String, Value>,
) -> Option<BrowserInputV1> {
    let pointers = &operation.pointers;
    let (kind, text) = if let Some(script) = first_string(arguments, &pointers.script) {
        (BrowserInputKindV1::Script, script)
    } else if let Some(file) = first_string(arguments, &pointers.file) {
        (BrowserInputKindV1::File, file)
    } else if let Some(text) = first_string(arguments, &pointers.text) {
        let kind = if verb == BrowserVerbV1::Key {
            BrowserInputKindV1::Key
        } else {
            BrowserInputKindV1::Text
        };
        (kind, text)
    } else {
        return None;
    };
    Some(BrowserInputV1 {
        kind,
        length: text.chars().count() as u64,
        digest: Some(digest(text)),
        preview_class: input_preview_class(text),
    })
}

#[cfg(test)]
#[path = "browser_action_project_tests.rs"]
mod tests;
