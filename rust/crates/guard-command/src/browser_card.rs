//! Native approval card projection (BP-T045, PRD 5.8 items 1 to 5 and 7).
//!
//! Every approval surface renders this card instead of inferring meaning from
//! tool names. It is built only from a validated `BrowserActionV2`, so it never
//! carries typed text: an input shows its kind, its length and whether it is
//! masked. The input preview class comes from the native secret scanner that
//! filled the action.
//!
//! The card always offers Allow once, Always allow and Deny (approval
//! invariant). Site and session grants join the choices once their grant
//! targets exist; a choice that cannot run is never shown.

use guard_contracts::{
    BrowserActionV2, BrowserCardChoiceV1, BrowserCardDetailV1, BrowserCardRequestV1,
    BrowserCardSiteV1, BrowserCardV1, BrowserInputPreviewClassV1, BrowserVerbV1,
};

const AGENT_MAX_CHARS: usize = 48;
const FALLBACK_AGENT: &str = "The agent";

fn agent_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let words = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = words.chars().take(AGENT_MAX_CHARS).collect();
    if name.is_empty() {
        FALLBACK_AGENT.to_owned()
    } else {
        name
    }
}

/// The host and port of an origin, as the headline names the site.
fn site_label(origin: &str) -> Option<String> {
    let host = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let host = host.trim_end_matches('/');
    (!host.is_empty() && !host.contains(char::is_whitespace)).then(|| host.to_owned())
}

/// The headline verb phrase. Navigation names the site as its object; every
/// other verb takes "on <site>".
fn verb_phrase(verb: BrowserVerbV1) -> &'static str {
    use BrowserVerbV1::*;
    match verb {
        Navigate => "open",
        Read => "read the page",
        Click => "click on the page",
        Type => "type into a form",
        Key => "press keys",
        Select => "choose an option",
        Scroll => "scroll the page",
        Screenshot => "take a screenshot",
        Upload => "upload a file",
        Download => "download a file",
        Evaluate => "run a script",
        CookieRead => "read cookies",
        CookieWrite => "change cookies",
        StorageRead => "read site storage",
        StorageWrite => "change site storage",
        Intercept => "intercept network traffic",
        Permission => "change site permissions",
        TabControl => "manage browser tabs",
        Attach => "attach to a browser",
        Other => "control the browser",
    }
}

fn headline(agent: &str, verb: BrowserVerbV1, site: Option<&str>) -> String {
    match (verb, site) {
        (BrowserVerbV1::Navigate, Some(site)) => format!("{agent} wants to open {site}"),
        (BrowserVerbV1::Navigate, None) => format!("{agent} wants to open a page"),
        (_, Some(site)) => format!("{agent} wants to {} on {site}", verb_phrase(verb)),
        (_, None) => format!("{agent} wants to {} in the browser", verb_phrase(verb)),
    }
}

fn detail(action: &BrowserActionV2) -> BrowserCardDetailV1 {
    let element = action.element.as_ref();
    let sensitive_element =
        element.is_some_and(|element| element.is_password || element.is_payment);
    let input = action.input.as_ref();
    BrowserCardDetailV1 {
        element_preview: element.and_then(|element| element.name_preview.clone()),
        input_kind: input.map(|input| input.kind),
        input_length: input.map(|input| input.length),
        input_masked: input.is_some_and(|input| {
            sensitive_element
                || matches!(
                    input.preview_class,
                    BrowserInputPreviewClassV1::LooksLikeSecret
                        | BrowserInputPreviewClassV1::LooksLikePayment
                )
        }),
    }
}

/// Builds the approval card for one projected action.
pub fn browser_card(request: &BrowserCardRequestV1) -> Result<BrowserCardV1, &'static str> {
    let action = &request.action;
    action.validate_shape().map_err(|error| error.code())?;
    let agent = agent_name(&request.agent);
    let site = action.target.origin.as_deref().and_then(site_label);
    let mut risk_chips = Vec::with_capacity(action.sensitive_surface_flags.len());
    for flag in &action.sensitive_surface_flags {
        if !risk_chips.contains(flag) {
            risk_chips.push(*flag);
        }
    }
    let card = BrowserCardV1 {
        headline: headline(&agent, action.verb, site.as_deref()),
        verb: action.verb,
        site: BrowserCardSiteV1 {
            origin: action.target.origin.clone(),
            first_visit_in_task: request.first_visit_in_task,
            left_granted_site: request.left_granted_site,
        },
        profile_line: action.session.profile_mode.into(),
        detail: detail(action),
        risk_chips,
        provider_findings: Vec::new(),
        choices: vec![
            BrowserCardChoiceV1::AllowOnce,
            BrowserCardChoiceV1::AlwaysAllow,
            BrowserCardChoiceV1::Deny,
        ],
        steps: Vec::new(),
    };
    debug_assert!(card.keeps_approval_invariant());
    Ok(card)
}

#[cfg(test)]
#[path = "browser_card_tests.rs"]
mod tests;
