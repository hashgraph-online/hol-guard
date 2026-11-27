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
    provider_id_is_valid, BrowserActionV2, BrowserCardChoiceV1, BrowserCardDetailV1,
    BrowserCardProviderFindingV1, BrowserCardRequestV1, BrowserCardSiteV1, BrowserCardV1,
    BrowserInputPreviewClassV1, BrowserVerbV1, BROWSER_CARD_MAX_REASON_LABELS,
};

const AGENT_MAX_CHARS: usize = 48;
const FALLBACK_AGENT: &str = "The agent";

/// Control characters, and the Unicode format characters that reorder or hide
/// text (bidi overrides and isolates, zero-width marks, the byte-order mark).
fn is_unsafe_display_char(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn agent_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|character| {
            if is_unsafe_display_char(character) {
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

/// The origin the card shows: any userinfo (`user:password@`) is dropped, and an
/// origin with whitespace or unsafe display characters is not shown at all.
fn display_origin(origin: &str) -> Option<String> {
    // A browser reads `\` as a path separator, so `https://evil.test\@shop.test` opens
    // evil.test; stripping userinfo past it would name the wrong site. Show none instead.
    if origin.chars().any(|character| {
        character == '\\' || character.is_whitespace() || is_unsafe_display_char(character)
    }) {
        return None;
    }
    let (scheme, rest) = match origin.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, origin),
    };
    let authority_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() {
        return None;
    }
    Some(match scheme {
        Some(scheme) => format!("{scheme}://{host}{tail}"),
        None => format!("{host}{tail}"),
    })
}

/// The host and port of a display origin, as the headline names the site.
fn site_label(origin: &str) -> Option<String> {
    let host = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let host = host.trim_end_matches('/');
    (!host.is_empty()).then(|| host.to_owned())
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

/// Provider rows, strongest fresh verdict first. A stale or missing answer follows every fresh one.
/// A row with a malformed provider id is dropped and extra reason labels are cut.
fn ordered_findings(
    findings: &[BrowserCardProviderFindingV1],
) -> Vec<BrowserCardProviderFindingV1> {
    let mut rows: Vec<BrowserCardProviderFindingV1> = findings
        .iter()
        .filter(|row| provider_id_is_valid(&row.provider_id))
        .cloned()
        .map(|mut row| {
            row.reason_labels.truncate(BROWSER_CARD_MAX_REASON_LABELS);
            row
        })
        .collect();
    rows.sort_by_key(|row| {
        (
            std::cmp::Reverse(row.state.is_fresh()),
            std::cmp::Reverse(row.verdict.strength()),
        )
    });
    rows
}

/// Builds the approval card for one projected action.
pub fn browser_card(request: &BrowserCardRequestV1) -> Result<BrowserCardV1, &'static str> {
    let action = &request.action;
    action.validate_shape().map_err(|error| error.code())?;
    let agent = agent_name(&request.agent);
    let origin = action.target.origin.as_deref().and_then(display_origin);
    let site = origin.as_deref().and_then(site_label);
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
            origin,
            first_visit_in_task: request.first_visit_in_task,
            left_granted_site: request.left_granted_site,
        },
        profile_line: action.session.profile_mode.into(),
        detail: detail(action),
        risk_chips,
        provider_findings: ordered_findings(&request.provider_findings),
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
