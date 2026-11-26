//! The [`BrowserActionV2`] an Oh My Pi `eval` program stands for.
//!
//! One program can open a page, click, type and run in-page code. The action is its strongest
//! step: the step with the highest intent, the first one on a tie. Its target is the URL that step
//! names, or the page its tab last opened. Every step's verb surfaces are flagged, so a program
//! that runs in-page code is never weaker than `browser.privileged`, whichever step is shown.
//!
//! Admission does not read this: the parser in `pretool/generic_omp_eval_browser.rs` decides which
//! programs settle. A program the tokenizer cannot read (a comment, a regular expression, a
//! template interpolation) that still names the browser facade projects as an unmodelled
//! privileged action, so a reviewed program has an action too.

use std::collections::HashMap;

use guard_contracts::{
    BrowserActionV2, BrowserDriverKindV1, BrowserDriverTrustClassV1, BrowserDriverV2,
    BrowserElementV1, BrowserInputKindV1, BrowserInputV1, BrowserIntentV1, BrowserProfileModeV1,
    BrowserSensitiveSurfaceV1, BrowserSessionV2, BrowserVerbV1, BROWSER_ACTION_V2_VERSION,
};

use crate::browser_action_project::{stronger_intent, verb_surfaces};
use crate::browser_action_target::{
    browser_target, digest, element_preview, empty_target, input_preview_class,
    name_looks_like_password, name_looks_like_payment, url_runs_script,
};
use crate::browser_driver_compile::browser_verb_intent;
use crate::pretool::generic::{
    tokenize_browser_eval as tokenize, BrowserEvalToken as Token,
    BROWSER_EVAL_MAX_CODE_BYTES as MAX_CODE_BYTES, BROWSER_EVAL_OPEN_KEYS as OPEN_KEYS,
};

/// The driver id an `eval` browser action carries.
pub const OMP_EVAL_BROWSER_DRIVER_ID: &str = "omp.eval-browser";

/// One browser call in the program.
struct Step {
    method: String,
    verb: BrowserVerbV1,
    url: Option<String>,
    element: Option<String>,
}

/// The action an `eval` program's browser calls stand for, or `None` when it makes none.
pub fn omp_eval_browser_action(
    code: &str,
    harness: &str,
    guard_origins: &[&str],
) -> Option<BrowserActionV2> {
    let tokens = if code.len() <= MAX_CODE_BYTES {
        tokenize(code)
    } else {
        None
    };
    let (steps, profile_mode) = match tokens {
        Some(tokens) => scan(&tokens)?,
        None if code.contains("browser.") || code.contains("browser[") => (
            vec![Step {
                method: "eval".to_owned(),
                verb: BrowserVerbV1::Other,
                url: None,
                element: None,
            }],
            BrowserProfileModeV1::Unknown,
        ),
        None => return None,
    };
    let mut surfaces = Vec::new();
    let mut flag = |surface| {
        if !surfaces.contains(&surface) {
            surfaces.push(surface);
        }
    };
    for step in &steps {
        verb_surfaces(step.verb).iter().copied().for_each(&mut flag);
        if step.url.as_deref().is_some_and(url_runs_script) {
            flag(BrowserSensitiveSurfaceV1::ScriptEval);
        }
        if step
            .element
            .as_deref()
            .is_some_and(name_looks_like_password)
        {
            flag(BrowserSensitiveSurfaceV1::PasswordField);
        }
    }
    let mut shown = steps.first()?;
    for step in &steps[1..] {
        if rank(browser_verb_intent(step.verb)) > rank(browser_verb_intent(shown.verb)) {
            shown = step;
        }
    }
    let intent = stronger_intent(browser_verb_intent(shown.verb), &surfaces);
    let script = matches!(shown.verb, BrowserVerbV1::Evaluate | BrowserVerbV1::Other);
    Some(BrowserActionV2 {
        version: BROWSER_ACTION_V2_VERSION,
        driver: BrowserDriverV2 {
            id: OMP_EVAL_BROWSER_DRIVER_ID.to_owned(),
            kind: BrowserDriverKindV1::HarnessTool,
            identity_hash: None,
            trust_class: BrowserDriverTrustClassV1::FirstParty,
        },
        session: BrowserSessionV2 {
            harness: harness.to_owned(),
            session_ref_digest: None,
            profile_mode,
        },
        intent,
        operation: format!("eval.{}", shown.method).chars().take(64).collect(),
        verb: shown.verb,
        target: shown
            .url
            .as_deref()
            .map_or_else(empty_target, |url| browser_target(url, guard_origins)),
        element: shown.element.as_deref().map(|name| BrowserElementV1 {
            role: None,
            name_digest: Some(digest(name)),
            name_preview: Some(element_preview(name)),
            is_password: name_looks_like_password(name),
            is_payment: name_looks_like_payment(name),
            is_file_input: shown.verb == BrowserVerbV1::Upload,
        }),
        input: script.then(|| BrowserInputV1 {
            kind: BrowserInputKindV1::Script,
            length: code.len() as u64,
            digest: Some(digest(code)),
            preview_class: input_preview_class(code),
        }),
        sensitive_surface_flags: surfaces,
        cdp: None,
        volatile_fields_dropped: Vec::new(),
    })
}

/// Higher is stronger. Reading a page is weaker than leaving it.
fn rank(intent: BrowserIntentV1) -> u8 {
    match intent {
        BrowserIntentV1::Inspect => 0,
        BrowserIntentV1::Navigation => 1,
        BrowserIntentV1::Interact => 2,
        BrowserIntentV1::Transfer => 3,
        BrowserIntentV1::Privileged => 4,
    }
}

/// Keep the strictest profile mode seen.
fn stricter(mode: BrowserProfileModeV1, profile: &mut Option<BrowserProfileModeV1>) {
    if profile.is_none_or(|seen| profile_rank(mode) > profile_rank(seen)) {
        *profile = Some(mode);
    }
}

/// Higher is less known about whose browser it is.
fn profile_rank(mode: BrowserProfileModeV1) -> u8 {
    match mode {
        BrowserProfileModeV1::Isolated => 0,
        BrowserProfileModeV1::Dedicated => 1,
        BrowserProfileModeV1::Unknown => 2,
        BrowserProfileModeV1::RemoteDebugging => 3,
        BrowserProfileModeV1::Shared => 4,
    }
}

fn tab_verb(method: &str) -> BrowserVerbV1 {
    use BrowserVerbV1::*;
    match method {
        "goto" | "reload" | "back" | "forward" => Navigate,
        "title" | "url" | "observe" | "errors" | "console" | "text" | "attr" | "isVisible"
        | "isEnabled" | "isChecked" | "count" | "waitFor" | "waitForSelector" | "waitForText"
        | "content" | "innerText" | "textContent" | "getAttribute" | "waitForTimeout"
        | "waitForLoadState" | "waitForURL" => Read,
        "screenshot" => Screenshot,
        "click" | "dblclick" | "hover" | "check" | "uncheck" | "tap" | "dragAndDrop" => Click,
        "fill" | "type" => Type,
        "press" => Key,
        "select" | "selectOption" => Select,
        "scroll" | "mouseWheel" => Scroll,
        "evaluate" | "$eval" | "$$eval" | "evaluateHandle" | "addScriptTag" | "addInitScript" => {
            Evaluate
        }
        "setInputFiles" | "upload" => Upload,
        "download" => Download,
        "cookies" => CookieRead,
        "setCookie" | "addCookies" | "clearCookies" => CookieWrite,
        "route" | "unroute" | "setExtraHTTPHeaders" => Intercept,
        "close" | "bringToFront" => TabControl,
        _ => Other,
    }
}

/// The browser steps and the strictest profile the program's opens name.
fn scan(tokens: &[Token]) -> Option<(Vec<Step>, BrowserProfileModeV1)> {
    let mut steps = Vec::new();
    let mut pages: HashMap<String, Option<String>> = HashMap::new();
    let mut profile: Option<BrowserProfileModeV1> = None;
    let ident = |index: usize| match tokens.get(index) {
        Some(Token::Ident(word)) => Some(word.as_str()),
        _ => None,
    };
    let punct = |index: usize, ch: char| tokens.get(index) == Some(&Token::Punct(ch));
    let string = |index: usize| match tokens.get(index) {
        Some(Token::Str(text)) => Some(text.clone()),
        _ => None,
    };
    // `NAME = [await] browser.METHOD(`: the bound name, if any, for each facade call.
    let bound = |index: usize| {
        let at = if index > 0 && ident(index - 1) == Some("await") {
            index - 1
        } else {
            index
        };
        (at >= 2 && punct(at - 1, '='))
            .then(|| ident(at - 2))
            .flatten()
            .map(str::to_owned)
    };
    for index in 0..tokens.len() {
        let Some(receiver) = ident(index) else {
            continue;
        };
        if (index > 0 && punct(index - 1, '.')) || !punct(index + 1, '.') {
            continue;
        }
        let Some(mut method) = ident(index + 2) else {
            continue;
        };
        let mut arguments = index + 4;
        // `page.keyboard.press(...)`, `page.mouse.click(...)`: the device's method is the step.
        if receiver != "browser" && punct(index + 3, '.') && punct(index + 5, '(') {
            let Some(device_method) = ident(index + 4) else {
                continue;
            };
            method = device_method;
            arguments = index + 6;
        } else if !punct(index + 3, '(') {
            continue;
        }
        if receiver == "browser" {
            match method {
                "open" => {
                    let (url, mode) = open_options(tokens, index + 4);
                    stricter(mode, &mut profile);
                    if let Some(name) = bound(index) {
                        pages.insert(name, url.clone());
                    }
                    steps.push(Step {
                        method: "browser.open".to_owned(),
                        verb: if mode == BrowserProfileModeV1::RemoteDebugging {
                            BrowserVerbV1::Attach
                        } else {
                            BrowserVerbV1::Navigate
                        },
                        url,
                        element: None,
                    });
                }
                "tab" => {
                    stricter(BrowserProfileModeV1::Isolated, &mut profile);
                    if let Some(name) = bound(index) {
                        pages.insert(name, None);
                    }
                }
                _ => steps.push(Step {
                    method: format!("browser.{method}"),
                    verb: BrowserVerbV1::Other,
                    url: None,
                    element: None,
                }),
            }
            continue;
        }
        if (receiver != "page" && !pages.contains_key(receiver)) || method == "run" {
            // `TAB.run(callback)` is not a step itself: the `page` calls inside it are.
            continue;
        }
        let verb = tab_verb(method);
        let first = string(arguments);
        let url = if verb == BrowserVerbV1::Navigate && method == "goto" {
            if let (Some(url), Some(page)) = (&first, pages.get_mut(receiver)) {
                *page = Some(url.clone());
            }
            first.clone()
        } else {
            pages.get(receiver).cloned().flatten()
        };
        let element = matches!(
            verb,
            BrowserVerbV1::Click
                | BrowserVerbV1::Type
                | BrowserVerbV1::Select
                | BrowserVerbV1::Upload
        )
        .then_some(first)
        .flatten();
        steps.push(Step {
            method: method.to_owned(),
            verb,
            url,
            element,
        });
    }
    if steps.is_empty() {
        return None;
    }
    Some((steps, profile.unwrap_or(BrowserProfileModeV1::Unknown)))
}

/// The `url` of a `browser.open({...})` options object and the profile it names. An option the
/// isolated facade does not list, or an `app` other than OMP's own browser, may attach another
/// browser, so it reads as a remote-debugging profile.
fn open_options(tokens: &[Token], start: usize) -> (Option<String>, BrowserProfileModeV1) {
    let mut url = None;
    let mut mode = BrowserProfileModeV1::Isolated;
    if tokens.get(start) != Some(&Token::Punct('{')) {
        return (url, mode);
    }
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            Token::Ident(key) | Token::Str(key)
                if depth == 1 && tokens.get(index + 1) == Some(&Token::Punct(':')) =>
            {
                let value = match tokens.get(index + 2) {
                    Some(Token::Str(value)) => Some(value.clone()),
                    _ => None,
                };
                match key.as_str() {
                    "url" => url = value,
                    "app" if value.as_deref() == Some("own") => {}
                    key if OPEN_KEYS.contains(&key) => {}
                    _ => mode = BrowserProfileModeV1::RemoteDebugging,
                }
            }
            _ => {}
        }
    }
    (url, mode)
}

#[cfg(test)]
#[path = "browser_omp_eval_action_tests.rs"]
mod tests;
