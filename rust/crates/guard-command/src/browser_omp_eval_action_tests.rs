use guard_contracts::{
    BrowserInputKindV1, BrowserIntentV1, BrowserProfileModeV1, BrowserSensitiveSurfaceV1,
    BrowserVerbV1,
};

use super::*;
use crate::pretool::generic::loopback_browser_program;

fn action(code: &str) -> BrowserActionV2 {
    let action = omp_eval_browser_action(code, "omp", &["http://127.0.0.1:5179"])
        .unwrap_or_else(|| panic!("no action: {code}"));
    action.validate_shape().expect("valid shape");
    action
}

#[test]
fn a_page_check_projects_its_strongest_step_on_the_opened_page() {
    let code = "const tab = await browser.open({name:'demo',url:'http://localhost:4173'}); display(await tab.title()); await tab.click('#start'); await tab.screenshot();";
    assert!(loopback_browser_program(code, None));
    let found = action(code);
    assert_eq!(found.driver.id, OMP_EVAL_BROWSER_DRIVER_ID);
    assert_eq!(found.driver.kind, BrowserDriverKindV1::HarnessTool);
    assert_eq!(found.verb, BrowserVerbV1::Click);
    assert_eq!(found.intent, BrowserIntentV1::Interact);
    assert_eq!(found.operation, "eval.click");
    assert_eq!(
        found.target.origin.as_deref(),
        Some("http://localhost:4173")
    );
    assert!(found.target.is_loopback);
    assert_eq!(found.session.profile_mode, BrowserProfileModeV1::Isolated);
    assert!(found.element.is_some());
    assert!(found.input.is_none());
}

#[test]
fn in_page_code_is_privileged_with_only_a_digest_of_the_program() {
    let code = "const tab=browser.tab('t'); await tab.click('#a'); display(await tab.evaluate(()=>document.title));";
    assert!(loopback_browser_program(code, None));
    let found = action(code);
    assert_eq!(found.verb, BrowserVerbV1::Evaluate);
    assert_eq!(found.intent, BrowserIntentV1::Privileged);
    assert!(found
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::ScriptEval));
    let input = found.input.expect("script input");
    assert_eq!(input.kind, BrowserInputKindV1::Script);
    assert_eq!(input.length, code.len() as u64);
    assert!(input.digest.is_some());
}

#[test]
fn a_goto_moves_the_target_and_page_runs_count_their_inner_calls() {
    let code = "const tab = browser.tab('t'); await tab.run(async ({page}) => { await page.goto('http://localhost:4173/about'); await page.keyboard.press('Space'); return await page.title(); });";
    assert!(loopback_browser_program(code, None));
    let found = action(code);
    assert_eq!(found.verb, BrowserVerbV1::Key);
    assert_eq!(found.operation, "eval.press");
    let goto =
        action("const tab = browser.tab('t'); await tab.goto('http://localhost:5173/next');");
    assert_eq!(goto.verb, BrowserVerbV1::Navigate);
    assert_eq!(goto.target.origin.as_deref(), Some("http://localhost:5173"));
}

#[test]
fn reviewed_programs_still_project_an_action() {
    // Another host: admission reviews it, the action names it.
    let remote = "const tab = await browser.open({url:'https://example.com/login'}); await tab.fill('#password', 'x');";
    assert!(!loopback_browser_program(remote, None));
    let found = action(remote);
    assert!(!found.target.is_loopback);
    assert_eq!(found.verb, BrowserVerbV1::Type);
    assert!(found
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::PasswordField));
    // Guard's own origin is marked.
    let own = action("const tab = await browser.open({url:'http://127.0.0.1:5179/approvals'});");
    assert!(own.target.is_guard_origin);
    // An option that may attach another browser.
    let attach =
        action("const tab = await browser.open({url:'http://localhost:3000', app:'chrome'});");
    assert_eq!(attach.verb, BrowserVerbV1::Attach);
    assert_eq!(
        attach.session.profile_mode,
        BrowserProfileModeV1::RemoteDebugging
    );
    assert_eq!(attach.intent, BrowserIntentV1::Privileged);
    // A comment stops the tokenizer: the program is unmodelled and privileged.
    let commented = "// check the page\nconst tab = browser.tab('t'); await tab.click('#a');";
    assert!(!loopback_browser_program(commented, None));
    let unread = action(commented);
    assert_eq!(unread.verb, BrowserVerbV1::Other);
    assert_eq!(unread.intent, BrowserIntentV1::Privileged);
    assert_eq!(unread.session.profile_mode, BrowserProfileModeV1::Unknown);
    // Facade methods the parser does not model.
    let other = action("await browser.cookies();");
    assert_eq!(other.verb, BrowserVerbV1::Other);
    assert_eq!(other.operation, "eval.browser.cookies");
}

#[test]
fn a_javascript_url_is_script_evaluation() {
    let found = action("const tab = browser.tab('t'); await tab.goto('javascript:alert(1)');");
    assert!(found
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::ScriptEval));
    assert_eq!(found.intent, BrowserIntentV1::Privileged);
}

#[test]
fn programs_without_browser_calls_have_no_action() {
    for code in [
        "display(1 + 2);",
        "const r = await fetch('http://127.0.0.1:8080/health'); display(r.ok);",
        "// no browser here\nconsole.log(1)",
    ] {
        assert!(
            omp_eval_browser_action(code, "omp", &[]).is_none(),
            "{code}"
        );
    }
}

#[test]
fn options_guard_cannot_read_may_attach_another_browser() {
    for code in [
        "const o = {app: 'chrome'}; await browser.open(o);",
        "const o = {app: 'chrome'}; await browser.open({...o});",
        "const k = 'app'; await browser.open({[k]: 'chrome'});",
        "const app = 'chrome'; await browser.open({app});",
    ] {
        let found = action(code);
        assert_eq!(
            found.session.profile_mode,
            BrowserProfileModeV1::RemoteDebugging,
            "{code}"
        );
        assert_eq!(found.verb, BrowserVerbV1::Attach, "{code}");
    }
    for code in [
        "await browser.open();",
        "await browser.open({url: 'https://example.com', headed: true});",
        "const url = 'https://example.com'; await browser.open({url, headed: true,});",
    ] {
        let found = action(code);
        assert_eq!(
            found.session.profile_mode,
            BrowserProfileModeV1::Isolated,
            "{code}"
        );
        assert_eq!(found.verb, BrowserVerbV1::Navigate, "{code}");
    }
}

#[test]
fn facade_access_the_scanner_does_not_model_is_still_a_browser_action() {
    for code in [
        "await browser['open']({url: 'https://example.com'});",
        "await browser?.open({url: 'https://example.com'});",
        "const {open} = browser; await open({url: 'https://example.com'});",
    ] {
        let found = omp_eval_browser_action(code, "omp", &[]).expect(code);
        assert_eq!(found.verb, BrowserVerbV1::Other, "{code}");
        assert_eq!(found.intent, BrowserIntentV1::Privileged, "{code}");
        assert_eq!(
            found.session.profile_mode,
            BrowserProfileModeV1::Unknown,
            "{code}"
        );
    }
}
