//! First-party browser driver profiles shipped with Guard.
//!
//! The Chrome DevTools MCP, Playwright MCP and Puppeteer MCP tool lists live in
//! `contributions/browser-drivers/` as ordinary driver profiles. They compile once, with the same
//! compiler and limits as a contributed profile, and replace the hand-kept operation tables that
//! used to sit in `browser_mcp_patterns.rs`. Server-name detection and the generic operation-name
//! fallback for other browser servers stay native.

use std::sync::OnceLock;

use guard_contracts::{BrowserIntentV1, BrowserProfileModeV1};

use crate::browser_driver_compile::{
    compile_browser_driver_set, BrowserDriverOrigin, CompiledBrowserDriverV1, CompiledBrowserToolV1,
};

pub const CHROME_DEVTOOLS_DRIVER_ID: &str = "browser.chrome-devtools-mcp";
pub const PLAYWRIGHT_DRIVER_ID: &str = "browser.playwright-mcp";
pub const PUPPETEER_DRIVER_ID: &str = "browser.puppeteer-mcp";

const CHROME_DEVTOOLS: &str =
    include_str!("../../../../contributions/browser-drivers/browser.chrome-devtools-mcp.json");
const PLAYWRIGHT: &str =
    include_str!("../../../../contributions/browser-drivers/browser.playwright-mcp.json");
const PUPPETEER: &str =
    include_str!("../../../../contributions/browser-drivers/browser.puppeteer-mcp.json");

/// The publisher first-party profiles name. Only first-party profiles are compiled against it.
const FIRST_PARTY_PUBLISHERS: &[&str] = &["HOL Guard"];

/// The compiled first-party profiles. The files ship in this crate, so a compile failure is a
/// build defect that the tests catch; at run time it leaves the table empty and the generic
/// operation-name fallback applies.
pub fn first_party_browser_drivers() -> &'static [CompiledBrowserDriverV1] {
    static DRIVERS: OnceLock<Vec<CompiledBrowserDriverV1>> = OnceLock::new();
    DRIVERS.get_or_init(|| compile_first_party().unwrap_or_default())
}

pub(crate) fn compile_first_party() -> Result<Vec<CompiledBrowserDriverV1>, String> {
    let sources = [
        (CHROME_DEVTOOLS.as_bytes(), BrowserDriverOrigin::FirstParty),
        (PLAYWRIGHT.as_bytes(), BrowserDriverOrigin::FirstParty),
        (PUPPETEER.as_bytes(), BrowserDriverOrigin::FirstParty),
    ];
    compile_browser_driver_set(&sources, FIRST_PARTY_PUBLISHERS)
        .map_err(|error| error.code().to_owned())
}

fn driver(id: &str) -> Option<&'static CompiledBrowserDriverV1> {
    first_party_browser_drivers()
        .iter()
        .find(|driver| driver.id == id)
}

/// The intent a first-party profile gives `operation`. `None` when the profile does not list the
/// operation as a fixed tool.
pub fn first_party_operation_intent(driver_id: &str, operation: &str) -> Option<BrowserIntentV1> {
    match driver(driver_id)?.tools.get(operation)? {
        CompiledBrowserToolV1::Fixed(compiled) => Some(compiled.intent),
        _ => None,
    }
}

/// Profile mode from launch arguments, using the first-party profiles' flag lists. Isolation wins
/// over remote debugging, then a dedicated profile directory, then an explicit shared flag.
pub fn first_party_profile_mode<'a>(
    arguments: impl Iterator<Item = &'a str> + Clone,
) -> BrowserProfileModeV1 {
    let drivers = first_party_browser_drivers();
    let any = |pick: fn(&CompiledBrowserDriverV1) -> &[String]| {
        arguments.clone().any(|argument| {
            drivers
                .iter()
                .flat_map(pick)
                .any(|flag| argument.starts_with(flag.as_str()))
        })
    };
    if any(|driver| &driver.profile_flags.isolated) {
        return BrowserProfileModeV1::Isolated;
    }
    if any(|driver| &driver.profile_flags.remote_debugging) {
        return BrowserProfileModeV1::RemoteDebugging;
    }
    if any(|driver| &driver.profile_flags.dedicated) {
        return BrowserProfileModeV1::Dedicated;
    }
    if any(|driver| &driver.profile_flags.shared) {
        return BrowserProfileModeV1::Shared;
    }
    BrowserProfileModeV1::Unknown
}

#[cfg(test)]
#[path = "browser_first_party_drivers_tests.rs"]
mod tests;
