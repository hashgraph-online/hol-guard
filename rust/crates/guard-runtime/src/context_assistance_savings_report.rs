//! Turns the helped-session record into this week's savings estimate.
//!
//! Measured: how many sessions and prompts CIGAR helped, how much context it
//! handed over, which files it showed, which of those the agent opened anyway,
//! and the tokens each helped session used. Estimated: the tokens the same
//! work would have used without CIGAR, from the share CIGAR saved on Guard's
//! own benchmark for that app. Saved = used x rate / (1 - rate).
use super::read;
use super::{load, now, record_roots, Helped, DAY_SECS, KEEP_DAYS};
use serde::Serialize;
use std::path::Path;

pub(crate) const SCHEMA: &str = "guard-cigar-savings.v1";
/// Share of tokens CIGAR saved on Guard's benchmark, rounded down. Apps not
/// benchmarked use the lowest measured share.
const RATES: &[(&str, u32)] = &[("codex", 52), ("claude-code", 61)];
const DEFAULT_RATE: u32 = 52;
const CHARS_PER_TOKEN: u64 = 4;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) sessions: u64,
    pub(crate) prompts: u64,
    pub(crate) context_tokens: u64,
    pub(crate) files_shown: u64,
    pub(crate) files_opened_anyway: u64,
    /// Helped sessions whose own record Guard could read.
    pub(crate) measured_sessions: u64,
    pub(crate) used_tokens: u64,
    pub(crate) estimated_saved_tokens: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct App {
    pub(crate) app: String,
    /// Benchmark share used for the estimate, in percent.
    pub(crate) rate_percent: u32,
    #[serde(flatten)]
    pub(crate) totals: Totals,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) schema: &'static str,
    pub(crate) window_days: u64,
    pub(crate) estimate: bool,
    pub(crate) total: Totals,
    pub(crate) apps: Vec<App>,
}

pub(crate) fn rate(app: &str) -> u32 {
    RATES
        .iter()
        .find(|(name, _)| *name == app)
        .map_or(DEFAULT_RATE, |(_, rate)| *rate)
}

pub(crate) fn saved(used: u64, rate_percent: u32) -> u64 {
    let rate = u64::from(rate_percent.min(90));
    used.saturating_mul(rate) / (100 - rate)
}

impl Totals {
    fn add(&mut self, other: &Totals) {
        self.sessions += other.sessions;
        self.prompts += other.prompts;
        self.context_tokens += other.context_tokens;
        self.files_shown += other.files_shown;
        self.files_opened_anyway += other.files_opened_anyway;
        self.measured_sessions += other.measured_sessions;
        self.used_tokens += other.used_tokens;
        self.estimated_saved_tokens += other.estimated_saved_tokens;
    }
}

fn session(helped: &Helped, roots: &[std::path::PathBuf], rate_percent: u32) -> Totals {
    let mut totals = Totals {
        sessions: 1,
        prompts: helped.prompts,
        context_tokens: helped.chars / CHARS_PER_TOKEN,
        files_shown: helped.files.len() as u64,
        ..Totals::default()
    };
    let usage = helped
        .transcript
        .as_deref()
        .and_then(|path| read::usage(path, roots, &helped.files))
        .filter(|usage| usage.requests > 0);
    if let Some(usage) = usage {
        totals.measured_sessions = 1;
        totals.files_opened_anyway = usage.opened.len() as u64;
        totals.used_tokens = usage.tokens;
        totals.estimated_saved_tokens = saved(usage.tokens, rate_percent);
    }
    totals
}

/// This week's report. `home` and `env` say where the apps keep their records.
pub(crate) fn report(
    guard_home: &Path,
    home: &Path,
    env: impl Fn(&str) -> Option<String>,
) -> Report {
    report_at(guard_home, home, env, now())
}

pub(crate) fn report_at(
    guard_home: &Path,
    home: &Path,
    env: impl Fn(&str) -> Option<String>,
    at: u64,
) -> Report {
    let roots = record_roots(home, env);
    let cutoff = at.saturating_sub(KEEP_DAYS * DAY_SECS);
    let mut apps: Vec<App> = Vec::new();
    // Only sessions where CIGAR showed real code count as helped.
    let helped = load(guard_home).sessions;
    for item in helped
        .iter()
        .filter(|item| item.last >= cutoff && !item.files.is_empty())
    {
        let rate_percent = rate(&item.app);
        let totals = session(item, &roots, rate_percent);
        match apps.iter_mut().find(|app| app.app == item.app) {
            Some(app) => app.totals.add(&totals),
            None => apps.push(App {
                app: item.app.clone(),
                rate_percent,
                totals,
            }),
        }
    }
    apps.sort_by(|left, right| {
        right
            .totals
            .estimated_saved_tokens
            .cmp(&left.totals.estimated_saved_tokens)
            .then_with(|| left.app.cmp(&right.app))
    });
    let mut total = Totals::default();
    for app in &apps {
        total.add(&app.totals);
    }
    Report {
        schema: SCHEMA,
        window_days: KEEP_DAYS,
        estimate: true,
        total,
        apps,
    }
}
