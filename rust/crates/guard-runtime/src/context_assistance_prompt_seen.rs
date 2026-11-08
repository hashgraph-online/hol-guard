//! The excerpts CIGAR already added to a session. A later prompt in the same
//! session names an excerpt it already has instead of sending it again, so
//! a long session does not carry the same code once per prompt. An excerpt
//! counts as the same only when its file, lines and text all match, so code
//! edited since it was shown is sent again.
//!
//! Only this process remembers, for a bounded number of sessions; a
//! restart, or a session it no longer holds, gets every excerpt again.
use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_SESSIONS: usize = 64;
const MAX_SPANS: usize = 128;

/// Lines of one project file that a prompt's context showed, with a digest
/// of the text they held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Span {
    pub(super) path: String,
    pub(super) start: u64,
    pub(super) end: u64,
    digest: u64,
}

impl Span {
    pub(super) fn new(path: &str, start: u64, end: u64, text: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        Self {
            path: path.to_owned(),
            start,
            end,
            digest: hasher.finish(),
        }
    }
}

/// Stands for the hint that ends a note, recorded beside the excerpts once
/// a note of the session carried it. No project file has an empty path, so
/// it never matches an excerpt.
pub(super) fn hint() -> Span {
    Span::new("", 0, 0, "hint")
}

/// One session of one app in one project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Session {
    pub(super) root: PathBuf,
    pub(super) app: String,
    pub(super) id: String,
}

type Sessions = Mutex<VecDeque<(Session, Vec<Span>)>>;

fn sessions() -> &'static Sessions {
    static SESSIONS: OnceLock<Sessions> = OnceLock::new();
    SESSIONS.get_or_init(Default::default)
}

/// What earlier prompts of `session` were shown.
pub(super) fn earlier(session: &Session) -> Vec<Span> {
    let Ok(sessions) = sessions().lock() else {
        return Vec::new();
    };
    sessions
        .iter()
        .find(|(known, _)| known == session)
        .map(|(_, spans)| spans.clone())
        .unwrap_or_default()
}

/// Records what this prompt's context showed. The session moves to the back
/// of the list, and the oldest session or span goes once a bound is met.
/// Pi and Oh My Pi drop the context when the agent is busy or the prompt
/// changed before it starts, so Guard cannot tell whether they showed it and
/// records nothing for them.
pub(super) fn remember(session: &Session, shown: &[Span]) {
    if shown.is_empty() || matches!(session.app.as_str(), "pi" | "omp") {
        return;
    }
    let Ok(mut sessions) = sessions().lock() else {
        return;
    };
    let mut spans = sessions
        .iter()
        .position(|(known, _)| known == session)
        .and_then(|index| sessions.remove(index))
        .map(|(_, spans)| spans)
        .unwrap_or_default();
    spans.extend(shown.iter().cloned());
    let extra = spans.len().saturating_sub(MAX_SPANS);
    spans.drain(..extra);
    while sessions.len() >= MAX_SESSIONS {
        sessions.pop_front();
    }
    sessions.push_back((session.clone(), spans));
}

#[cfg(test)]
#[path = "context_assistance_prompt_seen_tests.rs"]
mod tests;
