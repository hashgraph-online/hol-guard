//! The production facts answer each question once and stop at the deadline.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::CompoundGitCheckV1;

use crate::compound_git_facts::{GitFacts, ResidentGitFacts};
use crate::compound_git_inspection_op_tests::request;

#[test]
fn an_expired_deadline_denies_every_fact_without_running_anything() {
    let req = request(CompoundGitCheckV1::Compound);
    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let facts = ResidentGitFacts::with_deadline(&req, expired);
    let cwd = std::env::temp_dir();
    let git = Path::new("/bin/sh");
    assert!(facts.trusted_git(&cwd).is_none());
    assert!(facts.probe(git, &cwd, &["-c", "exit 0"]).is_none());
    assert!(!facts.fetch_origin_is_safe(&cwd, git));
    assert!(!facts.status_is_safe(&cwd, git));
    assert!(!facts.push_origin_is_safe(&cwd, git, "main"));
    assert!(!facts.object_query_is_safe(&cwd, git));
}

#[cfg(unix)]
#[test]
fn a_repeated_probe_runs_once() {
    let dir = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cgi-facts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let counter = dir.join("count.txt");
    let script = format!("echo x >> '{}'", counter.display());
    let req = request(CompoundGitCheckV1::Compound);
    let facts = ResidentGitFacts::new(&req);
    let git = Path::new("/bin/sh");
    let first = facts.probe(git, &dir, &["-c", &script]).unwrap();
    let second = facts.probe(git, &dir, &["-c", &script]).unwrap();
    assert_eq!(first.code, Some(0));
    assert_eq!(second.code, Some(0));
    assert_eq!(
        std::fs::read_to_string(&counter).unwrap().lines().count(),
        1
    );
    // A different question is not served from the cache.
    facts.probe(git, &dir, &["-c", &format!("{script}; true")]);
    assert_eq!(
        std::fs::read_to_string(&counter).unwrap().lines().count(),
        2
    );
    let _ = std::fs::remove_dir_all(&dir);
}
