//! Bounded, non-interactive Git metadata probes.
use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "git_probe_repository.rs"]
mod repository;
pub(super) use repository::{bisect_log_inert, repository_inert};

/// Wall-clock budget for one configuration probe. A loaded host can need more
/// than a second for the config, attribute and index queries together; the
/// caller's overall deadline still caps it and an expired probe still reviews.
pub(super) const PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Index and path listings stay bounded, but large enough for repositories
/// with a few hundred thousand tracked files.
pub(super) const LISTING_LIMIT: u64 = 16 * 1024 * 1024;

pub(super) type MemoKey = (String, Vec<String>, Option<String>, Option<String>, bool);
type Memo = Option<Vec<(MemoKey, Option<bool>)>>;

/// The program, arguments, explicit environment, directory and output bound
/// of one query. Every query starts from [`copy_command`], so the environment
/// is always cleared first and these parts describe the whole process.
type QueryKey = (
    OsString,
    Vec<OsString>,
    Vec<(OsString, Option<OsString>)>,
    Option<PathBuf>,
    u64,
);
type Queries = Option<Vec<(QueryKey, (ExitStatus, Vec<u8>))>>;

thread_local! {
    static MEMO: RefCell<Memo> = const { RefCell::new(None) };
    static QUERIES: RefCell<Queries> = const { RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static SPAWNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Git processes this thread started, for tests that count probe spawns.
#[cfg(all(test, unix))]
pub(super) fn spawns() -> usize {
    SPAWNS.with(std::cell::Cell::get)
}

/// Lets every proof within one evaluation share a single probe of each Git
/// segment, and a single run of each identical metadata query. Both memos are
/// dropped when `evaluate` returns, so the next evaluation inspects the
/// repository and its configuration again.
pub(crate) fn with_memo<T>(evaluate: impl FnOnce() -> T) -> T {
    struct Restore(Memo, Queries);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEMO.with(|memo| *memo.borrow_mut() = self.0.take());
            QUERIES.with(|queries| *queries.borrow_mut() = self.1.take());
        }
    }
    let _restore = Restore(
        MEMO.with(|memo| memo.replace(Some(Vec::new()))),
        QUERIES.with(|queries| queries.replace(Some(Vec::new()))),
    );
    evaluate()
}

/// Whether a proof earlier in this evaluation already settled `key` as safe.
/// Outside an evaluation scope nothing is recorded, so this stays false.
pub(super) fn proven(key: &MemoKey) -> bool {
    MEMO.with(|memo| {
        memo.borrow().as_ref().is_some_and(|entries| {
            entries
                .iter()
                .any(|(entry, value)| entry == key && *value == Some(true))
        })
    })
}

pub(super) fn memoized(key: MemoKey, probe: impl FnOnce() -> Option<bool>) -> Option<bool> {
    let cached = MEMO.with(|memo| {
        memo.borrow().as_ref().map(|entries| {
            entries
                .iter()
                .find(|(entry, _)| *entry == key)
                .map(|(_, value)| *value)
        })
    });
    match cached {
        Some(Some(value)) => value,
        Some(None) => {
            let value = probe();
            MEMO.with(|memo| {
                if let Some(entries) = memo.borrow_mut().as_mut() {
                    entries.push((key, value));
                }
            });
            value
        }
        None => probe(),
    }
}

/// Runs a read-only metadata query built by [`copy_command`]. Within one
/// evaluation an identical query that already completed is answered from
/// memory: nothing the hook evaluates runs in between, so Git would print the
/// same bytes again. A query that failed or timed out is never remembered, and
/// an expired deadline still refuses before the memo is consulted.
pub(super) fn output(
    command: &mut Command,
    deadline: Instant,
    limit: u64,
) -> Option<(ExitStatus, Vec<u8>)> {
    if Instant::now() >= deadline {
        return None;
    }
    let key: QueryKey = (
        command.get_program().to_owned(),
        command.get_args().map(ToOwned::to_owned).collect(),
        command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(ToOwned::to_owned)))
            .collect(),
        command.get_current_dir().map(ToOwned::to_owned),
        limit,
    );
    let cached = QUERIES.with(|queries| {
        queries.borrow().as_ref().and_then(|entries| {
            entries
                .iter()
                .find(|(entry, _)| *entry == key)
                .map(|(_, result)| result.clone())
        })
    });
    if cached.is_some() {
        return cached;
    }
    let result = spawn_output(command, deadline, limit)?;
    QUERIES.with(|queries| {
        if let Some(entries) = queries.borrow_mut().as_mut() {
            entries.push((key, result.clone()));
        }
    });
    Some(result)
}

fn spawn_output(
    command: &mut Command,
    deadline: Instant,
    limit: u64,
) -> Option<(ExitStatus, Vec<u8>)> {
    #[cfg(test)]
    SPAWNS.with(|spawns| spawns.set(spawns.get() + 1));
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(limit + 1).read_to_end(&mut bytes).ok()?;
        (bytes.len() <= limit as usize).then_some(bytes)
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let bytes = reader.join().ok()??;
    Some((status?, bytes))
}

pub(super) fn submodules_are_inert(
    base: &Command,
    arguments: &[String],
    deadline: Instant,
) -> Option<bool> {
    let ignored = arguments
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_str() != "--")
        .filter_map(|arg| {
            if arg == "--ignore-submodules" {
                Some(true)
            } else {
                arg.strip_prefix("--ignore-submodules=")
                    .map(|value| value == "all")
            }
        })
        .last()
        == Some(true);
    if ignored {
        return Some(true);
    }
    let mut index = copy_command(base)?;
    // Inspect index metadata with fsmonitor and paging explicitly disabled.
    index.args([
        "-c",
        "core.fsmonitor=false",
        "--no-pager",
        "ls-files",
        "--stage",
        "-z",
        "--",
        ":/",
    ]);
    let (status, bytes) = output(&mut index, deadline, LISTING_LIMIT)?;
    if !status.success() {
        // Outside any repository there is no index and no gitlink, and
        // status or diff stops during repository setup. Any other listing
        // failure (a corrupt index, a timeout) stays unproven.
        return outside_repository(base, deadline)?.then_some(true);
    }
    // Gitlinks may launch children whose local configuration is unprobed.
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .all(|record| {
                [b"100644 ", b"100755 ", b"120000 "]
                    .iter()
                    .any(|mode| record.starts_with(*mode))
            }),
    )
}

/// Whether Git, in the same environment and directory, finds no repository.
fn outside_repository(base: &Command, deadline: Instant) -> Option<bool> {
    let mut lookup = copy_command(base)?;
    lookup.args(["--no-pager", "rev-parse", "--git-dir"]);
    let (status, _) = output(&mut lookup, deadline, 4096)?;
    Some(status.code() == Some(128))
}

/// Copy only the explicit lookup environment and directory, never ambient state.
pub(super) fn copy_command(base: &Command) -> Option<Command> {
    let mut command = Command::new(base.get_program());
    command.args(base.get_args()).env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command.current_dir(base.get_current_dir()?);
    Some(command)
}

#[cfg(test)]
mod tests {
    use super::{memoized, with_memo};
    use std::cell::Cell;

    fn key(argument: &str) -> super::MemoKey {
        (
            "git".into(),
            vec!["status".into(), argument.into()],
            Some("/home".into()),
            Some("/home/repo".into()),
            false,
        )
    }

    #[test]
    fn one_evaluation_probes_each_segment_once() {
        let runs = Cell::new(0);
        let probe = |value| {
            runs.set(runs.get() + 1);
            value
        };
        with_memo(|| {
            assert_eq!(memoized(key("--short"), || probe(Some(true))), Some(true));
            assert_eq!(memoized(key("--short"), || probe(Some(false))), Some(true));
            assert_eq!(memoized(key("--long"), || probe(None)), None);
            assert_eq!(memoized(key("--long"), || probe(Some(true))), None);
        });
        assert_eq!(runs.get(), 2);
    }

    #[test]
    fn later_evaluations_probe_again() {
        let runs = Cell::new(0);
        let probe = || {
            runs.set(runs.get() + 1);
            Some(true)
        };
        with_memo(|| memoized(key("--short"), probe));
        with_memo(|| memoized(key("--short"), probe));
        memoized(key("--short"), probe);
        memoized(key("--short"), probe);
        assert_eq!(runs.get(), 4);
    }

    #[test]
    fn nested_scope_restores_the_outer_memo() {
        let runs = Cell::new(0);
        let probe = || {
            runs.set(runs.get() + 1);
            Some(true)
        };
        with_memo(|| {
            memoized(key("--short"), probe);
            with_memo(|| memoized(key("--short"), probe));
            memoized(key("--short"), probe);
        });
        assert_eq!(runs.get(), 2);
    }

    #[cfg(unix)]
    fn query(text: &str, marker: Option<&str>) -> Option<(std::process::ExitStatus, Vec<u8>)> {
        let mut base = std::process::Command::new("/bin/sh");
        base.current_dir("/");
        if let Some(marker) = marker {
            base.env("MARKER", marker);
        }
        let mut command = super::copy_command(&base)?;
        command.args(["-c", &format!("printf %s \"{text}$MARKER\"")]);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        super::output(&mut command, deadline, 4096)
    }

    #[cfg(unix)]
    #[test]
    fn one_evaluation_runs_each_identical_query_once() {
        let before = super::spawns();
        let (first, repeated, other, marked) = with_memo(|| {
            (
                query("a", None),
                query("a", None),
                query("b", None),
                query("a", Some("!")),
            )
        });
        assert_eq!(super::spawns() - before, 3);
        assert_eq!(
            first.as_ref().map(|(_, bytes)| bytes.as_slice()),
            Some(&b"a"[..])
        );
        assert_eq!(first, repeated);
        assert_eq!(other.map(|(_, bytes)| bytes), Some(b"b".to_vec()));
        assert_eq!(marked.map(|(_, bytes)| bytes), Some(b"a!".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn queries_outside_or_across_evaluations_run_again() {
        let before = super::spawns();
        with_memo(|| query("a", None));
        with_memo(|| query("a", None));
        query("a", None);
        query("a", None);
        assert_eq!(super::spawns() - before, 4);
    }

    #[cfg(unix)]
    #[test]
    fn an_expired_deadline_refuses_before_the_memo() {
        with_memo(|| {
            assert!(query("a", None).is_some());
            let mut command =
                super::copy_command(std::process::Command::new("/bin/sh").current_dir("/"))
                    .unwrap();
            command.args(["-c", "printf %s \"a$MARKER\""]);
            let before = super::spawns();
            assert!(super::output(&mut command, std::time::Instant::now(), 4096).is_none());
            assert_eq!(super::spawns(), before);
        });
    }
}
