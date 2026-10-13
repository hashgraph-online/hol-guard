//! Bounded, non-interactive Git metadata probes.
use std::cell::RefCell;
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Wall-clock budget for one configuration probe. A loaded host can need more
/// than a second for the config, attribute and index queries together; the
/// caller's overall deadline still caps it and an expired probe still reviews.
pub(super) const PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Index and path listings stay bounded, but large enough for repositories
/// with a few hundred thousand tracked files.
pub(super) const LISTING_LIMIT: u64 = 16 * 1024 * 1024;

pub(super) type MemoKey = (String, Vec<String>, Option<String>, Option<String>, bool);
type Memo = Option<Vec<(MemoKey, Option<bool>)>>;

thread_local! {
    static MEMO: RefCell<Memo> = const { RefCell::new(None) };
}

/// Lets every proof within one evaluation share a single probe of each Git
/// segment. The memo is dropped when `evaluate` returns, so the next
/// evaluation inspects the repository again.
pub(crate) fn with_memo<T>(evaluate: impl FnOnce() -> T) -> T {
    struct Restore(Memo);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEMO.with(|memo| *memo.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(MEMO.with(|memo| memo.replace(Some(Vec::new()))));
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

pub(super) fn output(
    command: &mut Command,
    deadline: Instant,
    limit: u64,
) -> Option<(ExitStatus, Vec<u8>)> {
    if Instant::now() >= deadline {
        return None;
    }
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
}
