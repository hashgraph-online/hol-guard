//! Proof for Guard's own contained pytest runner.
//!
//! `hol-guard pytest-contained [--workspace <dir>] [--] <pytest argv>` runs the
//! argv inside the mandatory operating-system sandbox and refuses to launch
//! when that sandbox is unavailable, so invoking it is the route Guard asks
//! models to take instead of running pytest directly. This proof admits only
//! the argument shapes the runner's CLI parses unambiguously and whose pytest
//! argv the runner itself accepts: a bare `pytest`/`py.test`, or a bare
//! `python`/`python3`/`python3.N` followed by `-m pytest`. The launcher
//! identity rule is the one in `guard_diagnostics` (bare name, no shadowing
//! launcher in the working directory). `--workspace` must resolve to the
//! working directory or to its nearest enclosing Git root; anything wider is
//! left to review.

use std::path::{Path, PathBuf};

fn python_name(name: &str) -> bool {
    name.strip_prefix("python").is_some_and(|suffix| {
        suffix.is_empty()
            || suffix
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn bare_name(value: &str) -> bool {
    !value.is_empty() && !value.contains(['/', '\\', '$', '`', '~', '*', '?', '[', '{'])
}

fn runner_command(command: &[String]) -> bool {
    match command {
        [] => false,
        [exe, ..] if !bare_name(exe) => false,
        [exe, ..] if matches!(exe.as_str(), "pytest" | "py.test") => true,
        [exe, module, target, ..] => python_name(exe) && module == "-m" && target == "pytest",
        _ => false,
    }
}

fn nearest_git_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .find(|dir| dir.join(".git").symlink_metadata().is_ok())
        .map(Path::to_path_buf)
}

fn workspace_allowed(value: &str, cwd: &str) -> bool {
    if value.is_empty()
        || value.starts_with(['-', '~'])
        || value.contains(['$', '`', '\\', '*', '?', '[', '{', '\0'])
    {
        return false;
    }
    let cwd = Path::new(cwd);
    if !cwd.is_absolute() {
        return false;
    }
    let Ok(cwd) = std::fs::canonicalize(cwd) else {
        return false;
    };
    let candidate = Path::new(value);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };
    let Ok(workspace) = std::fs::canonicalize(joined) else {
        return false;
    };
    workspace == cwd || nearest_git_root(&cwd).is_some_and(|root| root == workspace)
}

pub(super) fn safe_pytest_contained_arguments(arguments: &[String], cwd: Option<&str>) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    let [first, rest @ ..] = arguments else {
        return false;
    };
    if first != "pytest-contained" {
        return false;
    }
    let mut rest = rest;
    let mut workspace: Option<&str> = None;
    loop {
        match rest {
            [flag, value, tail @ ..] if flag == "--workspace" && workspace.is_none() => {
                workspace = Some(value);
                rest = tail;
            }
            [flag, tail @ ..] if flag.starts_with("--workspace=") && workspace.is_none() => {
                workspace = flag.strip_prefix("--workspace=");
                rest = tail;
            }
            [separator, tail @ ..] if separator == "--" => {
                rest = tail;
                break;
            }
            _ => break,
        }
    }
    // The shell consumes a trailing stderr merge; it is never a pytest argument.
    let rest = match rest {
        [head @ .., last] if last == "2>&1" => head,
        _ => rest,
    };
    !rest
        .iter()
        .any(|argument| argument.contains(['<', '>', '|', '&', ';', '\0']))
        && runner_command(rest)
        && workspace.is_none_or(|value| workspace_allowed(value, cwd))
}

#[cfg(test)]
mod tests {
    use super::safe_pytest_contained_arguments;

    fn args(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    fn workspace(label: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("pytest-contained-{label}-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        root
    }

    #[test]
    fn admits_only_forms_the_runner_cli_parses_unambiguously() {
        let root = workspace("admit");
        let cwd = root.to_str().unwrap();
        for command in [
            "pytest-contained python3 -m pytest -q",
            "pytest-contained -- python3 -m pytest -q",
            "pytest-contained pytest -q",
            "pytest-contained -- py.test tests/",
            "pytest-contained python -m pytest",
            "pytest-contained python3.12 -m pytest -k foo",
            "pytest-contained --workspace . -- python3 -m pytest -q",
            "pytest-contained --workspace . python3 -m pytest -q",
            "pytest-contained --workspace=. pytest -q",
            "pytest-contained pytest -q 2>&1",
        ] {
            assert!(
                safe_pytest_contained_arguments(&args(command), Some(cwd)),
                "{command}"
            );
        }
        let nested = root.join("pkg");
        let nested = nested.to_str().unwrap();
        assert!(safe_pytest_contained_arguments(
            &args("pytest-contained --workspace .. -- pytest -q"),
            Some(nested)
        ));
        let explicit = format!("pytest-contained --workspace {cwd} -- pytest -q");
        assert!(safe_pytest_contained_arguments(&args(&explicit), Some(cwd)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_bypass_and_ambiguous_forms() {
        let root = workspace("refuse");
        let cwd = root.to_str().unwrap();
        for command in [
            "pytest-contained",
            "pytest-contained --",
            "pytest-contained --workspace . --",
            "pytest-contained --workspace",
            "pytest-contained node -m pytest",
            "pytest-contained python3 -c print(1)",
            "pytest-contained python3 script.py",
            "pytest-contained python3 -W error -m pytest",
            "pytest-contained python3 -m pytestx",
            "pytest-contained /usr/bin/pytest -q",
            "pytest-contained ./pytest -q",
            "pytest-contained uv run pytest",
            "pytest-contained bash -c pytest",
            "pytest-contained --workspace / pytest -q",
            "pytest-contained --workspace .. pytest -q",
            "pytest-contained --workspace /tmp pytest -q",
            "pytest-contained --workspace ~ pytest -q",
            "pytest-contained --workspace $HOME pytest -q",
            "pytest-contained --workspace . --workspace . pytest",
            "pytest-contained --workspace=-x pytest -q",
            "pytest-contained --cwd /tmp pytest -q",
            "pytest-contained --timeout-seconds 9 pytest -q",
            "pytest-contained --read-only-workspace pytest -q",
            "pytest-contained -- -- pytest -q",
            "pytest-contained pytest-contained pytest",
            "pytest-contained pytest -q 2>&1 extra",
            "pytest-contained pytest -q >out",
            "pytest-contained pytest 2>/dev/null",
            "pytest-contained pytest &&",
            "pytest-contained pytest -k a|b",
            "pytest -q",
            "run pytest-contained pytest",
        ] {
            assert!(
                !safe_pytest_contained_arguments(&args(command), Some(cwd)),
                "{command}"
            );
        }
        assert!(!safe_pytest_contained_arguments(
            &args("pytest-contained pytest -q"),
            None
        ));
        assert!(!safe_pytest_contained_arguments(
            &args("pytest-contained --workspace . pytest -q"),
            Some("relative")
        ));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
