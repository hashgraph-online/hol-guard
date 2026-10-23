//! A Python package query reports what an environment already holds, so it
//! runs inside the workspace sandbox the way `npm ls` and `cargo tree` do, and
//! so does a runner that launches a program out of an environment the project
//! already materialized. Everything that installs on the runner's behalf keeps
//! the admission it has today, as does every read that resolves through the
//! home directory the sandbox replaces. A host without the sandbox, such as
//! Windows, keeps the admission for all of them too.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

const PROJECT: &str = "[project]\nname = \"app-portal\"\nversion = \"0.1.0\"\n";

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A project whose environment is already materialized, with the console
/// scripts a `pip install -e .` leaves behind.
fn project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(ws.join("uv.lock"), "version = 1\n").unwrap();
    std::fs::create_dir_all(ws.join(".venv/bin")).unwrap();
    // What makes the prefix a virtual environment pip reads without the user site.
    std::fs::write(
        ws.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\nversion = 3.12.3\n",
    )
    .unwrap();
    for name in ["pip", "pip3", "python"] {
        std::fs::write(ws.join(".venv/bin").join(name), "#!/bin/sh\n").unwrap();
    }
    ws
}

#[test]
fn a_package_query_reads_the_environment_inside_the_sandbox() {
    let ws = project("python-reads");
    for command in [
        ".venv/bin/pip list",
        "./.venv/bin/pip list --format=freeze",
        ".venv/bin/pip3 freeze",
        ".venv/bin/pip show requests",
        ".venv/bin/pip check",
        "uv pip list",
        "uv pip freeze",
        "uv pip show requests",
        "uv pip check",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn everything_that_installs_keeps_its_review() {
    let ws = project("python-installs");
    for command in [
        ".venv/bin/pip install requests",
        ".venv/bin/pip install -r requirements.txt",
        ".venv/bin/pip uninstall -y requests",
        ".venv/bin/pip download requests",
        ".venv/bin/pip wheel .",
        ".venv/bin/pip config set global.index-url https://example.invalid/simple",
        "uv pip install requests",
        "uv pip uninstall requests",
        "uv pip sync requirements.txt",
        "uv pip compile pyproject.toml",
        "pipx install ruff",
        "pipx run ruff check .",
        "pipx inject app-portal httpx",
        "pipx upgrade-all",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn an_option_or_operand_outside_the_query_keeps_its_review() {
    let ws = project("python-unknown");
    for command in [
        // `--target` and `--index-url` belong to the installing surface, and
        // `pip list` takes no distribution name, so each is another command's
        // shape rather than the listing this module reads.
        ".venv/bin/pip list --index-url https://example.invalid/simple",
        ".venv/bin/pip list requests",
        ".venv/bin/pip show",
        "uv pip list --target build",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_uv_query_without_a_materialized_environment_keeps_its_review() {
    // Without `.venv` uv would have to install before it could report, and
    // the sandbox has no network for that.
    let bare = workspace("python-bare", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv pip list", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn a_read_the_sandbox_would_answer_for_itself_keeps_its_review() {
    // A contained run is given the workspace as its `HOME`, so pip's cache,
    // the user site and every `pipx` layout resolve inside the sandbox. Each
    // of these would report that directory instead of the developer's, which
    // is a worse answer than the review it would replace.
    let ws = project("python-home-reads");
    for command in [
        ".venv/bin/pip cache dir",
        ".venv/bin/pip cache info",
        ".venv/bin/pip cache list",
        ".venv/bin/pip list --user",
        ".venv/bin/pip freeze --user",
        "uv pip list --user",
        "pipx list",
        "pipx list --short",
        "pipx environment",
        "pipx environment --value PIPX_HOME",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_query_beside_an_install_keeps_the_whole_command_out() {
    let ws = project("python-mixed");
    for command in [
        ".venv/bin/pip list && .venv/bin/pip install requests",
        "uv pip freeze > frozen.txt && uv pip install -r frozen.txt",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn a_pip_outside_a_virtual_environment_keeps_its_review() {
    // Outside a virtual environment pip reports the user site under the home
    // directory the sandbox replaces, so the listing would describe the
    // sandbox and `pip show` would miss what the developer installed.
    let ws = project("python-bare-pip");
    std::fs::create_dir_all(ws.join("tools/bin")).unwrap();
    std::fs::write(ws.join("tools/bin/pip"), "#!/bin/sh\n").unwrap();
    for command in [
        "pip list",
        "pip3 freeze",
        "pip show requests",
        "tools/bin/pip list",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_virtual_environment_that_exposes_the_user_site_keeps_its_review() {
    // `python -m venv --system-site-packages` writes
    // `include-system-site-packages = true`, which leaves the user site
    // enabled inside the environment. pip there still reports what the
    // developer installed under their own home, so a contained run would
    // describe the sandbox's home instead.
    let ws = project("python-system-site");
    std::fs::write(
        ws.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\ninclude-system-site-packages = true\nversion = 3.12.3\n",
    )
    .unwrap();
    for command in [
        ".venv/bin/pip list",
        ".venv/bin/pip show requests",
        "uv pip list",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn an_empty_venv_directory_is_not_an_environment() {
    // `.venv` can exist without holding an environment, and uv then searches
    // for one elsewhere; the listing would report whatever it found.
    let bare = workspace("python-empty-venv", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::create_dir_all(bare.join(".venv/bin")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv pip list", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

/// A project with a Poetry manifest, lockfile and local virtual environment.
fn poetry_project(name: &str) -> std::path::PathBuf {
    let ws = project(name);
    std::fs::write(ws.join("poetry.lock"), "# generated\n").unwrap();
    ws
}

#[test]
fn a_poetry_read_that_stays_in_the_project_runs_inside_the_sandbox() {
    let ws = poetry_project("poetry-reads");
    for command in [
        "poetry check",
        "poetry check --lock",
        "poetry version",
        "poetry version --short",
        "poetry --no-interaction check",
        "poetry -q version",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn every_poetry_verb_that_reaches_a_registry_keeps_its_review() {
    let ws = poetry_project("poetry-installs");
    for command in [
        "poetry add requests",
        "poetry install",
        "poetry install --no-root",
        "poetry update",
        "poetry lock",
        "poetry remove requests",
        "poetry export -f requirements.txt",
        "poetry publish --build",
        "poetry self update",
        "poetry source add internal https://example.invalid/simple",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_poetry_verb_that_writes_or_moves_the_project_keeps_its_review() {
    // `poetry version 2.0.0` writes the version back into the manifest, the
    // directory options name a project these checks never looked at, and
    // `env info` and `show` answer for the environment poetry resolves
    // through its own home, which the sandbox replaces.
    let ws = poetry_project("poetry-elsewhere");
    for command in [
        "poetry version 2.0.0",
        "poetry version patch",
        "poetry version -- patch",
        "poetry version -- 2.0.0",
        "poetry version --project=../dashboard",
        "poetry version -C../dashboard",
        "poetry version -P../dashboard",
        "poetry check --directory=../dashboard",
        "poetry check --project ../dashboard",
        "poetry check --unknown-option",
        "poetry run -C ../dashboard pytest",
        "poetry run --project=../dashboard pytest",
        "poetry -C ../dashboard run pytest",
        "poetry --directory ../dashboard check",
        "poetry --project ../dashboard version",
        "poetry env info",
        "poetry show",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_runner_launching_the_project_environment_runs_inside_the_sandbox() {
    // `poetry run` and `pipenv run` launch out of the environment the project
    // already holds, which is what `uv run` does, and the sandbox bounds the
    // nested program the same way there: no network, no home, writes inside
    // the workspace. A nested install is admitted for that reason, not
    // because the install itself was judged safe.
    let ws = poetry_project("runner-launches");
    std::fs::write(ws.join("Pipfile"), "[packages]\n").unwrap();
    for command in [
        "poetry run pytest -q",
        "poetry run -- pytest -q",
        "poetry run ruff check src",
        "poetry --no-interaction run pytest -q",
        "poetry run pip install ./local-package",
        "poetry run python -m pip install ./local-package",
        "pipenv run pytest -q",
        "pipenv run -- pytest -q",
        "pipenv run python -m pytest",
        "pipenv -q run pytest -q",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn a_runner_verb_that_names_no_program_keeps_its_review() {
    // A bare `run` drops into a shell poetry picks, an option standing where
    // the program belongs is the runner's own, and every pipenv verb that is
    // not `run` builds, relocates or installs into an environment.
    let ws = poetry_project("runner-no-program");
    std::fs::write(ws.join("Pipfile"), "[packages]\n").unwrap();
    for command in [
        "poetry run",
        "poetry run --",
        "pipenv run",
        "pipenv run --",
        "pipenv run --help",
        "pipenv install",
        "pipenv install requests",
        "pipenv sync",
        "pipenv update",
        "pipenv shell",
        "pipenv --python 3.12 run pytest",
        "pipenv --venv",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_poetry_run_without_a_materialized_environment_keeps_its_review() {
    // Poetry puts the environment under its own home unless the project holds
    // `.venv`, and a contained run is handed the workspace as that home, so
    // the run would have to create the environment the sandbox has no network
    // to fill.
    let bare = workspace("poetry-bare", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(bare.join("poetry.lock"), "# generated\n").unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "poetry run pytest -q", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
    // The verbs that read the manifest need no environment at all.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "poetry check", &bare);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
    }
    // Pipenv's default is an environment under its own home, so it reads the
    // same way.
    std::fs::write(bare.join("Pipfile"), "[packages]\n").unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "pipenv run pytest -q", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn a_poetry_read_beside_an_install_keeps_the_whole_command_out() {
    let ws = poetry_project("poetry-mixed");
    for command in [
        "poetry check && poetry install",
        "poetry version; poetry add requests",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn a_venv_that_holds_no_environment_keeps_the_runner_out() {
    // A directory named `.venv` is not proof of anything: without `pyvenv.cfg`
    // the runner goes looking for an environment elsewhere, and one built
    // against the developer's own site packages answers for a home the sandbox
    // replaces. Both are the wrong environment to launch a program out of, and
    // `uv pip` is already kept out for the same two reasons.
    let bare = workspace("runner-hollow-venv", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(bare.join("poetry.lock"), "# generated\n").unwrap();
    std::fs::write(bare.join("Pipfile"), "[packages]\n").unwrap();
    std::fs::create_dir_all(bare.join(".venv/bin")).unwrap();
    for command in ["poetry run pytest -q", "pipenv run pytest -q"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &bare);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    std::fs::write(
        bare.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\ninclude-system-site-packages = true\n",
    )
    .unwrap();
    for command in ["poetry run pytest -q", "pipenv run pytest -q"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &bare);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // The same environment written the ordinary way is the one the runner is
    // admitted on.
    std::fs::write(
        bare.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\nversion = 3.12.3\n",
    )
    .unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "poetry run pytest -q", &bare);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
    }
}

/// A plain output redirect disqualifies the narrower read-only pytest profile,
/// which cannot confine the file the suite opens. The workspace sandbox can, so
/// the run routes there instead of asking. A chain as short as
/// `pytest -q && echo done` already reached the sandbox, because two segments
/// earn no narrower profile of their own; the single command belongs there for
/// the same reason.
#[test]
fn a_redirected_pytest_run_routes_to_the_workspace_sandbox() {
    let ws = project("python-pytest-redirect");
    std::fs::write(ws.join(".venv/bin/pytest"), "#!/bin/sh\n").unwrap();
    for command in [
        "pytest -q > out.txt",
        "pytest -q tests/ > out.txt 2>&1",
        ".venv/bin/pytest -q > out.txt",
        "pytest -q >> pytest.log",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
    // A lone trailing `2>&1` names no file: the narrower read-only sink peels
    // it from the core itself (`contained_core`), so on macOS the run keeps
    // that sandboxed profile, as `python3 -m pytest -q 2>&1 | tail -20` does.
    // Where no narrower profile claims pytest, its projection `pytest -q`
    // reaches the workspace sandbox the way the plain run does.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, action) = outcome(harness, "pytest -q 2>&1", &ws);
        if cfg!(target_os = "macos") {
            assert_eq!(
                reason, "native_pytest_readonly_containment_required",
                "{harness}"
            );
            assert_eq!(action, "sandbox-required", "{harness}");
        } else {
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        }
    }
    // A redirect the sandbox cannot confine keeps its review.
    for command in ["pytest -q > ../out.txt"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}
