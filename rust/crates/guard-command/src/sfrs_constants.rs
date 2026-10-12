//! Shared command and tool classification tables (`constants_core.py`).
//! Generated from the retired Python tables; keep in step with the vectors.

// Consumed by the later classifier slices.
#![allow(dead_code)]

pub(crate) const COMMAND_CANDIDATE_LIST_KEYS: &[&str] =
    &["argv", "command_args", "commandArgs", "commands"];
pub(crate) const COMMAND_LIST_KEYS: &[&str] = &["argv", "command_args", "commandArgs"];
pub(crate) const COMMAND_SEQUENCE_KEYS: &[&str] = &["commands"];
pub(crate) const COMMAND_KEYS: &[&str] = &[
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
];
pub(crate) const DESTRUCTIVE_SHELL_COMMANDS: &[&str] = &[
    "chmod",
    "chown",
    "dd",
    "del",
    "erase",
    "mv",
    "perl",
    "python",
    "python3",
    "rd",
    "remove-item",
    "rm",
    "rmdir",
    "ruby",
    "tee",
    "truncate",
    "unlink",
];
pub(crate) const DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS: &[&str] = &["login", "push", "run"];
pub(crate) const DOCKER_BUILDX_BUILD_SUBCOMMANDS: &[&str] = &["b", "build"];
pub(crate) const DOCKER_BUILDX_FLAG_OPTIONS: &[&str] = &["--debug"];
pub(crate) const DOCKER_BUILDX_OPTIONS_WITH_VALUES: &[&str] = &["--builder"];
pub(crate) const DOCKER_BUILD_ARG_SECRET_MARKERS: &[&str] = &[
    "API",
    "AUTH",
    "AWS",
    "CREDENTIAL",
    "KEY",
    "NPM",
    "PASSWORD",
    "SECRET",
    "TOKEN",
];
pub(crate) const DOCKER_BUILD_ARG_TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
];
pub(crate) const DOCKER_BUILD_METADATA_FLAGS: &[&str] = &["--annotation", "--label"];
pub(crate) const DOCKER_BUILD_OUTPUT_FLAGS: &[&str] = &[
    "--cache-to",
    "--iidfile",
    "--load",
    "--metadata-file",
    "--output",
    "--push",
    "-o",
];
pub(crate) const DOCKER_BUILD_SECRET_FLAGS: &[&str] = &["--allow", "--secret", "--ssh"];
pub(crate) const DOCKER_BUILD_SUBCOMMANDS: &[&str] = &["build"];
pub(crate) const DOCKER_COMPOSE_FLAG_OPTIONS: &[&str] = &[
    "--all-resources",
    "--compatibility",
    "--dry-run",
    "--no-ansi",
    "--no-interpolate",
    "--verbose",
    "--volumes",
    "-q",
];
pub(crate) const DOCKER_COMPOSE_OPTIONS_WITH_VALUES: &[&str] = &[
    "--ansi",
    "--env-file",
    "--file",
    "--parallel",
    "--profile",
    "--profiles",
    "--progress",
    "--project-directory",
    "--project-name",
    "-f",
    "-p",
];
pub(crate) const DOCKER_COMPOSE_SAFE_SUBCOMMANDS: &[&str] = &[
    "build", "config", "create", "down", "events", "images", "logs", "ls", "pause", "port", "ps",
    "pull", "restart", "rm", "start", "stop", "top", "unpause", "up", "version", "wait",
];
pub(crate) const DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS: &[&str] =
    &["cp", "exec", "publish", "push", "run", "watch"];
pub(crate) const DOCKER_COMPOSE_SUBCOMMAND: &str = r#"compose"#;
pub(crate) const DOCKER_GLOBAL_FLAG_OPTIONS: &[&str] = &["--debug", "--tls", "--tlsverify"];
pub(crate) const DOCKER_GLOBAL_OPTIONS_WITH_VALUES: &[&str] = &[
    "--config",
    "--context",
    "--host",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "-H",
    "-c",
    "-l",
];
pub(crate) const DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS: &[&str] = &["--tls", "--tlsverify"];
pub(crate) const DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS: &[&str] = &[
    "--config",
    "--context",
    "--host",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "-H",
    "-c",
];
pub(crate) const DOCKER_SENSITIVE_CONTEXT_ENV_KEYS: &[&str] = &[
    "COMPOSE_ENV_FILES",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS_VERIFY",
];
pub(crate) const FILE_READ_TOOL_NAMES: &[&str] = &[
    "cat_file",
    "open_file",
    "read",
    "read_file",
    "view",
    "view_file",
];
pub(crate) const FILE_WRITE_TOOL_NAMES: &[&str] = &[
    "apply_patch",
    "delete",
    "delete_file",
    "edit",
    "edit_file",
    "multiedit",
    "strreplace",
    "write",
    "write_file",
];
pub(crate) const FIND_EXEC_ACTION_FLAGS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];
pub(crate) const FIND_EXEC_PLACEHOLDER_TARGET: &str = r#"guard-find-placeholder.py"#;
pub(crate) const FIND_EXEC_TERMINATOR_TOKENS: &[&str] = &["+", ";", "\\;"];
pub(crate) const GH_PR_OPTION_VALUE_FLAGS: &[&str] = &["--repo", "-R"];
pub(crate) const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
    "target_path",
    "targetPath",
];
pub(crate) const PATH_LIST_KEYS: &[&str] = &["paths", "file_paths", "filePaths"];
pub(crate) const PYTEST_OPTION_CONFIG_PATHS: &[&str] = &[
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
];
pub(crate) const PYTEST_SAFE_FLAGS: &[&str] = &[
    "--disable-warnings",
    "--quiet",
    "--verbose",
    "-q",
    "-s",
    "-v",
    "-x",
];
pub(crate) const PYTEST_SAFE_FLAGS_WITH_VALUES: &[&str] = &["--maxfail", "--tb", "-k", "-m"];
pub(crate) const PYTEST_UNSAFE_ENV_KEYS: &[&str] = &[
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONUSERBASE",
];
pub(crate) const PYTHON_INTERPRETER_OPTIONS_WITH_VALUES: &[&str] =
    &["--check-hash-based-pycs", "-W", "-X"];
pub(crate) const PYTHON_MODULE_MUTATING_FLAGS: &[(&str, &[&str])] = &[
    ("mypy", &["--install-types"]),
    ("pytest", &["--basetemp", "--debug", "--junitxml"]),
    ("ruff", &["--add-noqa"]),
];
pub(crate) const PYTHON_MODULE_MUTATING_SUBCOMMANDS: &[(&str, &[&str])] = &[("ruff", &["format"])];
pub(crate) const PYTHON_MODULE_OPTIONS_WITH_VALUES: &[(&str, &[&str])] =
    &[("ruff", &["--cache-dir", "--color", "--config"])];
pub(crate) const READ_ONLY_LOOKUP_COMMANDS: &[&str] = &[
    "cat", "date", "egrep", "fd", "fgrep", "find", "grep", "head", "ls", "pwd", "rg", "sed", "tail",
];
pub(crate) const READ_ONLY_LOOKUP_FILTERS: &[&str] =
    &["cat", "egrep", "fgrep", "grep", "head", "rg", "sed", "tail"];
pub(crate) const READ_ONLY_SEARCH_EXECUTION_FLAGS: &[(&str, &[&str])] = &[(
    "rg",
    &["--config-path", "--hostname-bin", "--pre", "--pre-glob"],
)];
pub(crate) const SAFE_PYTHON_MODULE_COMMANDS: &[&str] = &["pytest", "ruff"];
pub(crate) const SAFE_PYTHON_MODULE_SHADOW_PATHS: &[(&str, &[&str])] = &[
    (
        "pytest",
        &[
            "pytest.py",
            "pytest.pyc",
            "pytest/__init__.py",
            "pytest/__init__.pyc",
            "pytest/__main__.py",
            "pytest/__main__.pyc",
        ],
    ),
    (
        "ruff",
        &[
            "ruff.py",
            "ruff.pyc",
            "ruff/__init__.py",
            "ruff/__init__.pyc",
            "ruff/__main__.py",
            "ruff/__main__.pyc",
        ],
    ),
];
pub(crate) const SAFE_SHELL_REDIRECT_TARGETS: &[&str] =
    &["/dev/null", "/dev/stderr", "/dev/stdout", "nul"];
pub(crate) const SAFE_STATIC_SHELL_COMMANDS: &[&str] = &["echo", "printf", "true"];
pub(crate) const SHELL_COMMAND_STRING_INTERPRETERS: &[&str] = &["ash", "bash", "dash", "sh", "zsh"];
pub(crate) const SHELL_CONTROL_PREFIX_TOKENS: &[&str] = &[
    "!", "(", "case", "do", "elif", "else", "for", "if", "select", "then", "until", "while", "{",
];
pub(crate) const SHELL_SCRIPT_INTERPRETER_COMMANDS: &[&str] =
    &[".", "ash", "bash", "dash", "sh", "source", "zsh"];
pub(crate) const SHELL_STARTUP_ENV_KEYS: &[&str] = &["BASH_ENV", "ENV", "ZDOTDIR"];
pub(crate) const SHELL_TOOL_NAMES: &[&str] = &[
    "ash",
    "bash",
    "cmd",
    "dash",
    "powershell",
    "pwsh",
    "run_command",
    "run_terminal_command",
    "sh",
    "shell",
    "terminal",
    "zsh",
];
pub(crate) const SUDO_OPTION_VALUE_FLAGS: &[&str] =
    &["-C", "-D", "-R", "-T", "-g", "-h", "-p", "-r", "-t", "-u"];
pub(crate) const SUDO_OPTION_VALUE_LONG_FLAGS: &[&str] = &[
    "--chdir",
    "--chroot",
    "--close-from",
    "--command-timeout",
    "--group",
    "--host",
    "--login-class",
    "--prompt",
    "--role",
    "--type",
    "--user",
];
pub(crate) const TRUSTED_INTERPRETER_INSTALL_ROOTS: &[&str] = &[
    "/home/linuxbrew/.linuxbrew",
    "/opt/homebrew",
    "/opt/hostedtoolcache/Python",
    "/usr/local",
];
pub(crate) const UNMODELED_INLINE_INTERPRETER_COMMANDS: &[&str] = &["perl", "ruby"];
