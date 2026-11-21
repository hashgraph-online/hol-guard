//! Shared request-classification patterns and option sets (`constants_patterns.py`).
//! Generated from the retired Python tables; keep in step with the vectors.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::hook_adapter_pytext::compile_fancy;

pub(crate) const BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS: &[&str] =
    &["cat", "curl", "echo", "printf", "sed", "tr", "wget"];
pub(crate) const CURL_AT_FILE_FLAGS_WITH_VALUE: &[&str] =
    &["--data", "--data-ascii", "--data-binary", "--json", "-d"];
pub(crate) const CURL_CONFIG_FLAGS_WITH_VALUE: &[&str] = &["--config", "-K"];
pub(crate) const CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE: &[&str] = &[
    "--data-raw",
    "--header",
    "--proxy-user",
    "--request",
    "--user",
];
pub(crate) const CURL_DATA_URLENCODE_FLAGS_WITH_VALUE: &[&str] =
    &["--data-urlencode", "--url-query"];
pub(crate) const CURL_DIRECT_FILE_FLAGS_WITH_VALUE: &[&str] = &["--upload-file", "-T"];
pub(crate) const CURL_EXPAND_FLAGS_WITH_VALUE: &[&str] = &[
    "--expand-data",
    "--expand-header",
    "--expand-url",
    "--expand-user",
    "--expand-variable",
];
pub(crate) const CURL_FORM_FLAGS_WITH_VALUE: &[&str] = &["--form", "-F"];
pub(crate) const CURL_SHORT_FLAGS_WITH_VALUES: &[&str] = &[
    "A", "C", "D", "E", "F", "H", "K", "P", "Q", "T", "U", "X", "Y", "b", "c", "d", "e", "h", "m",
    "o", "r", "t", "u", "w", "x", "y", "z",
];
pub(crate) const CURL_VARIABLE_FLAGS_WITH_VALUE: &[&str] = &["--variable"];
pub(crate) const DESTRUCTIVE_GIT_SUBCOMMANDS: &[&str] = &["clean", "reset", "restore", "rm"];
pub(crate) const DESTRUCTIVE_NODE_INLINE_CALLS: &[&str] = &[
    "appendFile",
    "appendFileSync",
    "chmod",
    "chmodSync",
    "chown",
    "chownSync",
    "copyFile",
    "copyFileSync",
    "mkdir",
    "mkdirSync",
    "rename",
    "renameSync",
    "rm",
    "rmSync",
    "truncate",
    "truncateSync",
    "unlink",
    "unlinkSync",
    "writeFile",
    "writeFileSync",
];
pub(crate) const ENCODED_EXECUTION_TARGET_PATTERN: &str = r#"(?:(?:[A-Za-z0-9_./~-]+/)?env(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b"#;
pub(crate) const FIND_PATH_VALUE_PREDICATES: &[&str] = &[
    "-ilname",
    "-iname",
    "-ipath",
    "-iregex",
    "-iwholename",
    "-lname",
    "-name",
    "-path",
    "-regex",
    "-wholename",
];
pub(crate) const GIT_GLOBAL_OPTIONS_WITH_VALUE: &[&str] = &[
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
    "-C",
    "-c",
];
pub(crate) static HEREDOC_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"<<-?\s*(['\"]?)([^\s'\";|&<>]+)\1"#));
pub(crate) const NODE_INLINE_EVAL_FLAGS: &[&str] = &["--eval", "--print", "-e", "-p"];
pub(crate) static NODE_LOCAL_FILE_ACCESS_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?i)\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream)\s*\(|\[\s*['\"](?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream)['\"]\s*\]"#,
    )
});
pub(crate) static NODE_MUTATING_HTTP_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?i)\b(?:POST|PUT|PATCH|DELETE)\b|\bmethod\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|\b(?:body|data)\s*:"#,
    )
});
pub(crate) const NODE_OPTION_FLAGS_WITH_VALUE: &[&str] = &[
    "--conditions",
    "--debug-port",
    "--experimental-loader",
    "--import",
    "--input-type",
    "--inspect-port",
    "--loader",
    "--redirect-warnings",
    "--require",
    "--title",
    "-r",
];
pub(crate) static NODE_READ_ONLY_HTTP_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"(?i)\b(?:fetch|https?\.get)\s*\("#));
pub(crate) static NODE_SENSITIVE_RUNTIME_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?i)\b(?:process|globalThis)\b|\bprocess\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])|\bglobal\s*(?:\.\s*process|\[\s*['\"`](?:process|p['\"`]\s*\+\s*['\"`]rocess|pr['\"`]\s*\+\s*['\"`]ocess|pro['\"`]\s*\+\s*['\"`]cess|proc['\"`]\s*\+\s*['\"`]ess|proce['\"`]\s*\+\s*['\"`]ss|proces['\"`]\s*\+\s*['\"`]s)['\"`]\s*\])\s*(?:\.\s*env|\[\s*['\"`](?:env|e['\"`]\s*\+\s*['\"`]nv|en['\"`]\s*\+\s*['\"`]v)['\"`]\s*\])|\b(?:import|require|createRequire)\b|\brequire\s*\(\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]\s*\)|\bimport\s*\(\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]\s*\)|\bimport\b[\s\S]{0,200}\bfrom\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]|\b(?:exec|execFile|execFileSync|execSync|spawn|spawnSync|fork|eval|Function)\s*\("#,
    )
});
pub(crate) const PYTEST_COMMAND_NAMES: &[&str] =
    &["py.test", "py.test.exe", "pytest", "pytest.exe"];
pub(crate) const PYTEST_COMMAND_RUNNER_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("conda", &["run"]),
    ("direnv", &["exec"]),
    ("hatch", &["run"]),
    ("mise", &["exec", "x"]),
    ("pdm", &["run"]),
    ("pipenv", &["run"]),
    ("pipx", &["run"]),
    ("pixi", &["run"]),
    ("poetry", &["run"]),
    ("rye", &["run"]),
    ("uv", &["run"]),
];
pub(crate) const PYTEST_EXECUTOR_COMMANDS: &[&str] = &["parallel", "watch", "xargs"];
pub(crate) const PYTEST_RUNNER_OPTIONS_WITH_VALUES: &[(&str, &[&str])] = &[
    ("conda", &["--cwd", "--name", "--prefix"]),
    ("hatch", &["--env", "--project"]),
    ("mise", &["--cwd", "--env", "--jobs"]),
    ("pdm", &["--config", "--project", "--site-packages"]),
    ("pipenv", &["--categories", "--extra-pip-args", "--python"]),
    ("pipx", &["--index-url", "--pip-args", "--suffix", "--with"]),
    ("pixi", &["--environment", "--manifest-path"]),
    ("poetry", &["--directory", "--project"]),
    ("rye", &["--pyproject"]),
    (
        "uv",
        &[
            "--cache-dir",
            "--color",
            "--config-file",
            "--config-settings",
            "--default-index",
            "--directory",
            "--env-file",
            "--extra",
            "--find-links",
            "--group",
            "--index",
            "--index-strategy",
            "--index-url",
            "--keyring-provider",
            "--package",
            "--project",
            "--python",
            "--with",
            "--with-editable",
            "--with-requirements",
            "-f",
            "-p",
            "-w",
        ],
    ),
];
pub(crate) const PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS: &[(&str, usize)] = &[("direnv", 1)];
pub(crate) static READ_ONLY_INTERPRETER_MUTATION_PATTERNS: LazyLock<Vec<FancyRegex>> =
    LazyLock::new(|| {
        vec![
            compile_fancy(r#"(?i)\bwrite_(?:text|bytes)\s*\("#),
            compile_fancy(r#"(?i)\bunlink\b"#),
            compile_fancy(
                r#"(?i)\b(?:unlink|rmdir|remove|removedirs|rename|replace|chmod|chown|mkdir|makedirs|truncate)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\b(?:copy|copy2|copyfile|copyfileobj|copytree|move|rmtree|symlink|link)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\bopen\s*\([^)]*(?:,\s*['\"][^'\"]*[wax+][^'\"]*['\"]|\bmode\s*=\s*['\"][^'\"]*[wax+][^'\"]*['\"])"#,
            ),
            compile_fancy(r#"(?i)\.\s*open\s*\(\s*['\"][^'\"]*[wax+][^'\"]*['\"]"#),
            compile_fancy(
                r#"(?i)\b(?:fdopen|os\.fdopen)\s*\([^)]*,\s*['\"][^'\"]*[wax+][^'\"]*['\"]"#,
            ),
            compile_fancy(
                r#"(?i)\bos\.open\s*\([^)]*\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b"#,
            ),
            compile_fancy(r#"(?i)\bos\.write\s*\("#),
            compile_fancy(r#"(?i)\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\("#),
            compile_fancy(
                r#"(?i)\b(?:os\.system|subprocess\.(?:run|popen|call|check_call|check_output)|run|popen|call|check_call|check_output|system)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\bpath\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*path\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\b[\s;]+(?P=alias)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\("#,
            ),
            compile_fancy(
                r#"(?i)\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*path\s*\([^)]*\)\s*\.\s*open\b[\s;]+(?P=alias)\s*\(\s*['\"][^'\"]*[wax+][^'\"]*['\"]"#,
            ),
        ]
    });
pub(crate) const SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN: &str = r#"(?:cd\b[^\n;&|<>$`]*)"#;
pub(crate) const SAFE_NODE_GENERATED_FILE_EXTENSIONS: &[&str] =
    &[".csv", ".json", ".jsonl", ".md", ".txt"];
pub(crate) const SAFE_NODE_GENERATED_FILE_ROOTS: &[&str] =
    &["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"];
pub(crate) static SHELL_ASSIGNMENT_PATTERN: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r#"^[A-Za-z_][A-Za-z0-9_]*(?:\+)?=.*"#));
pub(crate) const SHELL_COMMAND_SEPARATORS: &[&str] = &["&", "&&", ";", "|", "|&", "||"];
pub(crate) const SHELL_COMMAND_WRAPPERS: &[&str] = &[
    "builtin", "command", "env", "exec", "nice", "nohup", "stdbuf", "sudo", "time",
];
pub(crate) const SHELL_LOCAL_READ_COMMANDS: &[&str] =
    &["cat", "egrep", "fgrep", "grep", "head", "rg", "sed", "tail"];
pub(crate) const SHELL_NETWORK_SINK_COMMANDS: &[&str] = &[
    "curl", "nc", "ncat", "netcat", "rsync", "scp", "ssh", "wget",
];
pub(crate) const SHELL_NEWLINE_SEPARATOR: &str = r#";"#;
pub(crate) static SINGLE_INTERPRETER_HEREDOC_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?is)^\s*(?:(?:(?:cd\b[^\n;&|<>$`]*))\s*&&\s*)*(?P<interpreter>[^\s;&|<>$`]*(?:perl|pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?|ruby))\b(?P<args>[^\n;&|]*)<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\";|&<>]+)(?P=quote)\s*\n(?P<body>.*)\n(?P=tag)\s*$"#,
    )
});
pub(crate) static SINGLE_NODE_HEREDOC_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?is)^\s*(?:(?:(?:cd\b[^\n;&|<>$`]*))\s*&&\s*)*node\b(?P<args>[^\n;&|]*)<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\";|&<>]+)(?P=quote)\s*\n(?P<body>.*)\n(?P=tag)\s*$"#,
    )
});
pub(crate) const WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE: &[&str] = &[
    "--body-data",
    "--header",
    "--method",
    "--password",
    "--post-data",
    "--user",
];
pub(crate) const WGET_UPLOAD_FLAGS_WITH_VALUE: &[&str] = &["--body-file", "--post-file"];
pub(crate) const WRAPPER_FLAGS_WITH_VALUES: &[(&str, &[&str])] = &[
    ("exec", &["-a"]),
    ("nice", &["--adjustment", "-n"]),
    (
        "stdbuf",
        &["--error", "--input", "--output", "-e", "-i", "-o"],
    ),
    (
        "sudo",
        &[
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--user",
            "-C",
            "-D",
            "-R",
            "-T",
            "-g",
            "-h",
            "-p",
            "-r",
            "-t",
            "-u",
        ],
    ),
    ("time", &["--format", "--output", "-f", "-o"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        LazyLock::force(&HEREDOC_PATTERN);
        LazyLock::force(&NODE_LOCAL_FILE_ACCESS_PATTERN);
        LazyLock::force(&NODE_MUTATING_HTTP_PATTERN);
        LazyLock::force(&NODE_READ_ONLY_HTTP_PATTERN);
        LazyLock::force(&NODE_SENSITIVE_RUNTIME_PATTERN);
        LazyLock::force(&READ_ONLY_INTERPRETER_MUTATION_PATTERNS);
        LazyLock::force(&SHELL_ASSIGNMENT_PATTERN);
        LazyLock::force(&SINGLE_INTERPRETER_HEREDOC_PATTERN);
        LazyLock::force(&SINGLE_NODE_HEREDOC_PATTERN);
    }
}
