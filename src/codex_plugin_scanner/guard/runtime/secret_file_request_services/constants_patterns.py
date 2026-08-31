"""Shared regular expressions and option sets for request classification."""

from __future__ import annotations

import re

_FIND_PATH_VALUE_PREDICATES = frozenset(
    {
        "-ilname",
        "-iname",
        "-iwholename",
        "-ipath",
        "-iregex",
        "-lname",
        "-name",
        "-path",
        "-regex",
        "-wholename",
    }
)

_NODE_INLINE_EVAL_FLAGS = frozenset({"-e", "--eval", "-p", "--print"})

_NODE_OPTION_FLAGS_WITH_VALUE = frozenset(
    {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--input-type",
        "--conditions",
        "--debug-port",
        "--inspect-port",
        "--redirect-warnings",
        "--title",
    }
)

_CURL_AT_FILE_FLAGS_WITH_VALUE = frozenset({"--data", "--data-ascii", "--data-binary", "--json", "-d"})

_CURL_CONFIG_FLAGS_WITH_VALUE = frozenset({"--config", "-K"})

_CURL_DATA_URLENCODE_FLAGS_WITH_VALUE = frozenset({"--data-urlencode", "--url-query"})

_CURL_EXPAND_FLAGS_WITH_VALUE = frozenset(
    {"--expand-data", "--expand-header", "--expand-url", "--expand-user", "--expand-variable"}
)

_CURL_FORM_FLAGS_WITH_VALUE = frozenset({"--form", "-F"})

_CURL_DIRECT_FILE_FLAGS_WITH_VALUE = frozenset({"--upload-file", "-T"})

_CURL_VARIABLE_FLAGS_WITH_VALUE = frozenset({"--variable"})

_CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE = frozenset(
    {"--data-raw", "--header", "--proxy-user", "--request", "--user"}
)

_CURL_SHORT_FLAGS_WITH_VALUES = frozenset(
    {
        "A",
        "b",
        "C",
        "c",
        "d",
        "D",
        "e",
        "E",
        "F",
        "H",
        "h",
        "K",
        "m",
        "o",
        "P",
        "Q",
        "r",
        "t",
        "T",
        "u",
        "U",
        "w",
        "x",
        "X",
        "y",
        "Y",
        "z",
    }
)

_WGET_UPLOAD_FLAGS_WITH_VALUE = frozenset({"--body-file", "--post-file"})

_WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE = frozenset(
    {"--body-data", "--header", "--method", "--password", "--post-data", "--user"}
)

_SHELL_COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "|", "&", "|&"})

_SHELL_COMMAND_WRAPPERS = frozenset({"builtin", "command", "env", "exec", "nice", "nohup", "stdbuf", "sudo", "time"})

_PYTEST_COMMAND_NAMES = frozenset({"py.test", "py.test.exe", "pytest", "pytest.exe"})

_PYTEST_COMMAND_RUNNER_SUBCOMMANDS = {
    "conda": frozenset({"run"}),
    "direnv": frozenset({"exec"}),
    "hatch": frozenset({"run"}),
    "mise": frozenset({"exec", "x"}),
    "pdm": frozenset({"run"}),
    "pipenv": frozenset({"run"}),
    "pipx": frozenset({"run"}),
    "pixi": frozenset({"run"}),
    "poetry": frozenset({"run"}),
    "rye": frozenset({"run"}),
    "uv": frozenset({"run"}),
}

_PYTEST_RUNNER_OPTIONS_WITH_VALUES = {
    "conda": frozenset({"--cwd", "--name", "--prefix"}),
    "hatch": frozenset({"--env", "--project"}),
    "mise": frozenset({"--cwd", "--env", "--jobs"}),
    "pdm": frozenset({"--config", "--project", "--site-packages"}),
    "pipenv": frozenset({"--categories", "--extra-pip-args", "--python"}),
    "pipx": frozenset({"--index-url", "--pip-args", "--suffix", "--with"}),
    "pixi": frozenset({"--environment", "--manifest-path"}),
    "poetry": frozenset({"--directory", "--project"}),
    "rye": frozenset({"--pyproject"}),
    "uv": frozenset(
        {
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
        }
    ),
}

_PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS = {"direnv": 1}

_PYTEST_EXECUTOR_COMMANDS = frozenset({"parallel", "watch", "xargs"})

_BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS = frozenset({"cat", "curl", "echo", "printf", "sed", "tr", "wget"})

_SHELL_NETWORK_SINK_COMMANDS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "scp", "rsync", "ssh"})

_SHELL_LOCAL_READ_COMMANDS = frozenset({"cat", "grep", "egrep", "fgrep", "head", "rg", "sed", "tail"})

_SHELL_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\+)?=.*")

_SHELL_NEWLINE_SEPARATOR = ";"

_HEREDOC_PATTERN = re.compile(r"<<-?\s*(['\"]?)([^\s'\";|&<>]+)\1")

_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN = r"(?:cd\b[^\n;&|<>$`]*)"

_SINGLE_INTERPRETER_HEREDOC_PATTERN = re.compile(
    rf"^\s*(?:(?:{_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN})\s*&&\s*)*(?P<interpreter>[^\s;&|<>$`]*(?:perl|pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?|ruby))\b(?P<args>[^\n;&|]*)<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\";|&<>]+)(?P=quote)\s*\n(?P<body>.*)\n(?P=tag)\s*$",
    re.IGNORECASE | re.DOTALL,
)

_SINGLE_NODE_HEREDOC_PATTERN = re.compile(
    rf"^\s*(?:(?:{_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN})\s*&&\s*)*node\b(?P<args>[^\n;&|]*)<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\";|&<>]+)(?P=quote)\s*\n(?P<body>.*)\n(?P=tag)\s*$",
    re.IGNORECASE | re.DOTALL,
)

_DESTRUCTIVE_NODE_INLINE_CALLS = frozenset(
    {
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
    }
)

_NODE_READ_ONLY_HTTP_PATTERN = re.compile(r"\b(?:fetch|https?\.get)\s*\(", re.IGNORECASE)

_NODE_MUTATING_HTTP_PATTERN = re.compile(
    r"\b(?:POST|PUT|PATCH|DELETE)\b|"
    r"\bmethod\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|"
    r"\b(?:body|data)\s*:",
    re.IGNORECASE,
)

_NODE_LOCAL_FILE_ACCESS_PATTERN = re.compile(
    r"\b(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|"
    r"createReadStream|createWriteStream)\s*\(|"
    r"\[\s*['\"](?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|"
    r"createReadStream|createWriteStream)['\"]\s*\]",
    re.IGNORECASE,
)

_NODE_SENSITIVE_RUNTIME_PATTERN = re.compile(
    r"\b(?:process|globalThis)\b|"
    r"\bprocess\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])|"
    r"\bglobal\s*(?:\.\s*process|\[\s*['\"`](?:process|p['\"`]\s*\+\s*['\"`]rocess|pr['\"`]\s*\+\s*['\"`]ocess|"
    r"pro['\"`]\s*\+\s*['\"`]cess|proc['\"`]\s*\+\s*['\"`]ess|proce['\"`]\s*\+\s*['\"`]ss|proces['\"`]\s*\+\s*['\"`]s)"
    r"['\"`]\s*\])\s*(?:\.\s*env|\[\s*['\"`](?:env|e['\"`]\s*\+\s*['\"`]nv|en['\"`]\s*\+\s*['\"`]v)['\"`]\s*\])|"
    r"\b(?:import|require|createRequire)\b|"
    r"\brequire\s*\(\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]\s*\)|"
    r"\bimport\s*\(\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]\s*\)|"
    r"\bimport\b[\s\S]{0,200}\bfrom\s*['\"](?:node:)?(?:child_process|fs|fs/promises)['\"]|"
    r"\b(?:exec|execFile|execFileSync|execSync|spawn|spawnSync|fork|eval|Function)\s*\(",
    re.IGNORECASE,
)

_SAFE_NODE_GENERATED_FILE_EXTENSIONS = frozenset({".csv", ".json", ".jsonl", ".md", ".txt"})

_SAFE_NODE_GENERATED_FILE_ROOTS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/")

_DESTRUCTIVE_GIT_SUBCOMMANDS = frozenset({"clean", "reset", "restore", "rm"})

_READ_ONLY_INTERPRETER_MUTATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bwrite_(?:text|bytes)\s*\(", re.IGNORECASE),
    re.compile(r"\bunlink\b", re.IGNORECASE),
    re.compile(
        r"\b(?:unlink|rmdir|remove|removedirs|rename|replace|chmod|chown|mkdir|makedirs|truncate)\s*\(", re.IGNORECASE
    ),
    re.compile(r"\b(?:copy|copy2|copyfile|copyfileobj|copytree|move|rmtree|symlink|link)\s*\(", re.IGNORECASE),
    re.compile(
        r"\bopen\s*\([^)]*(?:,\s*['\"][^'\"]*[wax+][^'\"]*['\"]|\bmode\s*=\s*['\"][^'\"]*[wax+][^'\"]*['\"])",
        re.IGNORECASE,
    ),
    re.compile(r"\.\s*open\s*\(\s*['\"][^'\"]*[wax+][^'\"]*['\"]", re.IGNORECASE),
    re.compile(r"\b(?:fdopen|os\.fdopen)\s*\([^)]*,\s*['\"][^'\"]*[wax+][^'\"]*['\"]", re.IGNORECASE),
    re.compile(r"\bos\.open\s*\([^)]*\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b", re.IGNORECASE),
    re.compile(r"\bos\.write\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\(", re.IGNORECASE),
    re.compile(
        r"\b(?:os\.system|subprocess\.(?:run|popen|call|check_call|check_output)|run|popen|call|check_call|check_output|system)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bpath\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*path\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\b[\s;]+(?P=alias)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*path\s*\([^)]*\)\s*\.\s*open\b[\s;]+(?P=alias)\s*\(\s*['\"][^'\"]*[wax+][^'\"]*['\"]",
        re.IGNORECASE,
    ),
)

_GIT_GLOBAL_OPTIONS_WITH_VALUE = frozenset(
    {
        "-C",
        "-c",
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    }
)

_WRAPPER_FLAGS_WITH_VALUES = {
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
    "sudo": frozenset(
        {
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
        }
    ),
    "time": frozenset({"-f", "--format", "-o", "--output"}),
}

_ENCODED_EXECUTION_TARGET_PATTERN = (
    r"(?:(?:[A-Za-z0-9_./~-]+/)?env"
    r"(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?"
    r"(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b"
)

__all__ = [
    "_BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS",
    "_CURL_AT_FILE_FLAGS_WITH_VALUE",
    "_CURL_CONFIG_FLAGS_WITH_VALUE",
    "_CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE",
    "_CURL_DATA_URLENCODE_FLAGS_WITH_VALUE",
    "_CURL_DIRECT_FILE_FLAGS_WITH_VALUE",
    "_CURL_EXPAND_FLAGS_WITH_VALUE",
    "_CURL_FORM_FLAGS_WITH_VALUE",
    "_CURL_SHORT_FLAGS_WITH_VALUES",
    "_CURL_VARIABLE_FLAGS_WITH_VALUE",
    "_DESTRUCTIVE_GIT_SUBCOMMANDS",
    "_DESTRUCTIVE_NODE_INLINE_CALLS",
    "_ENCODED_EXECUTION_TARGET_PATTERN",
    "_FIND_PATH_VALUE_PREDICATES",
    "_GIT_GLOBAL_OPTIONS_WITH_VALUE",
    "_HEREDOC_PATTERN",
    "_NODE_INLINE_EVAL_FLAGS",
    "_NODE_LOCAL_FILE_ACCESS_PATTERN",
    "_NODE_MUTATING_HTTP_PATTERN",
    "_NODE_OPTION_FLAGS_WITH_VALUE",
    "_NODE_READ_ONLY_HTTP_PATTERN",
    "_NODE_SENSITIVE_RUNTIME_PATTERN",
    "_PYTEST_COMMAND_NAMES",
    "_PYTEST_COMMAND_RUNNER_SUBCOMMANDS",
    "_PYTEST_EXECUTOR_COMMANDS",
    "_PYTEST_RUNNER_OPTIONS_WITH_VALUES",
    "_PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS",
    "_READ_ONLY_INTERPRETER_MUTATION_PATTERNS",
    "_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN",
    "_SAFE_NODE_GENERATED_FILE_EXTENSIONS",
    "_SAFE_NODE_GENERATED_FILE_ROOTS",
    "_SHELL_ASSIGNMENT_PATTERN",
    "_SHELL_COMMAND_SEPARATORS",
    "_SHELL_COMMAND_WRAPPERS",
    "_SHELL_LOCAL_READ_COMMANDS",
    "_SHELL_NETWORK_SINK_COMMANDS",
    "_SHELL_NEWLINE_SEPARATOR",
    "_SINGLE_INTERPRETER_HEREDOC_PATTERN",
    "_SINGLE_NODE_HEREDOC_PATTERN",
    "_WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE",
    "_WGET_UPLOAD_FLAGS_WITH_VALUE",
    "_WRAPPER_FLAGS_WITH_VALUES",
]
