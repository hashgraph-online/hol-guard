"""Classify sensitive runtime file-read requests without touching the filesystem."""

from __future__ import annotations

import ast
import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from ..models import GuardArtifact
from .actions import GuardActionEnvelope, apply_patch_target_paths
from .approval_context import build_runtime_executable_identity
from .command_decision_adapter import effect_decision_to_dict
from .command_evaluation import evaluate_command
from .command_extension_interaction import classify_command_extension_interaction
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .command_model import CanonicalCommand, parse_shell_command
from .data_flow import extract_heredocs
from .env_wrapper import parse_env_wrapper
from .extension_control_contract import ExtensionControlLayer
from .false_positive_rules import (
    SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS,
    SOURCE_INSPECTION_PARTS,
    SOURCE_INSPECTION_SENSITIVE_PARTS,
    fd_arg_requests_exec,
    fd_args_follow_symlinks,
    fd_exec_token_is_plain_sed,
    fd_search_targets,
    split_fd_args_and_exec,
    target_is_known_skill_doc_path,
)
from .github_capability_contract import GitHubCommandAssessment
from .github_capability_interaction import (
    github_capability_action_class,
    github_capability_requires_confirmation,
)
from .github_shell_capabilities import GitHubShellAnalysis
from .github_shell_capabilities import classify_github_shell_capabilities as _classify_github_shell_capabilities
from .interpreter_options import shell_interpreter_command_payload as _shell_interpreter_command_payload
from .kubernetes_commands import kubernetes_secret_read_source
from .pytest_config import (
    PYTEST_CONFIG_PATH_INVALID,
    PytestConfigAssessment,
    assess_pytest_configs,
    assess_selected_pytest_config,
    combine_pytest_config_assessments,
)
from .restricted_pytest import PYTEST_RESTRICTED_PROFILE_VERSION
from .secret_sensitivity import SecretPathMatch as SensitivePathMatch
from .secret_sensitivity import classify_secret_path
from .sed_scripts import sed_script_is_bounded_print
from .self_approval import (
    SELF_APPROVAL_ACTION_CLASS,
    SELF_APPROVAL_REASON,
    is_guard_approval_mutation_command,
)
from .shell_command_wrappers import is_trusted_absolute_command_path, normalize_transparent_shell_command
from .shell_execution_context import (
    SHELL_CWD_WORKSPACE_ESCAPE,
    ShellExecutionContext,
    model_shell_execution_context,
    validate_shell_execution_segment,
)

_FILE_READ_TOOL_NAMES = frozenset(
    {
        "read",
        "read_file",
        "open_file",
        "view",
        "view_file",
        "cat_file",
    }
)
_FILE_WRITE_TOOL_NAMES = frozenset(
    {
        "edit",
        "edit_file",
        "multiedit",
        "write",
        "write_file",
        "apply_patch",
    }
)
_PATH_KEYS = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
    "target_path",
    "targetPath",
)
_PATH_LIST_KEYS = ("paths", "file_paths", "filePaths")
_COMMAND_KEYS = (
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
)
_SUDO_OPTION_VALUE_FLAGS = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-r", "-T", "-t"})
_SUDO_OPTION_VALUE_LONG_FLAGS = frozenset(
    {
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
    }
)
_GH_PR_OPTION_VALUE_FLAGS = frozenset({"-R", "--repo"})
_SHELL_CONTROL_PREFIX_TOKENS = frozenset(
    {"!", "(", "{", "case", "do", "elif", "else", "for", "if", "select", "then", "until", "while"}
)
COMMAND_LIST_KEYS = ("argv", "command_args", "commandArgs")
COMMAND_SEQUENCE_KEYS = ("commands",)
COMMAND_CANDIDATE_LIST_KEYS = (*COMMAND_LIST_KEYS, *COMMAND_SEQUENCE_KEYS)
_COMMAND_LIST_KEYS = COMMAND_LIST_KEYS
_DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS = frozenset({"login", "push", "run"})
_DOCKER_BUILD_SUBCOMMANDS = frozenset({"build"})
_DOCKER_BUILDX_BUILD_SUBCOMMANDS = frozenset({"b", "build"})
_DOCKER_BUILD_SECRET_FLAGS = frozenset({"--allow", "--secret", "--ssh"})
_DOCKER_BUILD_OUTPUT_FLAGS = frozenset(
    {"--cache-to", "--iidfile", "--load", "--metadata-file", "--output", "--push", "-o"}
)
_DOCKER_BUILD_METADATA_FLAGS = frozenset({"--annotation", "--label"})
_DOCKER_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--config",
        "--context",
        "--host",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
        "-c",
        "-H",
        "-l",
    }
)
_DOCKER_GLOBAL_FLAG_OPTIONS = frozenset({"--debug", "--tls", "--tlsverify"})
# Docker global options that point Compose at a non-default/remotable control plane
# or credential material; any non-default value keeps a Compose command sensitive.
_DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS = frozenset(
    {"--config", "--context", "--host", "--tlscacert", "--tlscert", "--tlskey", "-c", "-H"}
)
# Docker global flag options (no value) that signal a non-default/TLS control plane.
_DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS = frozenset({"--tls", "--tlsverify"})
_DOCKER_SENSITIVE_CONTEXT_ENV_KEYS = frozenset(
    {
        "COMPOSE_ENV_FILES",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
    }
)
_DOCKER_COMPOSE_SUBCOMMAND = "compose"
_DOCKER_COMPOSE_OPTIONS_WITH_VALUES = frozenset(
    {
        "--ansi",
        "--env-file",
        "--file",
        "--parallel",
        "--profile",
        "--profiles",
        "--project-directory",
        "--project-name",
        "--progress",
        "-f",
        "-p",
    }
)
_DOCKER_COMPOSE_FLAG_OPTIONS = frozenset(
    {"--all-resources", "--compatibility", "--dry-run", "--no-ansi", "--no-interpolate", "--verbose", "--volumes", "-q"}
)
_DOCKER_COMPOSE_SAFE_SUBCOMMANDS = frozenset(
    {
        "build",
        "config",
        "create",
        "down",
        "events",
        "images",
        "logs",
        "ls",
        "pause",
        "port",
        "ps",
        "pull",
        "restart",
        "rm",
        "start",
        "stop",
        "top",
        "unpause",
        "up",
        "version",
        "wait",
    }
)
_DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS = frozenset({"cp", "exec", "publish", "push", "run", "watch"})
_DOCKER_BUILDX_OPTIONS_WITH_VALUES = frozenset({"--builder"})
_DOCKER_BUILDX_FLAG_OPTIONS = frozenset({"--debug"})
_DOCKER_BUILD_ARG_SECRET_MARKERS = frozenset(
    {"API", "AUTH", "AWS", "CREDENTIAL", "KEY", "NPM", "PASSWORD", "SECRET", "TOKEN"}
)
_DOCKER_BUILD_ARG_TOKEN_PREFIXES = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
)
_SAFE_PYTHON_MODULE_COMMANDS = frozenset({"pytest", "ruff"})
_TRUSTED_INTERPRETER_INSTALL_ROOTS = (
    Path("/home/linuxbrew/.linuxbrew"),
    Path("/opt/homebrew"),
    Path("/opt/hostedtoolcache/Python"),
    Path("/usr/local"),
)
_SAFE_PYTHON_MODULE_SHADOW_PATHS = {
    "pytest": (
        "pytest.py",
        "pytest.pyc",
        "pytest/__init__.py",
        "pytest/__init__.pyc",
        "pytest/__main__.py",
        "pytest/__main__.pyc",
    ),
    "ruff": (
        "ruff.py",
        "ruff.pyc",
        "ruff/__init__.py",
        "ruff/__init__.pyc",
        "ruff/__main__.py",
        "ruff/__main__.pyc",
    ),
}
_PYTEST_OPTION_CONFIG_PATHS = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)
_PYTEST_UNSAFE_ENV_KEYS = frozenset({"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE"})
_SHELL_STARTUP_ENV_KEYS = frozenset({"BASH_ENV", "ENV", "ZDOTDIR"})
_PYTEST_SAFE_FLAGS_WITH_VALUES = frozenset({"-k", "-m", "--maxfail", "--tb"})
_PYTEST_SAFE_FLAGS = frozenset({"-q", "-s", "-v", "-x", "--disable-warnings", "--quiet", "--verbose"})
_PYTHON_INTERPRETER_OPTIONS_WITH_VALUES = frozenset({"--check-hash-based-pycs", "-W", "-X"})
_PYTHON_MODULE_MUTATING_FLAGS = {
    "mypy": frozenset({"--install-types"}),
    "pytest": frozenset({"--basetemp", "--debug", "--junitxml"}),
    "ruff": frozenset({"--add-noqa"}),
}
_PYTHON_MODULE_MUTATING_SUBCOMMANDS = {
    "ruff": frozenset({"format"}),
}
_PYTHON_MODULE_OPTIONS_WITH_VALUES = {
    "ruff": frozenset({"--cache-dir", "--color", "--config"}),
}
_SAFE_STATIC_SHELL_COMMANDS = frozenset({"echo", "printf"})
_SHELL_TOOL_NAMES = frozenset(
    {
        "ash",
        "bash",
        "cmd",
        "dash",
        "powershell",
        "pwsh",
        "run_command",
        "run_terminal_command",
        "shell",
        "sh",
        "terminal",
        "zsh",
    }
)
_SHELL_SCRIPT_INTERPRETER_COMMANDS = frozenset({"ash", "bash", "dash", "sh", "zsh", ".", "source"})
_SHELL_COMMAND_STRING_INTERPRETERS = frozenset({"ash", "bash", "dash", "sh", "zsh"})
_DESTRUCTIVE_SHELL_COMMANDS = frozenset(
    {
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
    }
)
_UNMODELED_INLINE_INTERPRETER_COMMANDS = frozenset({"perl", "ruby"})
_SAFE_SHELL_REDIRECT_TARGETS = frozenset(
    {
        "/dev/null",
        "/dev/stdout",
        "/dev/stderr",
        "nul",
    }
)
_READ_ONLY_LOOKUP_COMMANDS = frozenset(
    {"cat", "fd", "find", "grep", "egrep", "fgrep", "head", "ls", "rg", "sed", "tail"}
)
_READ_ONLY_LOOKUP_FILTERS = frozenset({"grep", "egrep", "fgrep", "head", "sed", "tail"})
_READ_ONLY_SEARCH_EXECUTION_FLAGS = {
    "rg": frozenset({"--config-path", "--hostname-bin", "--pre", "--pre-glob"}),
}
_READ_ONLY_GIT_STATUS_FLAGS = frozenset(
    {
        "--ahead-behind",
        "--branch",
        "--ignored",
        "--long",
        "--no-ahead-behind",
        "--no-renames",
        "--porcelain",
        "--renames",
        "--short",
        "--show-stash",
        "--untracked-files",
        "-b",
        "-s",
        "-u",
        "-z",
    }
)
_READ_ONLY_GIT_STATUS_VALUE_FLAGS = frozenset(
    {
        "--column",
        "--find-renames",
        "--ignored",
        "--porcelain",
        "--untracked-files",
    }
)
_FIND_EXEC_PLACEHOLDER_TARGET = "guard-find-placeholder.py"
_FIND_EXEC_ACTION_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FIND_EXEC_TERMINATOR_TOKENS = frozenset({";", r"\;", "+"})
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
            "--config-file",
            "--directory",
            "--env-file",
            "--index",
            "--index-url",
            "--project",
            "--python",
            "--with",
            "--with-editable",
            "--with-requirements",
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
_ENCODED_EXECUTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bxxd\s+(?:-r\s+-p|-rp)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n;]*\s-(?:e|ec|enc|encodedcommand)\b", re.IGNORECASE),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n;]*\bfrombase64string\s*\(", re.IGNORECASE),
)
_BASE64_LITERAL_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_LITERAL_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{24,}(?![A-Fa-f0-9])")
_MAX_DECODED_PAYLOAD_BYTES = 32 * 1024
_SENSITIVE_DECODED_PAYLOAD_TOKENS = (
    ".env",
    ".ssh/",
    ".aws/credentials",
    ".git-credentials",
    "process.env",
    "os.environ",
    "getenv(",
    "curl ",
    "wget ",
    "requests.",
    "fetch(",
    "axios.",
    "approval_policy",
    "hol-guard",
    "guard-bypass",
    ".codex/config.toml",
    "scp ",
)
_SECRET_EXFILTRATION_SECRET_PATTERN = re.compile(
    r"\b(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|private[_-]?key|secret|token)\b",
    re.IGNORECASE,
)
_SECRET_EXFILTRATION_NETWORK_PATTERN = re.compile(
    r"\b(?:axios\.post|fetch\s*\(|http\.client|requests\.post|urllib\.request|urlopen\s*\()|https?://",
    re.IGNORECASE,
)
_SECRET_EXFILTRATION_DESTINATION_PATTERN = re.compile(
    r"\b(?:collect|exfil|evil|leak|post|upload|webhook)\b",
    re.IGNORECASE,
)
_SENSITIVE_BASENAME_LABELS = {
    ".npmrc": "npm registry credentials",
    ".pypirc": "Python package credentials",
    ".netrc": "netrc credentials",
    ".git-credentials": "Git credential store",
}
_SENSITIVE_SUFFIX_LABELS = {
    (".aws", "credentials"): "AWS shared credentials file",
    (".aws", "config"): "AWS shared config file",
    (".docker", "config.json"): "Docker client config",
    (".ssh", "id_rsa"): "SSH private key",
    (".ssh", "id_ed25519"): "SSH private key",
    (".ssh", "id_ecdsa"): "SSH private key",
    (".ssh", "config"): "SSH client config",
}
_SENSITIVE_PATH_REASONS = {
    "local .env file": "Guard treats .env files as sensitive because they commonly store local secrets.",
    "npm registry credentials": "Guard treats .npmrc as sensitive because it may contain registry tokens.",
    "Python package credentials": "Guard treats .pypirc as sensitive because it may contain package credentials.",
    "netrc credentials": "Guard treats .netrc as sensitive because it may contain login secrets.",
    "Git credential store": "Guard treats .git-credentials as sensitive because it may contain repository credentials.",
    "AWS shared credentials file": (
        "Guard treats AWS shared credentials as sensitive because they contain cloud access keys."
    ),
    "AWS shared config file": "Guard treats AWS shared config as sensitive because it may contain credential profiles.",
    "Docker client config": "Guard treats Docker client config as sensitive because it may contain registry auth.",
    "SSH private key": "Guard treats SSH private keys as sensitive because they provide direct host access.",
    "SSH client config": "Guard treats SSH config as sensitive because it may reveal or shape host credentials.",
}


@dataclass(frozen=True, slots=True)
class FileReadRequestMatch:
    """A sensitive file-read tool call."""

    tool_name: str
    normalized_tool_name: str
    path_match: SensitivePathMatch


@dataclass(frozen=True, slots=True)
class ToolActionRequestMatch:
    """A sensitive native tool action that should block before execution."""

    tool_name: str
    normalized_tool_name: str
    command_text: str
    action_class: str
    reason: str
    raw_command_text: str | None = None
    wrapper_chain: tuple[str, ...] = ()
    canonical_command: CanonicalCommand | None = None
    shell_execution_context_hash: str | None = None
    shell_execution_context_reason_code: str | None = None
    shell_execution_effective_cwds: tuple[str, ...] = ()
    guard_default_action: str | None = None
    reason_code: str | None = None
    restricted_profile_version: str | None = None
    pytest_config_identity_sha256: str | None = None
    pytest_config_sources: tuple[str, ...] = ()
    pytest_config_reason_codes: tuple[str, ...] = ()
    interpreter_executable_identities: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class FileWriteRequestMatch:
    """A sensitive file-write tool call."""

    tool_name: str
    normalized_tool_name: str
    normalized_path: str
    path_class: str
    reason: str
    action_class: str


def is_file_read_tool_name(tool_name: str | None) -> bool:
    """Return whether the tool name looks like a file-read tool."""

    if not isinstance(tool_name, str) or not tool_name.strip():
        return False
    return tool_name.strip().lower() in _FILE_READ_TOOL_NAMES


def classify_sensitive_path(
    path: str | None,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> SensitivePathMatch | None:
    """Classify a path if it points at a high-confidence sensitive local file."""

    return classify_secret_path(path, cwd=cwd, home_dir=home_dir)


def extract_sensitive_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from tool arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None or normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in _candidate_paths(arguments):
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=str(tool_name).strip(),
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def extract_sensitive_file_read_request_from_action(
    action: GuardActionEnvelope,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from a normalized action envelope."""

    if action.action_type != "file_read":
        return None
    normalized_tool_name = _normalize_tool_name(action.tool_name) or "read"
    tool_name = action.tool_name.strip() if isinstance(action.tool_name, str) and action.tool_name.strip() else "Read"
    if normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in action.target_paths:
        if _is_lossy_redacted_path(candidate):
            continue
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=tool_name,
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def extract_sensitive_file_write_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    protected_paths: dict[str, str] | None = None,
) -> FileWriteRequestMatch | None:
    """Extract a sensitive file-write request from native tool arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None or normalized_tool_name not in _FILE_WRITE_TOOL_NAMES:
        return None
    requested_tool_name = str(tool_name).strip() if isinstance(tool_name, str) and str(tool_name).strip() else "Write"
    normalized_protected_paths = protected_paths or {}
    for candidate in _candidate_paths(arguments, include_apply_patch=normalized_tool_name == "apply_patch"):
        normalized_candidate = _normalized_candidate_path(candidate, cwd=cwd, home_dir=home_dir)
        if normalized_candidate is not None:
            protected_label = normalized_protected_paths.get(normalized_candidate)
            if protected_label is not None:
                return FileWriteRequestMatch(
                    tool_name=requested_tool_name,
                    normalized_tool_name=normalized_tool_name,
                    normalized_path=normalized_candidate,
                    path_class=protected_label,
                    reason=(
                        f"Guard treats writes to {protected_label} as sensitive because changing harness "
                        "configuration can weaken approvals or bypass protections before the user confirms the action."
                    ),
                    action_class="guard-managed config write",
                )
        path_match = classify_secret_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileWriteRequestMatch(
                tool_name=requested_tool_name,
                normalized_tool_name=normalized_tool_name,
                normalized_path=path_match.normalized_path,
                path_class=path_match.path_class,
                reason=path_match.reason,
                action_class="sensitive local file write",
            )
    return None


def _normalized_candidate_path(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    stripped = value.strip().strip("'").strip('"')
    if not stripped:
        return None
    return _normalize_path(_expand_home(stripped, home_dir), cwd)


def _is_lossy_redacted_path(path: str) -> bool:
    return path.strip().startswith(".../")


def build_file_read_request_artifact(
    harness: str,
    request: FileReadRequestMatch,
    *,
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    """Build a Guard artifact for an exact sensitive runtime file-read request."""

    fingerprint = _file_read_request_fingerprint(
        harness=harness,
        tool_name=request.normalized_tool_name,
        normalized_path=request.path_match.normalized_path,
    )
    request_summary = (
        f"Requested `{request.tool_name}` access to `{request.path_match.normalized_path}` "
        f"({request.path_match.path_class})."
    )
    risk_summary = f"Requests access to a sensitive local file: {request.path_match.path_class}."
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:file-read:{fingerprint}",
        name=f"{request.tool_name} {Path(request.path_match.normalized_path).name}",
        harness=harness,
        artifact_type="file_read_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "tool_name": request.tool_name,
            "normalized_path": request.path_match.normalized_path,
            "path_class": request.path_match.path_class,
            "request_summary": request_summary,
            "runtime_request_signals": ["requests access to a sensitive local file"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": request.path_match.reason,
        },
    )


def build_file_write_request_artifact(
    harness: str,
    request: FileWriteRequestMatch,
    *,
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    """Build a Guard artifact for a sensitive runtime file-write request."""

    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "harness": harness,
                "tool_name": request.normalized_tool_name,
                "normalized_path": request.normalized_path,
                "action_class": request.action_class,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    request_summary = (
        f"Requested `{request.tool_name}` write access to `{request.normalized_path}` ({request.path_class})."
    )
    risk_summary = f"Requests a {request.action_class}: {request.path_class}."
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:file-write:{fingerprint}",
        name=f"{request.tool_name} {Path(request.normalized_path).name}",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "tool_name": request.tool_name,
            "normalized_path": request.normalized_path,
            "path_class": request.path_class,
            "action_class": request.action_class,
            "request_summary": request_summary,
            "runtime_request_signals": [f"writes a sensitive local path: {request.path_class}"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": request.reason,
        },
    )


def _shell_normalized_tool_name(
    *,
    normalized_tool_name: str | None,
    arguments: object,
) -> str | None:
    if normalized_tool_name in _SHELL_TOOL_NAMES:
        return normalized_tool_name
    if _candidate_command_texts(arguments):
        return "shell"
    return normalized_tool_name


def extract_sensitive_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
) -> ToolActionRequestMatch | None:
    """Extract a sensitive native tool action from arguments."""

    command_texts = _candidate_command_texts(arguments)
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name in _FILE_WRITE_TOOL_NAMES:
        return None
    if normalized_tool_name is None and not command_texts:
        return None
    requested_tool_name = str(tool_name).strip() if isinstance(tool_name, str) and str(tool_name).strip() else "Shell"
    effective_tool_name = _shell_normalized_tool_name(
        normalized_tool_name=normalized_tool_name,
        arguments=arguments,
    )
    if effective_tool_name is None:
        return None
    for command_text in command_texts:
        raw_command_text = command_text
        candidate_canonical = (
            canonical_command
            if canonical_command is not None and canonical_command.raw_text == raw_command_text.strip()
            else None
        )
        wrapper_chain: tuple[str, ...] = ()
        normalized_command_text = command_text
        if effective_tool_name in _SHELL_TOOL_NAMES:
            normalized_command = normalize_transparent_shell_command(command_text, cwd=cwd, home_dir=home_dir)
            command_text = normalized_command.normalized_command
            normalized_command_text = command_text
            wrapper_chain = normalized_command.wrapper_chain
        docker_sensitive_request = _docker_sensitive_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
        )
        if docker_sensitive_request is not None:
            docker_sensitive_request = _request_with_shell_execution_context(
                docker_sensitive_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                docker_sensitive_request = _request_with_wrapper_context(
                    docker_sensitive_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return docker_sensitive_request
        if raw_command_text != command_text:
            docker_sensitive_request = _docker_sensitive_tool_action_request(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=raw_command_text,
            )
            if docker_sensitive_request is not None:
                docker_sensitive_request = _request_with_shell_execution_context(
                    docker_sensitive_request,
                    command_text=normalized_command_text,
                    cwd=cwd,
                )
                if wrapper_chain:
                    docker_sensitive_request = _request_with_wrapper_context(
                        replace(
                            docker_sensitive_request,
                            command_text=normalized_command_text,
                        ),
                        raw_command_text=raw_command_text,
                        wrapper_chain=wrapper_chain,
                    )
                return docker_sensitive_request
        docker_config_request = _docker_config_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if docker_config_request is not None:
            docker_config_request = _request_with_shell_execution_context(
                docker_config_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                docker_config_request = _request_with_wrapper_context(
                    docker_config_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return docker_config_request
        kubernetes_secret_source = kubernetes_secret_read_source(command_text)
        if kubernetes_secret_source is not None:
            kubernetes_secret_request = ToolActionRequestMatch(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=command_text,
                action_class="Kubernetes secret read command",
                reason=(
                    f"Guard treats {kubernetes_secret_source} reads through Kubernetes CLIs as sensitive because "
                    "they can expose cluster credentials or application secrets before the user confirms the action."
                ),
            )
            kubernetes_secret_request = _request_with_shell_execution_context(
                kubernetes_secret_request,
                command_text=command_text,
                cwd=cwd,
            )
            if wrapper_chain:
                kubernetes_secret_request = _request_with_wrapper_context(
                    kubernetes_secret_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return kubernetes_secret_request
        destructive_execution_context = model_shell_execution_context(
            command_text,
            cwd=cwd,
            workspace_root=cwd,
            home_dir=home_dir,
        )
        raw_destructive_execution_context = (
            model_shell_execution_context(
                raw_command_text,
                cwd=cwd,
                workspace_root=cwd,
                home_dir=home_dir,
            )
            if raw_command_text != command_text
            else destructive_execution_context
        )
        destructive_shell_request = _destructive_shell_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=effective_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
            canonical_command=(
                candidate_canonical
                if candidate_canonical is not None and candidate_canonical.normalized_text == command_text
                else None
            ),
            raw_command_text=raw_command_text,
            execution_context=destructive_execution_context,
            raw_execution_context=raw_destructive_execution_context,
        )
        if destructive_shell_request is not None:
            destructive_shell_request = _request_with_shell_execution_context(
                destructive_shell_request,
                command_text=command_text,
                cwd=cwd,
                context=destructive_execution_context,
            )
            if wrapper_chain:
                destructive_shell_request = _request_with_wrapper_context(
                    destructive_shell_request,
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
            return destructive_shell_request
        if wrapper_chain:
            destructive_shell_request = _destructive_shell_tool_action_request(
                tool_name=requested_tool_name,
                normalized_tool_name=effective_tool_name,
                command_text=raw_command_text,
                cwd=cwd,
                home_dir=home_dir,
                canonical_command=candidate_canonical,
                raw_command_text=raw_command_text,
                execution_context=raw_destructive_execution_context,
                raw_execution_context=raw_destructive_execution_context,
            )
            if destructive_shell_request is not None:
                destructive_shell_request = _request_with_shell_execution_context(
                    destructive_shell_request,
                    command_text=normalized_command_text,
                    cwd=cwd,
                )
                destructive_shell_request = _request_with_wrapper_context(
                    replace(
                        destructive_shell_request,
                        command_text=normalized_command_text,
                    ),
                    raw_command_text=raw_command_text,
                    wrapper_chain=wrapper_chain,
                )
                return destructive_shell_request
    return None


def is_explicitly_benign_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return False
    found_benign_candidate = False
    for command_text in _candidate_command_texts(arguments):
        interpreter_evidence = _python_interpreter_executable_identities(
            command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if any(evidence.get("trust") not in {"trusted_guard", "trusted_system"} for evidence in interpreter_evidence):
            return False
        if normalized_tool_name in _SHELL_TOOL_NAMES:
            command_text = normalize_transparent_shell_command(
                command_text, cwd=cwd, home_dir=home_dir
            ).normalized_command
        stripped_command = command_text.strip()
        if not stripped_command:
            continue
        parts = _split_shell_parts(stripped_command)
        if not parts:
            return False
        parsed_command_names = list(_shell_command_names_from_parts(parts))
        if _looks_like_benign_interpreter_wait(stripped_command, parts, parsed_command_names):
            found_benign_candidate = True
            continue
        if _looks_like_read_only_interpreter_command(stripped_command, parts, parsed_command_names):
            found_benign_candidate = True
            continue
        if _looks_like_safe_read_only_lookup_command(
            stripped_command,
            parts,
            home_dir=home_dir,
        ):
            found_benign_candidate = True
            continue
        if _looks_like_safe_git_status_command(stripped_command, parts, cwd=cwd):
            found_benign_candidate = True
            continue
        return False
    return found_benign_candidate


def _looks_like_safe_git_status_command(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    saw_status = False
    try:
        effective_cwd = (cwd or Path.cwd()).resolve()
    except OSError:
        return False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index != 0:
            return False
        executable = segment[command_index]
        if "/" in executable or "\\" in executable:
            return False
        args = segment[command_index + 1 :]
        next_cwd = _safe_git_status_cd_target(command_name, args, cwd=effective_cwd)
        if next_cwd is not None:
            effective_cwd = next_cwd
            continue
        if command_name != "git" or not _git_status_args_are_read_only(args):
            return False
        if not _git_status_has_execution_free_config(effective_cwd):
            return False
        saw_status = True
    return saw_status


def _safe_git_status_cd_target(command_name: str, args: list[str], *, cwd: Path) -> Path | None:
    if command_name != "cd":
        return None
    path_args = _shell_args_without_trailing_redirections(args)
    if path_args != args or len(path_args) != 1 or path_args[0] in {"-", "--"}:
        return None
    path_text = path_args[0]
    if _shell_token_has_command_substitution(path_text):
        return None
    try:
        candidate = Path(path_text).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _git_status_has_execution_free_config(cwd: Path | None) -> bool:
    git_path = shutil.which("git")
    if git_path is None:
        return False
    try:
        resolved_git = Path(git_path).resolve()
        execution_cwd = (cwd or Path.cwd()).resolve()
    except OSError:
        return False
    if not _git_binary_path_is_trusted(resolved_git, cwd=execution_cwd):
        return False
    try:
        result = subprocess.run(
            [str(resolved_git), "config", "--null", "--get-all", "core.fsmonitor"],
            cwd=execution_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode == 1 and not result.stdout:
        return True
    if result.returncode != 0:
        return False
    values = [value.strip().lower() for value in result.stdout.split("\0") if value.strip()]
    return bool(values) and all(value in {"0", "false", "no", "off"} for value in values)


def _git_binary_path_is_trusted(git_path: Path, *, cwd: Path) -> bool:
    try:
        untrusted_roots = (
            cwd.resolve(),
            Path.home().resolve(),
            Path("/tmp").resolve(),
            Path("/private/tmp").resolve(),
        )
    except (OSError, RuntimeError):
        return False
    for untrusted_root in untrusted_roots:
        try:
            _ = git_path.relative_to(untrusted_root)
        except ValueError:
            continue
        return False
    current_uid = getattr(os, "getuid", lambda: -1)()
    current_groups = set(getattr(os, "getgroups", lambda: [])())
    try:
        for candidate in (git_path, *git_path.parents):
            metadata = candidate.stat()
            if metadata.st_mode & stat.S_IWOTH:
                return False
            if metadata.st_mode & stat.S_IWGRP and metadata.st_gid not in current_groups:
                return False
            if candidate == git_path and current_uid >= 0 and metadata.st_uid not in {0, current_uid}:
                return False
    except OSError:
        return False
    return True


def _git_status_args_are_read_only(args: list[str]) -> bool:
    if not args or args[0].lower() != "status":
        return False
    after_option_terminator = False
    for token in args[1:]:
        if after_option_terminator:
            continue
        if token == "--":
            after_option_terminator = True
            continue
        normalized = token.lower()
        if normalized in _READ_ONLY_GIT_STATUS_FLAGS:
            continue
        if "=" in normalized and normalized.split("=", 1)[0] in _READ_ONLY_GIT_STATUS_VALUE_FLAGS:
            continue
        if (
            normalized.startswith("-")
            and len(normalized) > 2
            and not normalized.startswith("--")
            and all(f"-{flag}" in _READ_ONLY_GIT_STATUS_FLAGS for flag in normalized[1:])
        ):
            continue
        return False
    return True


def _docker_sensitive_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
) -> ToolActionRequestMatch | None:
    if _docker_sensitive_reason(command_text) is None:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="docker-sensitive command",
        reason=(
            "Guard treats Docker login, run, push, and credential-bearing build "
            "actions as sensitive because they can expose credentials or execute privileged "
            "container workflows. Docker Compose actions are sensitive when they use "
            "subcommands that execute arbitrary commands or copy files (run, exec, cp, push, "
            "publish, watch), supply secret-bearing input (--env-file), target a non-default "
            "Docker host or context, or carry TLS/credential material through flags or "
            "environment variables."
        ),
    )


def _docker_config_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
) -> ToolActionRequestMatch | None:
    if _docker_config_path_from_command(command_text, cwd=cwd, home_dir=home_dir) is None:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="Docker client config access",
        reason=_SENSITIVE_PATH_REASONS["Docker client config"],
    )


def _destructive_shell_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
    canonical_command: CanonicalCommand | None = None,
    raw_command_text: str | None = None,
    execution_context: ShellExecutionContext | None = None,
    raw_execution_context: ShellExecutionContext | None = None,
) -> ToolActionRequestMatch | None:
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return None
    canonical_command = canonical_command or parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    execution_context = execution_context or model_shell_execution_context(
        command_text,
        cwd=cwd,
        workspace_root=cwd,
        home_dir=home_dir,
    )
    detection_command_text = command_text
    pytest_execution_requested = _shell_command_targets_pytest(detection_command_text)
    pytest_config_assessment = (
        _pytest_config_assessment_for_command(
            detection_command_text,
            cwd=cwd,
            execution_context=execution_context,
        )
        if pytest_execution_requested
        else PytestConfigAssessment((), True, False, (), None)
    )
    pytest_config_sources = tuple(result.source_path for result in pytest_config_assessment.results)
    interpreter_executable_identities = _python_interpreter_executable_identities(
        raw_command_text or detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
        execution_context=(
            raw_execution_context
            if raw_command_text is not None and raw_command_text != detection_command_text
            else execution_context
        ),
    )
    if is_guard_approval_mutation_command(detection_command_text):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=SELF_APPROVAL_ACTION_CLASS,
            reason=SELF_APPROVAL_REASON,
            canonical_command=canonical_command,
        )
    if _contains_encoded_or_encrypted_shell_command(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="encoded or encrypted shell command",
            reason=(
                "Guard treats encoded or encrypted decode-and-exec shell flows as sensitive and inspects bounded "
                "payloads in-process without executing them during evaluation."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if _contains_shell_credential_exfiltration(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="credential exfiltration shell command",
            reason=(
                "Guard treats shell scripts that combine credential-looking material with outbound HTTP posting as "
                "sensitive because they can exfiltrate local secrets before the user confirms the action."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if _contains_shell_network_file_upload(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="shell file upload command",
            reason=(
                "Guard treats shell-driven local file uploads as sensitive because they can exfiltrate local file "
                "contents to a network endpoint before the user confirms the action."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if _gh_pr_create_body_has_shell_command_substitution(detection_command_text) or (
        raw_command_text is not None
        and raw_command_text != detection_command_text
        and _gh_pr_create_body_has_shell_command_substitution(raw_command_text)
    ):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="GitHub PR body shell substitution",
            reason=(
                "Guard treats command substitution inside `gh pr create --body` as sensitive because shell backticks "
                "or `$()` run before GitHub receives the PR text. Use single quotes around Markdown code spans or "
                "`--body-file` for PR descriptions."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    extension_interaction = classify_command_extension_interaction(
        canonical_command,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )
    if extension_interaction.priority is not None:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=extension_interaction.priority.action_class,
            reason=extension_interaction.priority.reason,
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    github_assessment = classify_github_shell_capabilities(
        raw_command_text or detection_command_text,
        home_dir=home_dir,
    )
    if (
        github_assessment is not None
        and not github_capability_requires_confirmation(github_assessment)
        and execution_context.reason_code == SHELL_CWD_WORKSPACE_ESCAPE
        and home_dir is not None
    ):
        home_execution_context = model_shell_execution_context(
            detection_command_text,
            cwd=cwd,
            workspace_root=home_dir,
            home_dir=home_dir,
        )
        raw_home_execution_context = (
            model_shell_execution_context(
                raw_command_text,
                cwd=cwd,
                workspace_root=home_dir,
                home_dir=home_dir,
            )
            if raw_command_text is not None and raw_command_text != detection_command_text
            else home_execution_context
        )
        if home_execution_context.complete and raw_home_execution_context.complete:
            execution_context = home_execution_context
            raw_execution_context = raw_home_execution_context
            interpreter_executable_identities = _python_interpreter_executable_identities(
                raw_command_text or detection_command_text,
                cwd=cwd,
                home_dir=home_dir,
                execution_context=(
                    raw_execution_context
                    if raw_command_text is not None and raw_command_text != detection_command_text
                    else execution_context
                ),
            )
    execution_context_reason = _shell_execution_context_validation_reason(execution_context)
    if execution_context.directory_change_present and execution_context_reason is not None:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="unresolved shell execution context",
            reason=(
                "Guard could not prove the working directory for every shell segment and requires one "
                f"conservative decision before the user confirms execution ({execution_context_reason}). Use a "
                "literal, existing in-workspace directory with deterministic cd/pushd/popd control flow, or run the "
                "command from the intended directory."
            ),
            canonical_command=canonical_command,
            shell_execution_context_hash=execution_context.context_hash,
            shell_execution_context_reason_code=execution_context_reason,
            shell_execution_effective_cwds=tuple(str(path) for path in execution_context.effective_cwds),
            guard_default_action="sandbox-required" if pytest_execution_requested else None,
            reason_code="pytest_restricted_profile_required" if pytest_execution_requested else None,
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION if pytest_execution_requested else None,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    detection_command_is_destructive = _looks_destructive_shell_command(
        detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
        execution_context=execution_context,
    )
    raw_command_is_destructive = (
        raw_command_text is not None
        and raw_command_text != detection_command_text
        and _looks_destructive_shell_command(
            raw_command_text,
            cwd=cwd,
            home_dir=home_dir,
            execution_context=raw_execution_context,
        )
    )
    if detection_command_is_destructive or raw_command_is_destructive:
        matched_execution_context = raw_execution_context if raw_command_is_destructive else execution_context
        matched_execution_context = matched_execution_context or execution_context
        destructive_reason = (
            "Guard found execution-affecting pytest configuration or could not inspect the selected pytest "
            "configuration completely. Keep plugin/output/config overrides inside the restricted pytest profile; "
            "repair or remove malformed, missing, unreadable, oversized, or unsafe config inputs before retrying."
            if pytest_execution_requested and pytest_config_assessment.unsafe
            else (
                "Guard treats destructive shell writes and delete operations as sensitive because they can mutate "
                "the local machine before the user confirms the action."
            )
        )
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="destructive shell command",
            reason=destructive_reason,
            canonical_command=canonical_command,
            shell_execution_context_hash=(
                matched_execution_context.context_hash if matched_execution_context.directory_change_present else None
            ),
            shell_execution_context_reason_code=matched_execution_context.reason_code,
            shell_execution_effective_cwds=(
                tuple(str(path) for path in matched_execution_context.effective_cwds)
                if matched_execution_context.directory_change_present
                else ()
            ),
            guard_default_action="sandbox-required" if pytest_execution_requested else None,
            reason_code="pytest_restricted_profile_required" if pytest_execution_requested else None,
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION if pytest_execution_requested else None,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if pytest_execution_requested:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="pytest repository-code execution",
            reason=(
                "pytest_restricted_profile_required: Pytest collection imports repository-controlled tests, "
                "conftest.py files, and plugins. Run the exact pytest argv through "
                "`hol-guard pytest-contained --workspace <workspace> -- ...`; Guard will not launch pytest when "
                "the required operating-system sandbox is unavailable."
            ),
            canonical_command=canonical_command,
            guard_default_action="sandbox-required",
            reason_code="pytest_restricted_profile_required",
            restricted_profile_version=PYTEST_RESTRICTED_PROFILE_VERSION,
            pytest_config_identity_sha256=pytest_config_assessment.identity_sha256,
            pytest_config_sources=pytest_config_sources,
            pytest_config_reason_codes=pytest_config_assessment.reason_codes,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if github_assessment is not None and github_capability_requires_confirmation(github_assessment):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=github_capability_action_class(github_assessment),
            reason=(
                f"{github_assessment.detail} Guard requires confirmation because the operation is not a "
                "statically proven read-only composition."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if extension_interaction.fallback is not None:
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=extension_interaction.fallback.action_class,
            reason=extension_interaction.fallback.reason,
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    untrusted_interpreters = tuple(
        evidence
        for evidence in interpreter_executable_identities
        if evidence.get("trust") not in {"trusted_guard", "trusted_system"}
    )
    if untrusted_interpreters:
        trust_reasons = ", ".join(
            sorted({str(evidence.get("trust") or "unknown") for evidence in untrusted_interpreters})
        )
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="untrusted Python interpreter",
            reason=(
                "Guard requires review because the Python command resolves through an interpreter path that is "
                f"not an attested Guard or system runtime ({trust_reasons}). The decision is bound to the raw "
                "interpreter token, launch path, symlink chain, executable mode, file identity, and content hash."
            ),
            canonical_command=canonical_command,
            reason_code="interpreter_identity_untrusted",
            interpreter_executable_identities=interpreter_executable_identities,
        )
    return None


def _shell_execution_context_validation_reason(context: ShellExecutionContext) -> str | None:
    if not context.complete:
        return context.reason_code
    for segment in context.segments:
        _effective_cwd, reason = validate_shell_execution_segment(context, segment)
        if reason is not None:
            return reason
    return None


def classify_github_shell_capabilities(
    command_text: str,
    *,
    home_dir: Path | None,
) -> GitHubCommandAssessment | None:
    """Adapt the shared shell parser to focused GitHub capability composition."""

    return _classify_github_shell_capabilities(
        command_text,
        analysis=GitHubShellAnalysis(
            command_substitution_payloads=_shell_command_substitution_payloads,
            split_parts=_split_shell_parts,
            nested_commands=lambda parts: (*_env_split_string_payloads(parts), *_shell_command_scripts(parts)),
            pipelines=_iter_shell_pipelines,
            command_builtin_is_lookup=_shell_segment_is_command_builtin_lookup,
            primary_command=_shell_segment_primary_command,
            pipeline_companion_is_read_only=lambda segment: _github_pipeline_companion_is_read_only(
                segment,
                home_dir=home_dir,
            ),
        ),
    )


def _shell_segment_is_command_builtin_lookup(segment: list[str]) -> bool:
    contextual_segment = [_ShellTokenWithQuoteContext(raw=token, plain=token) for token in segment]
    for index, token in enumerate(segment):
        command_name = _normalized_shell_command_name(_shell_command_token_without_attached_redirection(token))
        if command_name == "command":
            return _command_builtin_options_are_lookup_only(contextual_segment, index + 1)
    return False


def _github_pipeline_companion_is_read_only(
    segment: list[str],
    *,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    if _is_python_interpreter_command(command_name):
        scripts = list(_script_interpreter_texts(segment))
        return bool(scripts) and all(_script_is_read_only_observer(script_text) for script_text in scripts)
    if any(">" in token or "<" in token for token in segment[command_index + 1 :] if token not in {"2>&1", "1>&2"}):
        return False
    args = [token for token in segment[command_index + 1 :] if token not in {"2>&1", "1>&2"}]
    if command_name == "jq":
        return _github_jq_filter_args_are_safe(args)
    if command_name in _READ_ONLY_LOOKUP_FILTERS:
        return _read_only_lookup_filter_segment_is_safe(command_name, args, home_dir=home_dir)
    return False


def _github_jq_filter_args_are_safe(args: list[str]) -> bool:
    boolean_options = {
        "--ascii-output",
        "--compact-output",
        "--exit-status",
        "--join-output",
        "--monochrome-output",
        "--raw-input",
        "--raw-output",
        "--slurp",
        "--sort-keys",
        "-C",
        "-M",
        "-R",
        "-S",
        "-a",
        "-c",
        "-e",
        "-j",
        "-r",
        "-s",
    }
    value_options = {"--arg": 2, "--argjson": 2}
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"2>&1", "1>&2"}:
            index += 1
            continue
        if token in boolean_options:
            index += 1
            continue
        if token in value_options:
            index += 1 + value_options[token]
            if index > len(args):
                return False
            continue
        if token.startswith("-"):
            return False
        return index == len(args) - 1
    return False


def _gh_pr_create_body_has_shell_command_substitution(command_text: str, *, depth: int = 0) -> bool:
    if depth > 2:
        return False
    if not _shell_command_substitution_payloads(command_text):
        return False
    tokens = _shell_tokens_preserving_quote_context(command_text)
    for segment in _shell_token_segments(tokens):
        for env_split_string in _gh_pr_env_split_string_payloads_with_substitution(segment):
            if _gh_pr_create_body_has_shell_command_substitution(env_split_string, depth=depth + 1):
                return True
        body_args_start_index = _gh_pr_create_body_args_start_index(segment)
        if body_args_start_index is None:
            continue
        if _gh_pr_create_body_args_have_substitution(segment[body_args_start_index:]):
            return True
    return False


def _gh_pr_env_split_string_payloads_with_substitution(segment: list[_ShellTokenWithQuoteContext]) -> tuple[str, ...]:
    env_index = _shell_segment_env_index([token.plain for token in segment])
    if env_index is None:
        return ()
    parsed = parse_env_wrapper([token.plain for token in segment[env_index + 1 :]])
    payloads: list[str] = []
    for expansion in parsed.split_expansions:
        source_index = env_index + 1 + expansion.source_index
        if source_index < len(segment) and _shell_command_substitution_payloads(segment[source_index].raw):
            payloads.append(expansion.payload.strip())
    return tuple(payload for payload in payloads if payload)


@dataclass(frozen=True, slots=True)
class _ShellTokenWithQuoteContext:
    raw: str
    plain: str


def _gh_pr_create_body_args_start_index(segment: list[_ShellTokenWithQuoteContext]) -> int | None:
    index = 0
    plain_segment = [token.plain for token in segment]
    while index < len(segment):
        redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(plain_segment, index)
        if redirect_tokens_consumed > 0:
            index += redirect_tokens_consumed
            continue
        token = segment[index]
        command_name = _normalized_shell_command_name(_shell_command_token_without_attached_redirection(token.plain))
        if command_name == "gh":
            if index + 1 >= len(segment) or segment[index + 1].plain != "pr":
                return None
            pr_command_index = _skip_gh_pr_options(segment, index + 2)
            if pr_command_index >= len(segment):
                return None
            if segment[pr_command_index].plain in {
                "create",
                "new",
            }:
                return pr_command_index + 1
            return None
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token.plain)):
            index += 1
            continue
        if command_name == "command":
            if _command_builtin_options_are_lookup_only(segment, index + 1):
                return None
            index = _skip_command_builtin_options(segment, index + 1)
            continue
        if command_name == "time":
            index = _skip_generic_shell_wrapper_options(command_name, segment, index + 1)
            continue
        if command_name == "env":
            index = _skip_env_wrapper_options(segment, index + 1)
            continue
        if command_name == "sudo":
            index = _skip_sudo_wrapper_options(segment, index + 1)
            continue
        if command_name in {"nice", "nohup", "stdbuf"}:
            index = _skip_generic_shell_wrapper_options(command_name, segment, index + 1)
            continue
        if command_name == "case":
            index = _skip_shell_case_header(segment, index + 1)
            continue
        if command_name == "select":
            index = _skip_shell_select_header(segment, index + 1)
            continue
        if token.plain in _SHELL_CONTROL_PREFIX_TOKENS or command_name in _SHELL_CONTROL_PREFIX_TOKENS:
            index += 1
            continue
        return None
    return None


def _skip_gh_pr_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if plain in _GH_PR_OPTION_VALUE_FLAGS:
            index += 2
            continue
        if any(plain.startswith(f"{flag}=") for flag in _GH_PR_OPTION_VALUE_FLAGS):
            index += 1
            continue
        if plain.startswith("-R") and plain != "-R":
            index += 1
            continue
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _skip_shell_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment) and segment[index].plain.startswith("-"):
        index += 1
    return index


def _skip_generic_shell_wrapper_options(
    command_name: str,
    segment: list[_ShellTokenWithQuoteContext],
    index: int,
) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if not plain.startswith("-"):
            break
        index += _wrapper_option_tokens_consumed(command_name, plain)
    return index


def _skip_command_builtin_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _command_builtin_options_are_lookup_only(segment: list[_ShellTokenWithQuoteContext], index: int) -> bool:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return False
        if not plain.startswith("-"):
            return False
        if "v" in plain[1:] or "V" in plain[1:]:
            return True
        index += 1
    return False


def _skip_shell_case_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        if segment[index].plain.endswith(")"):
            return index + 1
        index += 1
    return index


def _skip_shell_select_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        if segment[index].plain == "do":
            return index
        index += 1
    return index


def _skip_env_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    parsed = parse_env_wrapper([token.plain for token in segment[index:]])
    if not parsed.complete or parsed.command_index is None or parsed.split_expansions:
        return len(segment)
    return index + parsed.command_index


def _skip_sudo_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain in _SUDO_OPTION_VALUE_FLAGS:
            index += 2
            continue
        if plain in _SUDO_OPTION_VALUE_LONG_FLAGS:
            index += 2
            continue
        if any(plain.startswith(f"{flag}=") for flag in _SUDO_OPTION_VALUE_LONG_FLAGS):
            index += 1
            continue
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _gh_pr_create_body_args_have_substitution(args: list[_ShellTokenWithQuoteContext]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.plain in {"--body", "-b", "--body-file", "-F"}:
            if index + 1 >= len(args):
                return False
            if _shell_command_substitution_payloads(args[index + 1].raw):
                return True
            index += 2
            continue
        if arg.plain.startswith("-F") and len(arg.plain) > 2 and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("-b") and len(arg.plain) > 2 and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("--body-file=") and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("--body=") and _shell_command_substitution_payloads(arg.raw):
            return True
        index += 1
    return False


def _shell_tokens_preserving_quote_context(command_text: str) -> list[_ShellTokenWithQuoteContext]:
    tokens: list[_ShellTokenWithQuoteContext] = []
    index = 0
    while index < len(command_text):
        if command_text[index] in {"\n", "\r"}:
            tokens.append(_ShellTokenWithQuoteContext(raw=";", plain=";"))
            index += 1
            continue
        while index < len(command_text) and command_text[index].isspace() and command_text[index] not in {"\n", "\r"}:
            index += 1
        if index >= len(command_text):
            break
        if command_text[index] in {"\n", "\r"}:
            tokens.append(_ShellTokenWithQuoteContext(raw=";", plain=";"))
            index += 1
            continue
        if command_text[index] in {";", "&", "|"}:
            if command_text.startswith("&&", index) or command_text.startswith("||", index):
                raw_token = command_text[index : index + 2]
                index += 2
            else:
                raw_token = command_text[index]
                index += 1
            tokens.append(_ShellTokenWithQuoteContext(raw=raw_token, plain=raw_token))
            continue
        start = index
        quote: str | None = None
        escaped = False
        while index < len(command_text):
            char = command_text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\":
                escaped = True
                index += 1
                continue
            if quote is not None:
                if char == quote:
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char.isspace() or char in {";", "&", "|"}:
                break
            index += 1
        raw_token = command_text[start:index]
        if raw_token:
            tokens.append(_ShellTokenWithQuoteContext(raw=raw_token, plain=_plain_shell_token(raw_token)))
    return tokens


def _plain_shell_token(raw_token: str) -> str:
    try:
        parts = shlex.split(raw_token, posix=True)
    except ValueError:
        return raw_token.strip("'\"")
    if not parts:
        return ""
    return parts[0]


def _shell_token_segments(
    tokens: list[_ShellTokenWithQuoteContext],
) -> list[list[_ShellTokenWithQuoteContext]]:
    segments: list[list[_ShellTokenWithQuoteContext]] = []
    current: list[_ShellTokenWithQuoteContext] = []
    for token in tokens:
        if token.plain in {"&&", "||", ";", "&", "|", "|&"}:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _contains_shell_credential_exfiltration(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _shell_pipeline_reads_sensitive_path_to_network(parts, cwd=cwd, home_dir=home_dir):
        return True
    if _shell_segments_contain_credential_exfiltration(parts):
        return True
    for heredoc_payload in _shell_heredoc_payloads(normalized):
        if _text_contains_credential_exfiltration(heredoc_payload):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_credential_exfiltration(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_credential_exfiltration(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_credential_exfiltration(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_credential_exfiltration(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _shell_pipeline_reads_sensitive_path_to_network(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    secret_in_pipeline = False
    segment: list[str] = []
    for token in [*parts, ";"]:
        if token == ";" and _find_segment_expects_exec_terminator(segment):
            segment.append(token)
            continue
        if token in {"|", "|&"}:
            if _shell_segment_network_sink_receives_pipeline(segment) and secret_in_pipeline:
                return True
            if _shell_segment_reads_sensitive_path(segment, cwd=cwd, home_dir=home_dir):
                secret_in_pipeline = True
            segment = []
            continue
        if token in {"&&", "||", ";", "&"}:
            if _shell_segment_network_sink_receives_pipeline(segment) and secret_in_pipeline:
                return True
            secret_in_pipeline = False
            segment = []
            continue
        segment.append(token)
    return False


def _find_segment_expects_exec_terminator(segment: list[str]) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "find" or command_index is None:
        return False
    args = segment[command_index + 1 :]
    index = 0
    while index < len(args):
        if args[index] not in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            continue
        index += 1
        while index < len(args) and args[index] not in _FIND_EXEC_TERMINATOR_TOKENS:
            index += 1
        if index >= len(args):
            return True
        index += 1
    return False


def _shell_segment_reads_sensitive_path(segment: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    command_segment = segment[command_index:]
    if command_name == "find":
        return _find_segment_reads_sensitive_path(command_segment, cwd=cwd, home_dir=home_dir)
    if command_name not in _SHELL_LOCAL_READ_COMMANDS:
        return False
    if not _shell_read_segment_can_emit_stdout(command_segment):
        return False
    for token in _shell_segment_file_operand_tokens(command_segment):
        normalized_token = _shell_command_token_without_attached_redirection(token).strip("'\"")
        if not normalized_token:
            continue
        if classify_sensitive_path(normalized_token, cwd=cwd, home_dir=home_dir) is not None:
            return True
    return False


def _find_segment_reads_sensitive_path(
    command_segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    args = command_segment[1:]
    if not _find_exec_reads_file_content(args):
        return False
    return any(
        _find_target_candidate_is_sensitive(candidate, cwd=cwd, home_dir=home_dir)
        for candidate in _find_target_candidates(args)
    )


def _find_exec_reads_file_content(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg not in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            continue
        if index + 1 >= len(args):
            return False
        command_name = Path(args[index + 1]).name.lower()
        exec_index = index + 2
        exec_args: list[str] = []
        while exec_index < len(args) and args[exec_index] not in _FIND_EXEC_TERMINATOR_TOKENS:
            exec_args.append(args[exec_index])
            exec_index += 1
        if command_name in _SHELL_LOCAL_READ_COMMANDS:
            if command_name == "sed" and not _find_exec_sed_args_are_read_only(exec_args):
                index = exec_index + 1 if exec_index < len(args) else exec_index
                continue
            return True
        index = exec_index + 1 if exec_index < len(args) else exec_index
    return False


def _find_target_candidates(args: list[str]) -> tuple[str, ...]:
    candidates: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            while index < len(args) and args[index] not in _FIND_EXEC_TERMINATOR_TOKENS:
                index += 1
            if index < len(args):
                index += 1
            continue
        if arg in _FIND_PATH_VALUE_PREDICATES and index + 1 < len(args):
            candidates.append(args[index + 1])
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        candidates.append(arg)
        index += 1
    return tuple(candidates)


def _find_target_candidate_is_sensitive(candidate: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    normalized = _shell_command_token_without_attached_redirection(candidate).strip("'\"")
    if normalized in {"", "-", "{}", _FIND_EXEC_PLACEHOLDER_TARGET}:
        return False
    if classify_sensitive_path(normalized, cwd=cwd, home_dir=home_dir) is not None:
        return True
    return _path_text_looks_sensitive(normalized)


def _shell_segment_network_sink_receives_pipeline(segment: list[str]) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name not in _SHELL_NETWORK_SINK_COMMANDS or command_index is None:
        return False
    args = segment[command_index + 1 :]
    if command_name == "curl":
        return _curl_segment_consumes_stdin(args)
    if command_name == "wget":
        return _wget_segment_consumes_stdin(args)
    if command_name == "ssh":
        return _ssh_segment_consumes_stdin(args)
    return command_name in {"nc", "ncat", "netcat"}


def _shell_read_segment_can_emit_stdout(segment: list[str]) -> bool:
    if not segment:
        return False
    command_name = Path(segment[0]).name.lower()
    args = segment[1:]
    if command_name in {"grep", "egrep", "fgrep", "rg"}:
        return not _search_args_use_quiet_mode(args)
    return True


def _search_args_use_quiet_mode(args: list[str]) -> bool:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            return False
        if arg in {"-e", "--regexp", "-f", "--file"}:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in ("--regexp", "--file")):
            continue
        if (arg.startswith("-e") or arg.startswith("-f")) and len(arg) > 2:
            continue
        if arg in {"-q", "--quiet", "--silent"}:
            return True
        if arg.startswith("--quiet=") or arg.startswith("--silent="):
            return True
        if arg.startswith("-") and not arg.startswith("--") and "q" in arg[1:]:
            return True
    return False


def _ssh_segment_consumes_stdin(args: list[str]) -> bool:
    if not args:
        return False
    skip_next = False
    flags_with_values = frozenset(
        {
            "-b",
            "-c",
            "-D",
            "-E",
            "-e",
            "-F",
            "-I",
            "-i",
            "-J",
            "-L",
            "-l",
            "-m",
            "-O",
            "-o",
            "-p",
            "-R",
            "-S",
            "-W",
            "-w",
        }
    )
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            break
        if arg in flags_with_values:
            skip_next = True
            continue
        if any(arg.startswith(flag) and len(arg) > len(flag) for flag in flags_with_values):
            continue
        if arg in {"-n", "-f", "-G", "-N", "-Q", "-V"}:
            return False
        if any(arg.startswith(flag) and len(arg) > 2 for flag in ("-G", "-N", "-Q")):
            return False
        if arg.startswith("-") and not arg.startswith("--"):
            cluster_flags = arg[1:]
            for index, flag in enumerate(cluster_flags):
                if flag in {"n", "f", "N"}:
                    return False
                if f"-{flag}" in flags_with_values:
                    if index == len(cluster_flags) - 1:
                        break
                    break
    return True


def _shell_segment_file_operand_tokens(segment: list[str]) -> tuple[str, ...]:
    if not segment:
        return ()
    command_name = Path(segment[0]).name.lower()
    args = segment[1:]
    if command_name == "cat":
        return _cat_file_operand_tokens(args)
    if command_name in {"head", "tail"}:
        return _plain_file_operand_tokens(args)
    if command_name == "sed":
        return _sed_file_operand_tokens(args)
    if command_name in {"grep", "egrep", "fgrep", "rg"}:
        return _search_file_operand_tokens(command_name, args)
    return ()


def _cat_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    after_options = False
    for arg in args:
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "-":
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _plain_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    skip_next = False
    after_options = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_next = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes=") or re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _sed_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    scripts_seen = 0
    skip_script = False
    after_options = False
    for arg in args:
        if skip_script:
            skip_script = False
            scripts_seen += 1
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--quiet", "--silent"}:
            continue
        if arg in {"-e", "--expression"}:
            skip_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts_seen += 1
            continue
        if arg.startswith("--expression="):
            scripts_seen += 1
            continue
        if arg.startswith("-"):
            continue
        if scripts_seen == 0:
            scripts_seen += 1
            continue
        operands.append(arg)
    return tuple(operands)


def _search_file_operand_tokens(command_name: str, args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    pattern_seen = False
    skip_next = False
    skip_next_is_operand = False
    after_options = False
    for arg in args:
        if skip_next:
            if skip_next_is_operand:
                operands.append(arg)
            skip_next = False
            skip_next_is_operand = False
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {
            "-A",
            "-B",
            "-C",
            "-e",
            "-f",
            "-g",
            "-m",
            "-t",
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        }:
            skip_next = True
            skip_next_is_operand = command_name in {"grep", "egrep", "fgrep"} and arg == "--include"
            if command_name == "rg" and arg in {"-g", "--glob", "--iglob"}:
                skip_next_is_operand = True
            if arg in {"-e", "--regexp", "-f", "--file"}:
                pattern_seen = True
            continue
        search_value_flags = (
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        )
        if any(arg.startswith(f"{flag}=") for flag in search_value_flags):
            if command_name in {"grep", "egrep", "fgrep"} and arg.startswith("--include="):
                operands.append(arg.split("=", 1)[1])
                continue
            if command_name == "rg" and any(arg.startswith(f"{flag}=") for flag in ("--glob", "--iglob")):
                operands.append(arg.split("=", 1)[1])
                continue
            if arg.startswith(("--regexp=", "--file=")):
                pattern_seen = True
            continue
        option_value_prefixes = ("-A", "-B", "-C", "-m")
        if any(arg.startswith(prefix) and len(arg) > len(prefix) for prefix in option_value_prefixes):
            continue
        if command_name == "rg" and arg.startswith("-g") and len(arg) > 2:
            operands.append(arg[2:])
            continue
        if arg.startswith("-e") and len(arg) > 2:
            pattern_seen = True
            continue
        if arg.startswith("-"):
            continue
        if not pattern_seen:
            pattern_seen = True
            continue
        operands.append(arg)
    return tuple(operands)


def _curl_segment_consumes_stdin(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE:
            if index + 1 < len(args) and args[index + 1].strip("'\"") == "-":
                return True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE):
            if arg.split("=", 1)[1].strip("'\"") == "-":
                return True
            continue
        if arg.startswith("-T") and len(arg) > 2:
            if arg[2:].strip("'\"") == "-":
                return True
            continue
        if arg in _CURL_AT_FILE_FLAGS_WITH_VALUE or arg in _CURL_FORM_FLAGS_WITH_VALUE:
            if index + 1 < len(args) and _curl_value_consumes_stdin(args[index + 1]):
                return True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CURL_AT_FILE_FLAGS_WITH_VALUE | _CURL_FORM_FLAGS_WITH_VALUE):
            if _curl_value_consumes_stdin(arg.split("=", 1)[1]):
                return True
            continue
        if arg.startswith("-d") and len(arg) > 2:
            if _curl_value_consumes_stdin(arg[2:]):
                return True
            continue
        if arg.startswith("-F") and len(arg) > 2:
            if _curl_value_consumes_stdin(arg[2:]):
                return True
            continue
    return False


def _curl_value_consumes_stdin(value: str) -> bool:
    stripped = value.strip("'\"")
    return stripped == "@-" or stripped.endswith("=@-")


def _wget_segment_consumes_stdin(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg in _WGET_UPLOAD_FLAGS_WITH_VALUE:
            return index + 1 < len(args) and args[index + 1].strip("'\"") == "-"
        if any(arg.startswith(f"{flag}=") for flag in _WGET_UPLOAD_FLAGS_WITH_VALUE):
            return arg.split("=", 1)[1].strip("'\"") == "-"
    return False


def _shell_segments_contain_credential_exfiltration(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if command_name in _BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS and command_name not in {"curl", "wget"}:
            continue
        segment_text = _shell_segment_credential_exfiltration_text(
            segment,
            command_name=command_name,
            command_index=command_index,
        )
        if segment_text and _text_contains_credential_exfiltration(segment_text):
            return True
    return False


def _shell_segment_credential_exfiltration_text(
    segment: list[str],
    *,
    command_name: str,
    command_index: int,
) -> str:
    if command_name == "curl":
        return _curl_segment_credential_exfiltration_text(segment, command_index=command_index)
    if command_name == "wget":
        return _wget_segment_credential_exfiltration_text(segment, command_index=command_index)
    return " ".join(segment[command_index:])


def _curl_segment_credential_exfiltration_text(segment: list[str], *, command_index: int) -> str:
    surface_tokens = [
        token
        for token in segment[:command_index]
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token))
    ]
    surface_tokens.append(segment[command_index])
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token == "--":
            surface_tokens.extend(_network_destination_tokens(segment[index + 1 :]))
            break
        clustered_tokens_consumed = _curl_clustered_short_flag_tokens_consumed(segment, index)
        if clustered_tokens_consumed > 1:
            surface_tokens.append(token)
            surface_tokens.append(segment[index + 1])
            index += clustered_tokens_consumed
            continue
        if len(token) == 2 and token[0] == "-" and token[1] in _CURL_SHORT_FLAGS_WITH_VALUES:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            surface_tokens.append(token)
            index += 1
            continue
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE or token in _CURL_AT_FILE_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE or token in _CURL_FORM_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE or token in _CURL_VARIABLE_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE or token in {"-H", "-X"}:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if not token.startswith("-"):
            if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token):
                surface_tokens.append(token)
            index += 1
            continue
        surface_tokens.append(token)
        index += 1
    return " ".join(surface_tokens)


def _wget_segment_credential_exfiltration_text(segment: list[str], *, command_index: int) -> str:
    surface_tokens = [
        token
        for token in segment[:command_index]
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token))
    ]
    surface_tokens.append(segment[command_index])
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token == "--":
            surface_tokens.extend(_network_destination_tokens(segment[index + 1 :]))
            break
        if token in _WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if any(
            token.startswith(f"{flag}=")
            for flag in _WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE
            if flag.startswith("--")
        ):
            surface_tokens.append(token)
            index += 1
            continue
        if not token.startswith("-"):
            if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token):
                surface_tokens.append(token)
            index += 1
            continue
        surface_tokens.append(token)
        index += 1
    return " ".join(surface_tokens)


def _network_destination_tokens(tokens: list[str]) -> list[str]:
    return [token for token in tokens if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token)]


def _text_contains_credential_exfiltration(text: str) -> bool:
    if not _SECRET_EXFILTRATION_SECRET_PATTERN.search(text):
        return False
    if not _SECRET_EXFILTRATION_NETWORK_PATTERN.search(text):
        return False
    return _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(text) is not None


def _contains_encoded_or_encrypted_shell_command(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    executable_surface = _shell_text_without_quoted_literals(normalized)
    if any(pattern.search(executable_surface) for pattern in _ENCODED_EXECUTION_PATTERNS):
        return True
    if _contains_command_substitution_decode_exec(normalized):
        return True
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    for payload in _decoded_shell_payloads(executable_surface):
        if _decoded_payload_looks_sensitive(
            payload,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_encoded_or_encrypted_shell_command(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_encoded_or_encrypted_shell_command(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_encoded_or_encrypted_shell_command(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _contains_command_substitution_decode_exec(command_text: str) -> bool:
    substitution_payloads = _shell_command_substitution_payloads(command_text)
    if not substitution_payloads:
        return False
    if not any(_contains_decode_primitive(payload) for payload in substitution_payloads):
        return False
    lowered = command_text.lower()
    if re.search(r"\b(?:ash|bash|dash|sh|zsh)\b[^\n;|&]*-[A-Za-z]*c[A-Za-z]*", lowered):
        return True
    return bool(re.search(r"\beval\b[^\n;|&]*\$\(", lowered))


def _contains_shell_network_file_upload(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _curl_stdin_config_uses_file_upload(
        normalized,
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    ):
        return True
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            if _segment_uses_network_file_upload(
                segment,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                stdin_uses_local_file=_shell_pipeline_stdin_uses_local_file(
                    pipeline,
                    index,
                    cwd=cwd,
                    home_dir=home_dir,
                ),
            ):
                return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_network_file_upload(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_network_file_upload(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_network_file_upload(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_network_file_upload(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _segment_uses_network_file_upload(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    stdin_uses_local_file: bool = False,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    segment_args = segment[command_index + 1 :]
    if command_name == "curl":
        return _curl_segment_uses_file_upload(
            segment_args,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            stdin_uses_local_file=stdin_uses_local_file,
        )
    if command_name == "wget":
        return _wget_segment_uses_file_upload(segment_args, stdin_uses_local_file=stdin_uses_local_file)
    return False


def _curl_segment_uses_file_upload(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_config_paths: frozenset[str] = frozenset(),
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
    stdin_uses_local_file: bool = False,
) -> bool:
    index = 0
    saw_variable_file_input = False
    saw_variable_expansion = False
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            break
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_config_uses_file_upload(
                value,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                visited_config_paths=visited_config_paths,
                stdin_config_payloads=stdin_config_payloads,
            ):
                return True
            index += 2
            continue
        if (
            token in _CURL_AT_FILE_FLAGS_WITH_VALUE
            or token in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE
            or token in _CURL_FORM_FLAGS_WITH_VALUE
            or token in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE
        ):
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_upload_value_uses_local_file(token, value, stdin_uses_local_file=stdin_uses_local_file):
                return True
            index += 2
            continue
        if token in _CURL_VARIABLE_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(value)
            index += 2
            continue
        if token in _CURL_EXPAND_FLAGS_WITH_VALUE:
            saw_variable_expansion = True
            index += 2
            continue
        if token.startswith("--config=") and _curl_config_uses_file_upload(
            token.split("=", 1)[1],
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        if token.startswith("--data=") and _curl_upload_value_uses_local_file(
            "--data",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-ascii=") and _curl_upload_value_uses_local_file(
            "--data-ascii",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-binary=") and _curl_upload_value_uses_local_file(
            "--data-binary",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--json=") and _curl_upload_value_uses_local_file(
            "--json",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--url-query=") and _curl_upload_value_uses_local_file(
            "--url-query",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-urlencode=") and _curl_upload_value_uses_local_file(
            "--data-urlencode",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-raw=") and _curl_upload_value_uses_local_file(
            "--data-raw",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--form=") and _curl_upload_value_uses_local_file(
            "--form",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--upload-file=") and _curl_upload_value_uses_local_file(
            "--upload-file",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--variable="):
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(
                token.split("=", 1)[1]
            )
            index += 1
            continue
        if token.startswith("--expand-"):
            saw_variable_expansion = True
            index += 1
            continue
        clustered_tokens_consumed = _curl_clustered_short_flag_tokens_consumed(segment_args, index)
        clustered_upload_value = _curl_clustered_short_flag_value(segment_args, index, "T")
        if clustered_upload_value is not None and _curl_upload_value_uses_local_file(
            "-T",
            clustered_upload_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if clustered_config_value is not None and _curl_config_uses_file_upload(
            clustered_config_value,
            cwd=cwd,
            home_dir=home_dir,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        clustered_form_value = _curl_clustered_short_flag_value(segment_args, index, "F")
        if clustered_form_value is not None and _curl_upload_value_uses_local_file("-F", clustered_form_value):
            return True
        clustered_data_value = _curl_clustered_short_flag_value(segment_args, index, "d")
        if clustered_data_value is not None and _curl_upload_value_uses_local_file(
            "-d",
            clustered_data_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        index += clustered_tokens_consumed
    return saw_variable_file_input and saw_variable_expansion


def _curl_stdin_config_uses_file_upload(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> bool:
    heredoc_payloads = _shell_heredoc_payloads(command_text)
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            command_name, command_index = _shell_segment_primary_command(segment)
            if command_name != "curl" or command_index is None:
                continue
            segment_args = segment[command_index + 1 :]
            pipeline_stdin_payloads = _shell_pipeline_stdin_payloads(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
            )
            pipeline_stdin_uses_local_file = _shell_pipeline_stdin_uses_local_file(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
            )
            if pipeline_stdin_payloads and _curl_segment_uses_file_upload(
                segment_args,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                stdin_config_payloads=pipeline_stdin_payloads,
                stdin_uses_local_file=pipeline_stdin_uses_local_file,
            ):
                return True
            if (
                heredoc_payloads
                and not pipeline_stdin_payloads
                and _curl_segment_reads_config_from_stdin(segment_args)
                and _command_uses_curl_stdin_heredoc(command_text)
                and _curl_segment_uses_file_upload(
                    segment_args,
                    cwd=cwd,
                    home_dir=home_dir,
                    stdin_config_payloads=tuple((payload, cwd) for payload in heredoc_payloads),
                )
            ):
                return True
    return False


def _curl_segment_reads_config_from_stdin(segment_args: list[str]) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _strip_cli_value(_shell_command_token_without_attached_redirection(value)) == "-":
                return True
            index += 2
            continue
        if (
            token.startswith("--config=")
            and _strip_cli_value(_shell_command_token_without_attached_redirection(token.split("=", 1)[1])) == "-"
        ):
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if (
            clustered_config_value is not None
            and _strip_cli_value(_shell_command_token_without_attached_redirection(clustered_config_value)) == "-"
        ):
            return True
        index += 1
    return False


def _curl_inline_config_text_uses_file_upload(config_text: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    if not config_text or len(config_text.encode("utf-8", errors="ignore")) > _MAX_DECODED_PAYLOAD_BYTES:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(config_args, cwd=cwd, home_dir=home_dir)


def _shell_pipeline_stdin_uses_local_file(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    stdin_uses_local_file = False
    for upstream_segment in pipeline[:index]:
        stdin_uses_local_file = _shell_segment_stdout_uses_local_file(
            upstream_segment,
            stdin_uses_local_file=stdin_uses_local_file,
            cwd=cwd,
            home_dir=home_dir,
        )
    return stdin_uses_local_file or _shell_stdin_redirect_uses_local_file(
        pipeline[index],
        cwd=cwd,
        home_dir=home_dir,
    )


def _shell_pipeline_stdin_payloads(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: tuple[tuple[str, Path | None], ...] = ()
    for upstream_segment in pipeline[:index]:
        payloads = _shell_segment_stdout_payloads(
            upstream_segment,
            stdin_payloads=payloads,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
        )
    current_redirect_payloads = _shell_stdin_redirect_payloads(
        pipeline[index],
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    )
    return current_redirect_payloads or payloads


def _shell_stdout_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return ()
    segment_args = segment[command_index + 1 :]
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir, allowed_roots=allowed_roots)
    return ()


def _shell_segment_stdout_payloads(
    segment: list[str],
    *,
    stdin_payloads: tuple[tuple[str, Path | None], ...],
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_payloads
    segment_args = segment[command_index + 1 :]
    redirected_input_payloads = _shell_stdin_redirect_payloads(
        segment,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    )
    effective_input_payloads = redirected_input_payloads or stdin_payloads
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return (
            _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir, allowed_roots=allowed_roots)
            or effective_input_payloads
        )
    if command_name in {"sed", "tr"}:
        return effective_input_payloads
    return ()


def _shell_stdout_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "cat" or command_index is None:
        return False
    return _cat_reads_local_file(segment[command_index + 1 :], cwd=cwd, home_dir=home_dir)


def _shell_segment_stdout_uses_local_file(
    segment: list[str],
    *,
    stdin_uses_local_file: bool,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_uses_local_file
    if _shell_stdin_redirect_uses_local_file(segment, cwd=cwd, home_dir=home_dir):
        return True
    segment_args = segment[command_index + 1 :]
    if command_name == "cat":
        return _cat_reads_local_file(segment_args, cwd=cwd, home_dir=home_dir) or stdin_uses_local_file
    if command_name in {"echo", "printf"}:
        return False
    return stdin_uses_local_file


def _printf_stdout_payloads(segment_args: list[str]) -> tuple[str, ...]:
    args = list(segment_args)
    if args and args[0] == "--":
        args = args[1:]
    decoded_args = tuple(decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded)
    if not decoded_args:
        return ()
    if len(decoded_args) == 1:
        return decoded_args
    return (*decoded_args, "\n".join(decoded_args))


def _echo_stdout_payload(segment_args: list[str]) -> str | None:
    args = list(segment_args)
    while args and args[0] in {"-n", "-e", "-E"}:
        args = args[1:]
    if not args:
        return None
    decoded_parts = [decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded]
    if not decoded_parts:
        return None
    return " ".join(decoded_parts)


def _cat_stdout_payloads(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    consume_all = False
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        config_path = _resolved_runtime_path(token, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
        if config_path is None:
            continue
        payload_text = _read_small_runtime_text_file(
            config_path,
            allowed_roots=read_roots,
        )
        if payload_text is None:
            continue
        payloads.append((payload_text, config_path.parent))
    return tuple(payloads)


def _cat_reads_local_file(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    consume_all = False
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        if _looks_like_local_stdin_source(token):
            return True
    return False


def _shell_stdin_redirect_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<<<" and index + 1 < len(segment):
            payload_text = _decode_shell_text_literal(segment[index + 1])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 2
            continue
        if token.startswith("<<<"):
            payload_text = _decode_shell_text_literal(token[3:])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 1
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None:
            redirect_payload = _stdin_redirect_payload(
                redirect_target,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
            )
            if redirect_payload is not None:
                payloads.append(redirect_payload)
            index += tokens_consumed
            continue
        index += 1
    return tuple(payloads)


def _shell_stdin_redirect_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<" and index + 1 < len(segment):
            if _stdin_redirect_uses_local_file(segment[index + 1], cwd=cwd, home_dir=home_dir):
                return True
            index += 2
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None and _stdin_redirect_uses_local_file(
            redirect_target,
            cwd=cwd,
            home_dir=home_dir,
        ):
            return True
        index += tokens_consumed if redirect_target is not None else 1
    return False


def _stdin_redirect_payload(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[str, Path | None] | None:
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    config_path = _resolved_runtime_path(target, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
    if config_path is None:
        return None
    payload_text = _read_small_runtime_text_file(
        config_path,
        allowed_roots=read_roots,
    )
    if payload_text is None:
        return None
    return payload_text, config_path.parent


def _stdin_redirect_uses_local_file(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    return _looks_like_local_stdin_source(target)


def _looks_like_local_stdin_source(value: str) -> bool:
    stripped_value = _strip_cli_value(value).lower()
    return bool(
        stripped_value
        and stripped_value not in {"-", "@-"}
        and stripped_value not in _SAFE_SHELL_REDIRECT_TARGETS
        and not stripped_value.startswith("&")
    )


def _stdin_redirect_target_from_token(token: str, *, next_token: str | None) -> tuple[str | None, int]:
    if _token_is_heredoc_operator(token):
        return None, 1
    if token in {"<", "0<"}:
        if next_token is None:
            return None, 1
        return next_token, 2
    if token.count("<") != 1:
        return None, 1
    fd, target = token.split("<", 1)
    if fd not in {"", "0"} or not target:
        return None, 1
    return target, 1


def _token_is_heredoc_operator(token: str) -> bool:
    return "<<" in token


def _decode_shell_text_literal(value: str) -> str | None:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return None
    try:
        return bytes(stripped_value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return stripped_value


def _wget_segment_uses_file_upload(segment_args: list[str], *, stdin_uses_local_file: bool = False) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _WGET_UPLOAD_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _direct_file_operand_uses_local_file(value, stdin_uses_local_file=False):
                return True
            index += 2
            continue
        if token.startswith("--body-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=False
        ):
            return True
        if token.startswith("--post-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=False
        ):
            return True
        index += 1
    return False


def _curl_upload_value_uses_local_file(flag: str, value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = value.strip()
    if flag in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE:
        return _direct_file_operand_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)
    if flag in _CURL_FORM_FLAGS_WITH_VALUE:
        return _curl_form_value_uses_local_file(stripped_value)
    if flag in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE:
        return _curl_data_urlencode_value_uses_local_file(stripped_value)
    if flag == "--data-raw":
        return False
    return _value_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)


def _curl_form_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    field_value = stripped_value.split("=", 1)[1] if "=" in stripped_value else stripped_value
    if not field_value or field_value[0] not in {"@", "<"}:
        return False
    return _direct_file_operand_uses_local_file(re.split(r"[;,]", field_value[1:], maxsplit=1)[0])


def _curl_data_urlencode_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value.startswith("@"):
        return _value_uses_local_file(stripped_value)
    if "@" not in stripped_value:
        return False
    name, file_candidate = stripped_value.split("@", 1)
    if "=" in name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_variable_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if "@" not in stripped_value:
        return False
    variable_name, file_candidate = stripped_value.split("@", 1)
    normalized_name = variable_name.lstrip("%")
    if not normalized_name or "=" in normalized_name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_config_uses_file_upload(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_config_paths: frozenset[str],
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
) -> bool:
    normalized_value = _shell_command_token_without_attached_redirection(value)
    stripped_value = _strip_cli_value(normalized_value)
    if stripped_value == "-":
        return any(
            _curl_inline_config_text_uses_file_upload(payload_text, cwd=payload_cwd, home_dir=home_dir)
            for payload_text, payload_cwd in stdin_config_payloads
        )
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    config_file = _resolved_runtime_path(normalized_value, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
    if config_file is None:
        return False
    normalized_config_path = str(config_file)
    if normalized_config_path in visited_config_paths:
        return False
    config_text = _read_small_runtime_text_file(
        config_file,
        allowed_roots=read_roots,
    )
    if config_text is None:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(
        config_args,
        cwd=config_file.parent,
        home_dir=home_dir,
        allowed_roots=read_roots,
        visited_config_paths=visited_config_paths | frozenset({normalized_config_path}),
        stdin_config_payloads=stdin_config_payloads,
    )


def _curl_config_arguments(config_text: str) -> list[str]:
    arguments: list[str] = []
    for raw_line in config_text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped_line, comments=True, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        if len(tokens) == 1 and not tokens[0].startswith("-") and ":" in tokens[0] and not tokens[0].endswith(":"):
            option_name, option_value = tokens[0].split(":", 1)
            if option_name and option_value:
                tokens = [option_name, option_value]
        if tokens[0].endswith(":"):
            tokens[0] = tokens[0][:-1]
        elif len(tokens) >= 3 and tokens[1] in {"=", ":"}:
            tokens = [tokens[0], *tokens[2:]]
        first_token = tokens[0]
        if not first_token.startswith("-"):
            first_token = f"--{first_token}"
        tokens[0] = first_token
        arguments.extend(tokens)
    return arguments


def _command_uses_curl_stdin_heredoc(command_text: str) -> bool:
    parts = _split_shell_parts(command_text)
    for segment in _iter_shell_command_segments(parts):
        if not any(_token_is_heredoc_operator(token) for token in segment):
            continue
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "curl" or command_index is None:
            continue
        if _curl_segment_reads_config_from_stdin(segment[command_index + 1 :]):
            return True
    return False


def _shell_heredoc_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    lines = command_text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        match = _HEREDOC_PATTERN.search(line)
        if match is None:
            line_index += 1
            continue
        delimiter = match.group(2)
        strip_tabs = line[match.start() :].startswith("<<-")
        body_lines: list[str] = []
        line_index += 1
        while line_index < len(lines):
            candidate_line = lines[line_index]
            normalized_line = candidate_line.lstrip("\t") if strip_tabs else candidate_line
            if normalized_line == delimiter:
                line_index += 1
                break
            body_lines.append(normalized_line if strip_tabs else candidate_line)
            line_index += 1
        payload = "\n".join(body_lines).strip()
        if payload:
            payloads.append(payload)
    return tuple(payloads)


def _curl_clustered_short_flag_value(segment_args: list[str], index: int, flag_character: str) -> str | None:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag == flag_character:
            attached_value = cluster[flag_index + 1 :]
            if attached_value:
                return attached_value
            return segment_args[index + 1] if index + 1 < len(segment_args) else ""
        if cluster_flag in _CURL_SHORT_FLAGS_WITH_VALUES:
            return None
    return None


def _curl_clustered_short_flag_tokens_consumed(segment_args: list[str], index: int) -> int:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return 1
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag not in _CURL_SHORT_FLAGS_WITH_VALUES:
            continue
        attached_value = cluster[flag_index + 1 :]
        if attached_value:
            return 1
        return 2 if index + 1 < len(segment_args) else 1
    return 1


def _direct_file_operand_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value in {"-", "@-"}:
        return stdin_uses_local_file
    return True


def _strip_cli_value(value: str) -> str:
    return value.strip().strip("'").strip('"')


def _value_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value == "@-":
        return stdin_uses_local_file
    if stripped_value.startswith("@"):
        return stripped_value[1:] != "-"
    return False


def _contains_decode_primitive(command_text: str) -> bool:
    lowered = command_text.lower()
    return bool(
        re.search(r"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))", lowered)
        or re.search(r"\bxxd\s+(?:-r\s+-p|-rp)\b", lowered)
        or re.search(r"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b", lowered)
        or re.search(r"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b", lowered)
    )


def _shell_text_without_quoted_literals(command_text: str) -> str:
    characters: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            if character == "'":
                single_quoted = False
            characters.append(" ")
            index += 1
            continue
        if double_quoted:
            if character == "\\":
                characters.append(" ")
                if index + 1 < len(command_text):
                    characters.append(" ")
                    index += 2
                else:
                    index += 1
                continue
            if character == '"':
                double_quoted = False
                characters.append(" ")
                index += 1
                continue
            if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                characters.append(f"$({payload})")
                index = next_index
                continue
            if character == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                characters.append(f"`{payload}`")
                index = next_index
                continue
            characters.append(" ")
            index += 1
            continue
        if character == "'":
            single_quoted = True
            characters.append(" ")
            index += 1
            continue
        if character == '"':
            double_quoted = True
            characters.append(" ")
            index += 1
            continue
        characters.append(character)
        index += 1
    return "".join(characters)


def _shell_command_substitution_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        if single_quoted:
            if command_text[index] == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            if command_text[index] == "\\" and index + 1 < len(command_text):
                index += 2
                continue
            if command_text[index] == '"':
                double_quoted = False
                index += 1
                continue
            if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            if command_text[index] == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            index += 1
            continue
        if command_text[index] == "\\" and index + 1 < len(command_text):
            index += 2
            continue
        if command_text[index] == "'":
            single_quoted = True
            index += 1
            continue
        if command_text[index] == '"':
            double_quoted = True
            index += 1
            continue
        if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] in "<>" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] == "`":
            payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        index += 1
    return tuple(payloads)


def _read_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    depth = 1
    payload_characters: list[str] = []
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            payload_characters.append(character)
            if character == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            payload_characters.append(character)
            if character == "\\" and index + 1 < len(command_text):
                payload_characters.append(command_text[index + 1])
                index += 2
                continue
            if character == '"':
                double_quoted = False
            index += 1
            continue
        if character == "'":
            single_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == '"':
            double_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "(":
            depth += 1
            payload_characters.append(character)
            index += 1
            continue
        if character == ")":
            depth -= 1
            if depth == 0:
                return "".join(payload_characters), index + 1
            payload_characters.append(character)
            index += 1
            continue
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _read_backtick_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    payload_characters: list[str] = []
    while index < len(command_text):
        character = command_text[index]
        if character == "\\" and index + 1 < len(command_text):
            payload_characters.append(character)
            payload_characters.append(command_text[index + 1])
            index += 2
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "`":
            return "".join(payload_characters), index + 1
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _decoded_payload_looks_sensitive(
    payload: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int,
    visited_script_paths: frozenset[str],
) -> bool:
    lowered = payload.lower()
    if _looks_destructive_shell_command(payload, cwd=cwd, home_dir=home_dir):
        return True
    if any(token in lowered for token in _SENSITIVE_DECODED_PAYLOAD_TOKENS):
        return True
    return _contains_encoded_or_encrypted_shell_command(
        payload,
        cwd=cwd,
        home_dir=home_dir,
        depth=depth,
        visited_script_paths=visited_script_paths,
    )


def _decoded_shell_payloads(command_text: str) -> tuple[str, ...]:
    lowered = command_text.lower()
    payloads: list[str] = []
    if any(
        token in lowered
        for token in ("base64", "b64decode", "frombase64string", "-encodedcommand", " -enc ", "openssl", "gpg")
    ):
        for literal in _BASE64_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_base64_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    if "xxd" in lowered:
        for literal in _HEX_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_hex_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    return tuple(payloads)


def _decode_base64_literal(literal: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(literal, validate=True)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decode_hex_literal(literal: str) -> str | None:
    if len(literal) % 2 != 0:
        return None
    try:
        decoded_bytes = binascii.unhexlify(literal)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decoded_bytes_to_text(decoded_bytes: bytes) -> str | None:
    if not decoded_bytes or len(decoded_bytes) > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = decoded_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _text_is_probably_source(text):
            return text
    return None


def _text_is_probably_source(text: str) -> bool:
    if not text.strip():
        return False
    printable = sum(1 for character in text if character.isprintable() or character in "\n\r\t")
    return printable / len(text) >= 0.85


def _local_shell_script_payloads(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_script_paths: frozenset[str],
) -> tuple[tuple[str, Path | None, str], ...]:
    payloads: list[tuple[str, Path | None, str]] = []
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_index is None:
            continue
        script_path = _shell_script_path_for_segment(segment, command_name=command_name, command_index=command_index)
        if script_path is None:
            continue
        script_file = _resolved_runtime_path(script_path, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
        if script_file is None:
            continue
        normalized_script_path = str(script_file)
        if normalized_script_path in visited_script_paths:
            continue
        script_text = _read_small_runtime_text_file(
            script_file,
            allowed_roots=read_roots,
        )
        if script_text is None:
            continue
        payloads.append((script_text, script_file.parent, normalized_script_path))
    return tuple(payloads)


def _shell_script_path_for_segment(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int,
) -> str | None:
    if command_name in _SHELL_SCRIPT_INTERPRETER_COMMANDS:
        return _shell_script_path_from_segment(segment[command_index + 1 :])
    command_token = segment[command_index].strip()
    if not command_token or command_token.startswith("-") or _SHELL_ASSIGNMENT_PATTERN.match(command_token):
        return None
    if not _is_explicit_shell_script_path_token(command_token):
        return None
    return command_token


def _shell_script_path_from_segment(segment_args: list[str]) -> str | None:
    index = 0
    while index < len(segment_args):
        token = segment_args[index].strip()
        if not token:
            index += 1
            continue
        if token == "--":
            index += 1
            break
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        if token == "-s":
            return None
        if token.startswith("-") and not token.startswith("--") and "c" in token[1:]:
            return None
        if not token.startswith("-") and not token.startswith("+"):
            return token
        if token in {"-c", "--command"} or token.startswith(("-c", "--command=")):
            return None
        if token in {"-O", "-o", "+O", "+o", "--rcfile", "--init-file"}:
            index += 2
            continue
        if token.startswith(("--rcfile=", "--init-file=")):
            index += 1
            continue
        index += 1
    while index < len(segment_args):
        token = segment_args[index].strip()
        if token:
            return token
        index += 1
    return None


def _is_explicit_shell_script_path_token(token: str) -> bool:
    normalized_token = token.strip()
    if not normalized_token:
        return False
    return (
        normalized_token.startswith((".", "/", "~"))
        or normalized_token.startswith("../")
        or normalized_token.startswith("./")
        or "/" in normalized_token
    )


def build_tool_action_request_artifact(
    harness: str,
    request: ToolActionRequestMatch,
    *,
    config_path: str,
    source_scope: str,
    extension_control_layers: tuple[ExtensionControlLayer, ...] = (),
) -> GuardArtifact:
    """Build a Guard artifact for a sensitive native tool action request."""

    policy_command = request.raw_command_text or request.command_text
    evaluation = evaluate_command(
        policy_command,
        canonical_command=(request.canonical_command if request.raw_command_text is None else None),
        compatibility_action_class=request.action_class,
        compatibility_reason=request.reason,
        extension_control_layers=extension_control_layers,
    )
    wrapper_chain = tuple(dict.fromkeys((*evaluation.command.wrapper_chain, *request.wrapper_chain)))
    fingerprint_payload = {
        "harness": harness,
        "tool_name": request.normalized_tool_name,
        "command_text": request.command_text,
        "action_class": request.action_class,
        "shell_execution_context_hash": request.shell_execution_context_hash,
        "interpreter_executable_identities": request.interpreter_executable_identities,
    }
    if request.restricted_profile_version is not None:
        fingerprint_payload["restricted_profile_version"] = request.restricted_profile_version
    if request.pytest_config_identity_sha256 is not None:
        fingerprint_payload["pytest_config_identity_sha256"] = request.pytest_config_identity_sha256
    fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True).encode("utf-8")).hexdigest()
    request_summary = f"Requested `{request.tool_name}` action `{request.command_text}` ({request.action_class})."
    if wrapper_chain:
        request_summary = (
            f"Requested `{request.tool_name}` action `{request.command_text}` via transparent wrappers "
            f"`{' -> '.join(wrapper_chain)}` ({request.action_class})."
        )
    risk_summary = f"Requests a sensitive native tool action: {request.action_class}."
    runtime_reason = request.reason
    if wrapper_chain:
        runtime_reason = (
            f"Guard normalized the transparent wrapper chain {' -> '.join(wrapper_chain)} "
            f"before evaluation. {request.reason}"
        )
    execution_context_metadata: dict[str, object] = {}
    if request.shell_execution_context_hash is not None:
        effective_cwds = list(request.shell_execution_effective_cwds)
        execution_context_metadata = {
            "shell_execution_context_hash": request.shell_execution_context_hash,
            "shell_execution_context_complete": request.shell_execution_context_reason_code is None,
            "shell_execution_context_reason_code": request.shell_execution_context_reason_code,
            "shell_execution_effective_cwds": effective_cwds,
            "effective_cwd": effective_cwds[-1] if effective_cwds else None,
        }
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:tool-action:{fingerprint}",
        name=f"{request.tool_name} {request.action_class}",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        command=policy_command,
        metadata={
            "tool_name": request.tool_name,
            "command_text": request.command_text,
            "action_class": request.action_class,
            "request_summary": request_summary,
            "runtime_request_signals": [f"invokes a sensitive native tool action: {request.action_class}"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": runtime_reason,
            "raw_command_text": request.raw_command_text,
            "wrapper_chain": list(wrapper_chain),
            "command_security_identity": evaluation.command.security_identity,
            "command_action_floor": evaluation.decision_plane.action,
            "command_decision_plane": effect_decision_to_dict(evaluation.decision_plane),
            "extension_control_resolution": {
                "blocked": evaluation.control_resolution.blocked,
                "failures": [failure.code.value for failure in evaluation.control_resolution.failures],
            },
            "command_rule_matches": [owned.to_dict() for owned in evaluation.matches],
            "risk_classes": list(evaluation.risk_classes),
            "command_parse_confidence": evaluation.command.confidence,
            "command_uncertainty_reason": evaluation.command.uncertainty_reason,
            "interpreter_executable_identities": [
                dict(identity) for identity in request.interpreter_executable_identities
            ],
            **execution_context_metadata,
            **(
                {"guard_default_action": request.guard_default_action}
                if request.guard_default_action is not None
                else {}
            ),
            **({"reason_code": request.reason_code} if request.reason_code is not None else {}),
            **(
                {
                    "pytest_config_identity_sha256": request.pytest_config_identity_sha256,
                    "pytest_config_sources": list(request.pytest_config_sources),
                    "pytest_config_complete": not request.pytest_config_reason_codes,
                    "pytest_config_reason_codes": list(request.pytest_config_reason_codes),
                }
                if request.pytest_config_identity_sha256 is not None
                else {}
            ),
            **(
                {
                    "restricted_profile_version": request.restricted_profile_version,
                    "restricted_capabilities": {
                        "workspace": "read-write",
                        "private_temporary_directory": "read-write",
                        "host_home": "denied",
                        "host_secret_environment": "denied",
                        "network": "denied",
                        "outside_writes": "denied",
                        "process_execution": "approved-interpreter-runtime-only",
                    },
                }
                if request.restricted_profile_version is not None
                else {}
            ),
        },
    )


def _request_with_wrapper_context(
    request: ToolActionRequestMatch,
    *,
    raw_command_text: str,
    wrapper_chain: tuple[str, ...],
) -> ToolActionRequestMatch:
    return ToolActionRequestMatch(
        tool_name=request.tool_name,
        normalized_tool_name=request.normalized_tool_name,
        command_text=request.command_text,
        action_class=request.action_class,
        reason=request.reason,
        raw_command_text=raw_command_text,
        wrapper_chain=wrapper_chain,
        canonical_command=request.canonical_command,
        shell_execution_context_hash=request.shell_execution_context_hash,
        shell_execution_context_reason_code=request.shell_execution_context_reason_code,
        shell_execution_effective_cwds=request.shell_execution_effective_cwds,
        guard_default_action=request.guard_default_action,
        reason_code=request.reason_code,
        restricted_profile_version=request.restricted_profile_version,
        pytest_config_identity_sha256=request.pytest_config_identity_sha256,
        pytest_config_sources=request.pytest_config_sources,
        pytest_config_reason_codes=request.pytest_config_reason_codes,
        interpreter_executable_identities=request.interpreter_executable_identities,
    )


def _request_with_shell_execution_context(
    request: ToolActionRequestMatch,
    *,
    command_text: str,
    cwd: Path | None,
    context: ShellExecutionContext | None = None,
) -> ToolActionRequestMatch:
    context = context or model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
    if not context.directory_change_present:
        return request
    reason_code = _shell_execution_context_validation_reason(context)
    return replace(
        request,
        shell_execution_context_hash=context.context_hash,
        shell_execution_context_reason_code=reason_code,
        shell_execution_effective_cwds=tuple(str(path) for path in context.effective_cwds),
    )


def _candidate_paths(value: object, *, include_apply_patch: bool = False) -> list[str]:
    results: list[str] = []
    _collect_candidate_paths(value, results, depth=0)
    if include_apply_patch and isinstance(value, dict):
        results.extend(apply_patch_target_paths(value))
    return results


def _collect_candidate_paths(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, dict):
        for key in _PATH_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                results.append(candidate)
        for key in _PATH_LIST_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, list):
                results.extend(item for item in candidate if isinstance(item, str) and item.strip())
        for child in value.values():
            if isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return
    if isinstance(value, list):
        for child in value:
            if isinstance(child, str) and child.strip():
                results.append(child)
            elif isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return


def _candidate_command_texts(value: object) -> list[str]:
    results: list[str] = []
    _collect_candidate_commands(value, results, depth=0)
    return results


def command_list_candidate_texts(
    values: list[str],
    *,
    preserve_items: bool = False,
) -> tuple[str, ...]:
    string_values = [item.strip() for item in values if isinstance(item, str) and item.strip()]
    if not string_values:
        return ()
    if preserve_items:
        return tuple(string_values)
    if len(string_values) == 1:
        return (string_values[0],)
    return (shlex.join(string_values),)


def _collect_candidate_commands(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            results.append(stripped)
        return
    if isinstance(value, list):
        results.extend(command_list_candidate_texts(value))
        for child in value:
            if isinstance(child, (dict, list)):
                _collect_candidate_commands(child, results, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key in _COMMAND_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            results.append(candidate.strip())
    for key in COMMAND_CANDIDATE_LIST_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, list):
            results.extend(command_list_candidate_texts(candidate, preserve_items=key in COMMAND_SEQUENCE_KEYS))
    for key, child in value.items():
        if key in COMMAND_CANDIDATE_LIST_KEYS:
            continue
        if isinstance(child, (dict, list)):
            _collect_candidate_commands(child, results, depth=depth + 1)


def _expand_home(value: str, home_dir: Path | None) -> str:
    if value == "~":
        return str(home_dir or Path.home())
    if value.startswith("~/") or value.startswith("~\\"):
        base = home_dir or Path.home()
        return str(base / value[2:])
    return value


def _normalize_path(value: str, cwd: Path | None) -> str:
    if os.path.isabs(value):
        return os.path.normpath(value)
    if cwd is not None:
        return os.path.normpath(os.path.join(str(cwd), value))
    return os.path.normpath(value)


def _runtime_read_roots(cwd: Path | None, home_dir: Path | None) -> tuple[Path, ...]:
    roots: list[Path] = []
    for candidate in (cwd, home_dir or Path.home()):
        if candidate is None:
            continue
        try:
            resolved_candidate = candidate.resolve(strict=False)
        except OSError:
            continue
        if resolved_candidate not in roots:
            roots.append(resolved_candidate)
    return tuple(roots)


def _path_is_within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    path_text = os.path.realpath(os.fspath(path))
    root_texts = _runtime_read_root_texts(roots)
    return any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts)


def _path_text_is_within_root(path_text: str, root: Path) -> bool:
    return _path_text_is_within_root_text(path_text, os.path.realpath(os.fspath(root)))


def _path_text_is_within_root_text(path_text: str, root_text: str) -> bool:
    normalized_path_text = os.path.normcase(path_text)
    normalized_root_text = os.path.normcase(root_text)
    try:
        return os.path.commonpath((normalized_path_text, normalized_root_text)) == normalized_root_text
    except ValueError:
        return False


def _runtime_read_root_texts(roots: tuple[Path, ...]) -> tuple[str, ...]:
    return tuple(os.path.realpath(os.fspath(root)) for root in roots)


def _runtime_relative_parts(path_text: str, root_text: str) -> tuple[str, ...] | None:
    try:
        relative_text = os.path.relpath(path_text, root_text)
    except ValueError:
        return None
    if relative_text in {"", "."}:
        return None
    parts = Path(relative_text).parts
    if not parts or any(_runtime_relative_part_is_unsafe(part) for part in parts):
        return None
    return parts


def _runtime_relative_part_is_unsafe(part: str) -> bool:
    if part in {"", ".", ".."}:
        return True
    separators = (os.sep, os.altsep) if os.altsep else (os.sep,)
    return any(separator in part for separator in separators)


def _runtime_entry_name_matches(
    entry_name: str,
    requested_name: str,
    *,
    entry_path: str,
    requested_path: str,
) -> bool:
    if entry_name == requested_name or os.path.normcase(entry_name) == os.path.normcase(requested_name):
        return True
    if entry_name.casefold() != requested_name.casefold():
        return False
    try:
        return os.path.samefile(entry_path, requested_path)
    except OSError:
        return False


def _runtime_entry_for_name(directory_text: str, requested_name: str) -> os.DirEntry[str] | None:
    requested_path = os.path.join(directory_text, requested_name)
    try:
        with os.scandir(directory_text) as entries:
            return next(
                (
                    entry
                    for entry in entries
                    if _runtime_entry_name_matches(
                        entry.name,
                        requested_name,
                        entry_path=entry.path,
                        requested_path=requested_path,
                    )
                ),
                None,
            )
    except OSError:
        return None


def _runtime_file_entry_under_root(path_text: str, root_text: str) -> os.DirEntry[str] | None:
    relative_parts = _runtime_relative_parts(path_text, root_text)
    if relative_parts is None:
        return None
    current_dir_text = root_text
    for directory_name in relative_parts[:-1]:
        directory_entry = _runtime_entry_for_name(current_dir_text, directory_name)
        if directory_entry is None:
            return None
        try:
            directory_stat = directory_entry.stat(follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISDIR(directory_stat.st_mode):
            return None
        current_dir_text = os.path.realpath(directory_entry.path)
        if not _path_text_is_within_root_text(current_dir_text, root_text):
            return None
    return _runtime_entry_for_name(current_dir_text, relative_parts[-1])


def _resolved_runtime_path(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> Path | None:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return None
    expanded_value = _expand_home(stripped_value, home_dir)
    normalized_path = Path(_normalize_path(expanded_value, cwd))
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    if not read_roots:
        return None
    path_text = os.path.realpath(os.fspath(normalized_path))
    root_texts = _runtime_read_root_texts(read_roots)
    if not any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts):
        return None
    return Path(path_text)


def _read_small_runtime_text_file(path: Path, *, allowed_roots: tuple[Path, ...]) -> str | None:
    path_text = os.path.realpath(os.fspath(path))
    root_texts = _runtime_read_root_texts(allowed_roots)
    if not any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts):
        return None
    runtime_entry = next(
        (
            entry
            for root_text in root_texts
            if _path_text_is_within_root_text(path_text, root_text)
            for entry in (_runtime_file_entry_under_root(path_text, root_text),)
            if entry is not None
        ),
        None,
    )
    if runtime_entry is None:
        return None
    open_flags = os.O_RDONLY
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if isinstance(nofollow_flag, int):
        open_flags |= nofollow_flag
    try:
        entry_stat = runtime_entry.stat(follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(entry_stat.st_mode) or entry_stat.st_size > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    try:
        descriptor = os.open(runtime_entry.path, open_flags)
    except OSError:
        return None
    try:
        stat_result = os.fstat(descriptor)
        if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size > _MAX_DECODED_PAYLOAD_BYTES:
            os.close(descriptor)
            return None
        with os.fdopen(descriptor, encoding="utf-8") as runtime_file:
            content = runtime_file.read(_MAX_DECODED_PAYLOAD_BYTES + 1)
            return content if len(content) <= _MAX_DECODED_PAYLOAD_BYTES else None
    except (OSError, UnicodeDecodeError):
        with contextlib.suppress(OSError):
            os.close(descriptor)
        return None


def _normalize_tool_name(tool_name: object) -> str | None:
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    return tool_name.strip().lower()


def _docker_sensitive_reason(command_text: str, *, _inherited_sensitive_env: bool = False) -> str | None:
    parts = _split_shell_parts(command_text.strip())
    exported_env_context: dict[str, bool] = {}
    for segment in _iter_shell_command_segments(parts):
        if segment and _normalized_shell_command_name(segment[0]) == "env":
            parsed_env = parse_env_wrapper(segment[1:])
            if not parsed_env.complete:
                return "env-wrapper-unresolved"
            env_sensitive = False if parsed_env.option_effects.ignore_environment else _inherited_sensitive_env
            env_sensitive = env_sensitive or _docker_env_assignments_are_sensitive(
                parsed_env.environment_delta.assignments
            )
            if parsed_env.executable_argv:
                remaining_reason = _docker_sensitive_reason(
                    shlex.join(parsed_env.executable_argv),
                    _inherited_sensitive_env=env_sensitive,
                )
                if remaining_reason is not None:
                    return remaining_reason
            continue
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name == "export" and command_index is not None:
            exported_env_context.update(_docker_exported_env_context_sensitivity(segment[:command_index]))
            exported_env_context.update(_docker_exported_env_context_sensitivity(segment[command_index + 1 :]))
            continue
        if command_name != "docker" or command_index is None:
            continue
        sensitive_env_context = (
            _inherited_sensitive_env
            or any(exported_env_context.values())
            or _docker_env_context_is_sensitive(segment[:command_index])
        )
        global_tokens = segment[command_index + 1 :]
        subcommand_index = _docker_subcommand_index(global_tokens)
        if subcommand_index is None:
            continue
        sensitive_context = sensitive_env_context or _docker_global_context_is_sensitive(
            global_tokens[:subcommand_index]
        )
        args = global_tokens[subcommand_index:]
        subcommand = args[0].lower()
        if _docker_subcommand_help_requested(args):
            continue
        if subcommand in _DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS:
            return subcommand
        if subcommand in _DOCKER_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(args[1:]):
            return "build-sensitive-flags"
        if subcommand == _DOCKER_COMPOSE_SUBCOMMAND:
            reason = _docker_compose_sensitive_reason(args[1:], sensitive_context=sensitive_context)
            if reason is not None:
                return reason
            continue
        if subcommand == "buildx" and len(args) > 1:
            buildx_subcommand_index = _docker_buildx_subcommand_index(args[1:])
            if buildx_subcommand_index is None:
                continue
            buildx_args = args[1 + buildx_subcommand_index :]
            buildx_subcommand = buildx_args[0].lower()
            if buildx_subcommand in _DOCKER_BUILDX_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(
                buildx_args[1:]
            ):
                return "buildx-build-sensitive-flags"
    return None


def _docker_subcommand_help_requested(args: list[str]) -> bool:
    for index, token in enumerate(args[1:], start=1):
        if token != "--help":
            continue
        return all(previous.startswith("-") for previous in args[1:index])
    return False


def _docker_subcommand_index(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return index + 1 if index + 1 < len(args) else None
        if _docker_global_option_has_value(token):
            index += 1 if "=" in token else 2
            continue
        if _docker_global_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return index
    return None


def _docker_global_option_has_value(token: str) -> bool:
    # Accept both long attached values like --host=... and short forms like -H=....
    return token in _DOCKER_GLOBAL_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_GLOBAL_OPTIONS_WITH_VALUES
    )


def _docker_global_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_GLOBAL_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_GLOBAL_FLAG_OPTIONS
    )


def _docker_global_context_is_sensitive(global_tokens: list[str]) -> bool:
    index = 0
    while index < len(global_tokens):
        token = global_tokens[index]
        attached_short = _docker_attached_short_context_option(token)
        if attached_short is not None:
            flag, value = attached_short
            if _docker_global_context_value_is_sensitive(flag, value):
                return True
            index += 1
            continue
        if _docker_global_option_has_value(token):
            if "=" in token:
                flag, value = token.split("=", 1)
                if _docker_global_context_value_is_sensitive(flag, value):
                    return True
                index += 1
                continue
            flag = token
            value = global_tokens[index + 1] if index + 1 < len(global_tokens) else ""
            if _docker_global_context_value_is_sensitive(flag, value):
                return True
            index += 2
            continue
        if token in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS
        ):
            return True
        index += 1
    return False


def _docker_attached_short_context_option(token: str) -> tuple[str, str] | None:
    for flag in ("-c", "-H"):
        if token.startswith(flag) and token not in {flag, f"{flag}="}:
            value = token[len(flag) :]
            if value.startswith("="):
                value = value[1:]
            return flag, value
    return None


def _docker_global_context_value_is_sensitive(flag: str, value: str) -> bool:
    if flag not in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS:
        return False
    normalized_value = value.strip().strip("\"'")
    if flag in {"--context", "-c"}:
        # ``default`` (and an empty value) still targets the local engine.
        return normalized_value.lower() not in {"", "default"}
    # ``--host``/``-H``, ``--config``, and TLS cert/key flags always point at a
    # non-default/remotable control plane or credential material.
    return True


def _docker_env_context_is_sensitive(prefix_tokens: list[str]) -> bool:
    env_index = next(
        (index for index, token in enumerate(prefix_tokens) if _normalized_shell_command_name(token) == "env"),
        None,
    )
    if env_index is not None:
        parsed = parse_env_wrapper(prefix_tokens[env_index + 1 :])
        if not parsed.complete:
            return True
        return _docker_env_assignments_are_sensitive(parsed.environment_delta.assignments)
    return any(
        assignment is not None and _docker_env_context_value_is_sensitive(*assignment)
        for assignment in (_docker_env_assignment(token) for token in prefix_tokens)
    )


def _docker_env_assignments_are_sensitive(assignments: tuple[tuple[str, str], ...]) -> bool:
    return any(
        name.upper() in _DOCKER_SENSITIVE_CONTEXT_ENV_KEYS
        and _docker_env_context_value_is_sensitive(name.upper(), value)
        for name, value in assignments
    )


def _docker_exported_env_context_sensitivity(args: list[str]) -> dict[str, bool]:
    exported: dict[str, bool] = {}
    for token in args:
        if token.startswith("-"):
            continue
        assignment = _docker_env_assignment(token)
        if assignment is None:
            continue
        key, value = assignment
        exported[key] = _docker_env_context_value_is_sensitive(key, value)
    return exported


def _docker_env_assignment(token: str) -> tuple[str, str] | None:
    normalized = _shell_command_token_without_attached_redirection(token).strip()
    if not _SHELL_ASSIGNMENT_PATTERN.match(normalized):
        return None
    key, _, value = normalized.partition("=")
    key = key.rstrip("+").upper()
    if key not in _DOCKER_SENSITIVE_CONTEXT_ENV_KEYS:
        return None
    return key, value.strip().strip("\"'")


def _docker_env_context_value_is_sensitive(key: str, value: str) -> bool:
    normalized_value = value.strip().strip("\"'")
    if key == "DOCKER_CONTEXT":
        return normalized_value.lower() not in {"", "default"}
    if key == "DOCKER_HOST":
        lowered = normalized_value.lower()
        return bool(normalized_value) and not lowered.startswith(("unix://", "npipe://"))
    if key == "DOCKER_TLS_VERIFY":
        return normalized_value.lower() not in {"", "0", "false", "no"}
    return bool(normalized_value)


def _docker_compose_sensitive_reason(args: list[str], *, sensitive_context: bool) -> str | None:
    if sensitive_context:
        return "compose-sensitive-context"
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            remaining = args[index + 1 :]
            if remaining:
                compose_subcommand = remaining[0].lower()
                return _docker_compose_subcommand_reason(compose_subcommand, remaining[1:])
            return None
        if _docker_compose_option_has_value(token):
            if _docker_compose_option_is_secret_bearing(token):
                return "compose-env-file"
            index += 1 if "=" in token else 2
            continue
        if _docker_compose_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return _docker_compose_subcommand_reason(token.lower(), args[index + 1 :])
    return None


def _docker_compose_subcommand_reason(compose_subcommand: str, subcommand_args: list[str]) -> str | None:
    if compose_subcommand in _DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS:
        return f"compose-{compose_subcommand}"
    if _docker_compose_args_include_secret_bearing_option(subcommand_args):
        return "compose-env-file"
    if compose_subcommand in _DOCKER_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(subcommand_args):
        return "compose-build-sensitive-flags"
    if compose_subcommand in _DOCKER_COMPOSE_SAFE_SUBCOMMANDS:
        return None
    # Unknown Compose subcommands stay sensitive by default.
    return "compose-unknown-subcommand"


def _docker_compose_option_has_value(token: str) -> bool:
    return token in _DOCKER_COMPOSE_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_COMPOSE_OPTIONS_WITH_VALUES
    )


def _docker_compose_option_is_secret_bearing(token: str) -> bool:
    return token == "--env-file" or token.startswith("--env-file=")


def _docker_compose_args_include_secret_bearing_option(args: list[str]) -> bool:
    return any(_docker_compose_option_is_secret_bearing(token) for token in args)


def _docker_compose_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_COMPOSE_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_COMPOSE_FLAG_OPTIONS
    )


def _docker_buildx_subcommand_index(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return index + 1 if index + 1 < len(args) else None
        if _docker_buildx_option_has_value(token):
            index += 1 if "=" in token else 2
            continue
        if _docker_buildx_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return index
    return None


def _docker_buildx_option_has_value(token: str) -> bool:
    return token in _DOCKER_BUILDX_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_BUILDX_OPTIONS_WITH_VALUES
    )


def _docker_buildx_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_BUILDX_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_BUILDX_FLAG_OPTIONS
    )


def _docker_build_args_are_sensitive(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return False
        if token in _DOCKER_BUILD_SECRET_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _DOCKER_BUILD_SECRET_FLAGS
        ):
            return True
        if _docker_build_output_flag_matches(token):
            return True
        if token == "--build-arg":
            value = args[index + 1] if index + 1 < len(args) else ""
            if _docker_build_arg_is_sensitive(value):
                return True
            index += 2
            continue
        if token.startswith("--build-arg=") and _docker_build_arg_is_sensitive(token.split("=", 1)[1]):
            return True
        if token in _DOCKER_BUILD_METADATA_FLAGS:
            value = args[index + 1] if index + 1 < len(args) else ""
            if _docker_build_metadata_value_is_sensitive(value):
                return True
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            flag, value = token.split("=", 1)
            if flag in _DOCKER_BUILD_METADATA_FLAGS and _docker_build_metadata_value_is_sensitive(value):
                return True
        index += 1
    return False


def _docker_build_output_flag_matches(token: str) -> bool:
    if token in _DOCKER_BUILD_OUTPUT_FLAGS or any(token.startswith(f"{flag}=") for flag in _DOCKER_BUILD_OUTPUT_FLAGS):
        return True
    return token.startswith("-o") and len(token) > 2


def _docker_build_arg_is_sensitive(value: str) -> bool:
    key, separator, assigned_value = value.partition("=")
    # Normalize after splitting to tolerate unusual shell tokenization.
    normalized_key = key.strip()
    return bool(
        normalized_key
        and (
            # Bare build args pass through the caller's environment, so block
            # them even when the variable name does not look secret-like.
            not separator
            or _docker_build_arg_name_is_sensitive(normalized_key)
            or _docker_build_arg_value_is_sensitive(assigned_value.strip())
        )
    )


def _docker_build_metadata_value_is_sensitive(value: str) -> bool:
    key, separator, assigned_value = value.partition("=")
    if not separator:
        return _docker_build_arg_value_is_sensitive(value.strip())
    return _docker_build_arg_value_is_sensitive(key.strip()) or _docker_build_arg_value_is_sensitive(
        assigned_value.strip()
    )


def _docker_build_arg_name_is_sensitive(value: str) -> bool:
    normalized = value.upper().replace("-", "_")
    parts = normalized.split("_")
    if any(part in _DOCKER_BUILD_ARG_SECRET_MARKERS for part in parts):
        return True
    substring_markers = _DOCKER_BUILD_ARG_SECRET_MARKERS - {"KEY"}
    return any(marker in normalized for marker in substring_markers)


def _docker_build_arg_value_is_sensitive(value: str) -> bool:
    lowered = value.lower().strip("\"'")
    if any(lowered.startswith(prefix) for prefix in _DOCKER_BUILD_ARG_TOKEN_PREFIXES):
        return True
    if "$(" in value or "`" in value:
        return True
    return any(_docker_build_arg_name_is_sensitive(variable_name) for variable_name in _shell_variable_names(value))


def _shell_variable_names(value: str) -> tuple[str, ...]:
    names: list[str] = []
    index = 0
    while index < len(value):
        dollar_index = value.find("$", index)
        if dollar_index == -1 or dollar_index + 1 >= len(value):
            break
        if value[dollar_index + 1] == "{":
            closing_index = value.find("}", dollar_index + 2)
            if closing_index == -1:
                index = dollar_index + 2
                continue
            variable_name = _shell_braced_variable_name(value[dollar_index + 2 : closing_index])
            if variable_name:
                names.append(variable_name)
            index = closing_index + 1
            continue
        variable_name, next_index = _shell_unbraced_variable_name(value, dollar_index + 1)
        if variable_name:
            names.append(variable_name)
        index = next_index
    return tuple(names)


def _shell_braced_variable_name(value: str) -> str:
    start = 1 if value.startswith("!") else 0
    variable_name, _ = _shell_unbraced_variable_name(value, start)
    return variable_name


def _shell_unbraced_variable_name(value: str, start: int) -> tuple[str, int]:
    if start >= len(value) or not (value[start].isalpha() or value[start] == "_"):
        return "", start + 1
    index = start + 1
    while index < len(value) and (value[index].isalnum() or value[index] == "_"):
        index += 1
    return value[start:index], index


def _docker_config_path_from_command(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    normalized_command = command_text.replace("\\", "/")
    if ".docker/config.json" not in normalized_command:
        return None
    match = classify_sensitive_path(".docker/config.json", cwd=cwd, home_dir=home_dir)
    if match is None:
        return None
    return match.normalized_path


def _looks_destructive_shell_command(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    execution_context: ShellExecutionContext | None = None,
    _execution_context_applied: bool = False,
) -> bool:
    normalized = command_text.strip()
    if not normalized:
        return False
    if not _execution_context_applied:
        execution_context = execution_context or model_shell_execution_context(
            normalized,
            cwd=cwd,
            workspace_root=cwd,
        )
        if execution_context.directory_change_present:
            if not execution_context.complete:
                return True
            has_heredoc = bool(extract_heredocs(normalized))
            heredoc_segment_cwds: list[Path] = []
            for context_segment in execution_context.segments:
                if context_segment.directory_operation is not None:
                    continue
                segment_cwd, validation_reason = validate_shell_execution_segment(
                    execution_context,
                    context_segment,
                )
                if segment_cwd is None or validation_reason is not None:
                    return True
                command_name, command_index = _shell_segment_primary_command(list(context_segment.tokens))
                if (
                    command_name in _SAFE_STATIC_SHELL_COMMANDS
                    and command_index is not None
                    and not _static_shell_segment_is_safe(list(context_segment.tokens[command_index + 1 :]))
                ):
                    return True
                segment_has_heredoc = any(token.startswith("<<") for token in context_segment.tokens)
                if segment_has_heredoc:
                    heredoc_segment_cwds.append(segment_cwd)
                elif _looks_destructive_shell_command(
                    context_segment.command_text,
                    cwd=segment_cwd,
                    home_dir=home_dir,
                    _execution_context_applied=True,
                ):
                    return True
            if has_heredoc:
                if len(heredoc_segment_cwds) != 1:
                    return True
                return _looks_destructive_shell_command(
                    normalized,
                    cwd=heredoc_segment_cwds[0],
                    home_dir=home_dir,
                    _execution_context_applied=True,
                )
            contextual_parts = _split_shell_parts(normalized)
            return _contains_prior_pytest_state_mutation(contextual_parts) or _contains_pytest_env_shell_script_wrapper(
                contextual_parts
            )
    if _is_literal_cat_heredoc_to_stdout(normalized):
        return False
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _looks_destructive_shell_command(substitution_payload, cwd=cwd, home_dir=home_dir):
            return True
    node_heredoc_script = _single_node_heredoc_script(normalized)
    if node_heredoc_script is not None:
        if _looks_like_safe_node_read_only_http_heredoc(normalized, node_heredoc_script):
            return False
        if _looks_like_safe_node_generated_file_heredoc(normalized, node_heredoc_script):
            return False
        return _node_script_contains_sensitive_runtime_behavior(node_heredoc_script)
    if _looks_like_safe_graphql_query_file_workflow(normalized):
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    lowered = normalized.lower()
    redacted_command_text = _redacted_shell_text_for_command_names(lowered)
    if _contains_mutating_shell_redirection(parts):
        return True
    if _contains_prior_pytest_state_mutation(parts):
        return True
    if _contains_pytest_env_shell_script_wrapper(parts):
        return True
    if _contains_pytest_process_substitution(normalized, parts):
        return True
    if _contains_unsafe_pytest_environment_wrapper(parts, cwd=cwd):
        return True
    if _looks_like_safe_read_only_lookup_command(normalized, parts, home_dir=home_dir):
        return False
    if _looks_like_read_only_shell_pipeline(normalized, parts, cwd=cwd, home_dir=home_dir):
        return False
    raw_command_names = list(_shell_command_names(redacted_command_text))
    parsed_command_names = list(_shell_command_names_from_parts(parts))
    if _looks_like_benign_interpreter_wait(normalized, parts, parsed_command_names):
        return False
    if _looks_like_read_only_interpreter_command(normalized, parts, parsed_command_names):
        return False
    if _looks_like_safe_pytest_binary_invocation(parts, cwd=cwd):
        return False
    if _contains_unsafe_pytest_binary_invocation(parts, cwd=cwd):
        return True
    if _single_interpreter_heredoc_script(normalized) is not None or any(
        _is_python_interpreter_command(command_name) for command_name in parsed_command_names
    ):
        return not _looks_like_safe_python_module_invocation(parts, cwd=cwd)
    if _contains_unmodeled_inline_interpreter_eval(normalized, parts, parsed_command_names):
        return True
    if _contains_destructive_node_inline_eval(parts):
        return True
    if _contains_destructive_git_command(parts):
        return True
    if _find_or_fd_uses_write_or_exec_action(parts, home_dir=home_dir):
        return True
    command_names = list(raw_command_names)
    command_names.extend(_shell_command_names_from_parts(parts))
    if any(command_name in _DESTRUCTIVE_SHELL_COMMANDS for command_name in command_names):
        return True
    if _find_command_uses_delete(parts):
        return True
    for env_split_string in _env_split_string_payloads(parts):
        if _looks_destructive_shell_command(env_split_string, cwd=cwd, home_dir=home_dir):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _looks_destructive_shell_command(shell_script, cwd=cwd, home_dir=home_dir):
            return True
    return any(
        command_name == "sed" and any(part == "-i" or part.startswith("-i") for part in parts[1:])
        for command_name in command_names
    )


def _is_literal_cat_heredoc_to_stdout(command_text: str) -> bool:
    heredocs = extract_heredocs(command_text)
    if len(heredocs) != 1:
        return False
    heredoc = heredocs[0]
    if command_text[heredoc.end :].strip():
        return False
    line_start = command_text.rfind("\n", 0, heredoc.operator_start) + 1
    header = (
        command_text[line_start : heredoc.operator_start] + command_text[heredoc.declaration_end : heredoc.body_start]
    )
    try:
        tokens = shlex.split(header, posix=True, comments=False)
    except ValueError:
        return False
    return tokens in (["cat"], ["cat", "-"])


def _looks_like_safe_read_only_lookup_command(
    command_text: str,
    parts: list[str],
    *,
    home_dir: Path | None,
) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if any(token in parts for token in {";", "&", "||", "|&"}):
        return False
    segments = _read_only_lookup_segments(parts)
    if not segments:
        return False
    for index, segment in enumerate(segments):
        if not segment:
            return False
        command = Path(segment[0]).name.lower()
        if "/" in segment[0] or "\\" in segment[0]:
            return False
        if index > 0 and command not in _READ_ONLY_LOOKUP_FILTERS:
            return False
        if index == 0:
            if command not in _READ_ONLY_LOOKUP_COMMANDS:
                return False
            if not _read_only_lookup_primary_segment_is_safe(command, segment[1:], home_dir=home_dir):
                return False
        elif not _read_only_lookup_filter_segment_is_safe(command, segment[1:], home_dir=home_dir):
            return False
    return True


def _read_only_lookup_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for token in parts:
        if token in {"|", "&&"}:
            if not segments[-1]:
                return []
            segments.append([])
            continue
        normalized_token = token.strip()
        if not normalized_token:
            continue
        if _read_only_lookup_token_is_safe_stderr_discard(normalized_token):
            continue
        segments[-1].append(normalized_token)
    return [segment for segment in segments if segment]


def _read_only_lookup_token_is_safe_stderr_discard(token: str) -> bool:
    redirection = _split_attached_redirection_token(token)
    if redirection is None:
        return False
    prefix, fd, _op, target = redirection
    return not prefix and fd == "2" and _normalized_redirect_target(target).lower() in _SAFE_SHELL_REDIRECT_TARGETS


def _read_only_lookup_primary_segment_is_safe(command: str, args: list[str], *, home_dir: Path | None) -> bool:
    if command == "sed":
        return _read_only_lookup_sed_args_are_safe(args, require_target=True, home_dir=home_dir)
    if command in {"head", "tail"}:
        return _read_only_lookup_head_tail_args_are_safe(args, require_target=True, home_dir=home_dir)
    if command == "cat":
        return _read_only_lookup_plain_targets_are_safe(args, allow_dirs=False, home_dir=home_dir)
    if command == "ls":
        return _read_only_lookup_ls_args_are_safe(args, home_dir=home_dir)
    if command in {"grep", "egrep", "fgrep", "rg"}:
        return _read_only_lookup_search_args_are_safe(command, args, home_dir=home_dir)
    if command == "fd":
        return _read_only_lookup_fd_args_are_safe(args, home_dir=home_dir)
    if command == "find":
        return _read_only_lookup_find_args_are_safe(args, home_dir=home_dir)
    return False


def _read_only_lookup_filter_segment_is_safe(
    command: str,
    args: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    if command == "sed":
        return _read_only_lookup_sed_args_are_safe(args, require_target=False)
    if command in {"head", "tail"}:
        return _read_only_lookup_head_tail_args_are_safe(args, require_target=False)
    if command in {"grep", "egrep", "fgrep"}:
        return _read_only_lookup_filter_grep_args_are_safe(args, home_dir=home_dir)
    return False


def _read_only_lookup_sed_args_are_safe(
    args: list[str],
    *,
    require_target: bool,
    home_dir: Path | None = None,
) -> bool:
    scripts: list[str] = []
    targets: list[str] = []
    saw_print_suppression = False
    skip_script = False
    after_options = False
    for arg in args:
        if skip_script:
            skip_script = False
            scripts.append(arg)
            continue
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-i", "--in-place"} or arg.startswith(("-i", "--in-place=")):
            return False
        if arg in {"-n", "--quiet", "--silent"}:
            saw_print_suppression = True
            continue
        if arg in {"-e", "--expression"}:
            skip_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts.append(arg[2:])
            continue
        if arg.startswith("--expression="):
            scripts.append(arg.split("=", 1)[1])
            continue
        if arg.startswith("-"):
            return False
        if not scripts:
            scripts.append(arg)
        else:
            targets.append(arg)
    if skip_script or not scripts or not saw_print_suppression:
        return False
    if not all(_read_only_lookup_sed_script_is_print_only(script) for script in scripts):
        return False
    if require_target:
        return bool(targets) and all(
            _read_only_lookup_target_is_safe(target, allow_dirs=False, home_dir=home_dir) for target in targets
        )
    return not targets


def _read_only_lookup_sed_script_is_print_only(script: str) -> bool:
    return sed_script_is_bounded_print(script)


def _read_only_lookup_head_tail_args_are_safe(
    args: list[str],
    *,
    require_target: bool,
    home_dir: Path | None = None,
) -> bool:
    targets: list[str] = []
    skip_count = False
    after_options = False
    for arg in args:
        if skip_count:
            skip_count = False
            if not re.fullmatch(r"\d{1,6}", arg.strip()):
                return False
            continue
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_count = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes="):
            if not re.fullmatch(r"\d{1,6}", arg.split("=", 1)[1].strip()):
                return False
            continue
        if re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg.startswith("-"):
            return False
        targets.append(arg)
    if skip_count:
        return False
    if require_target:
        return bool(targets) and all(
            _read_only_lookup_target_is_safe(target, allow_dirs=False, home_dir=home_dir) for target in targets
        )
    return not targets


def _read_only_lookup_plain_targets_are_safe(
    args: list[str],
    *,
    allow_dirs: bool,
    home_dir: Path | None = None,
) -> bool:
    targets: list[str] = []
    after_options = False
    for arg in args:
        if after_options:
            targets.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "-":
            return False
        if arg.startswith("-"):
            continue
        targets.append(arg)
    return all(_read_only_lookup_target_is_safe(target, allow_dirs=allow_dirs, home_dir=home_dir) for target in targets)


def _read_only_lookup_ls_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    return _read_only_lookup_plain_targets_are_safe(args, allow_dirs=True, home_dir=home_dir)


def _read_only_lookup_search_args_are_safe(
    command: str,
    args: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    execution_flags = _READ_ONLY_SEARCH_EXECUTION_FLAGS.get(command, frozenset())
    if any(arg in execution_flags or any(arg.startswith(f"{flag}=") for flag in execution_flags) for arg in args):
        return False
    targets = [arg for arg in args if arg and not arg.startswith("-")]
    return len(targets) < 2 or all(
        _read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in targets[1:]
    )


def _read_only_lookup_fd_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    if any(fd_arg_requests_exec(arg) for arg in args):
        return _fd_exec_sed_read_only_args_are_safe(args, home_dir=home_dir)
    targets = fd_search_targets(args)
    if targets is None:
        return False
    if not targets:
        return True
    return all(_read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in targets)


def _fd_exec_sed_read_only_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    parsed = split_fd_args_and_exec(args)
    if parsed is None:
        return False
    fd_args, exec_parts = parsed
    if not exec_parts or not fd_exec_token_is_plain_sed(exec_parts[0]):
        return False
    if exec_parts.count("{}") != 1:
        return False
    sed_args = [arg for arg in exec_parts[1:] if arg != "{}"]
    fd_targets = fd_search_targets(fd_args)
    if fd_targets is None or not fd_targets:
        return False
    return all(
        _read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir) for target in fd_targets
    ) and _read_only_lookup_sed_args_are_safe(
        sed_args,
        require_target=False,
        home_dir=home_dir,
    )


def _read_only_lookup_find_args_are_safe(args: list[str], *, home_dir: Path | None = None) -> bool:
    if any(_read_only_lookup_arg_is_redirection(arg) for arg in args):
        return False
    if _find_args_use_write_or_unsafe_exec_action(args):
        return False
    targets = [arg for arg in args if arg and not arg.startswith("-")]
    if not targets:
        return False
    return _read_only_lookup_target_is_safe(targets[0], allow_dirs=True, home_dir=home_dir)


_GREP_PATTERN_OPTIONS = frozenset({"-e", "--regexp"})
_GREP_PATTERN_FILE_OPTIONS = frozenset({"-f", "--file"})
_GREP_FILTER_FILE_OPTIONS = frozenset({"--exclude-from"})
_GREP_SKIP_NEXT_OPTIONS = frozenset(
    {
        "-A",
        "-B",
        "-C",
        "-m",
        "--after-context",
        "--before-context",
        "--context",
        "--max-count",
    }
)


def _read_only_lookup_filter_grep_args_are_safe(
    args: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    """Validate grep arguments in a filter (pipe) segment.

    In a filter segment grep reads stdin and writes matching lines to stdout.
    The first positional argument is the pattern (any string, including URIs).
    Subsequent positional arguments are file operands that grep opens as files.
    ``-f FILE`` reads patterns from a file, so it must also be validated.
    ``-e PATTERN`` provides a pattern and is safe to skip.
    """
    if not args:
        return False
    saw_pattern = False
    after_options = False
    skip_next_is_pattern = False
    skip_next_is_file = False
    skip_next_file_sets_pattern = False
    skip_next_is_value = False
    for arg in args:
        if skip_next_is_pattern:
            skip_next_is_pattern = False
            saw_pattern = True
            continue
        if skip_next_is_file:
            skip_next_is_file = False
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
            if skip_next_file_sets_pattern:
                saw_pattern = True
            continue
        if skip_next_is_value:
            skip_next_is_value = False
            continue
        if _read_only_lookup_arg_is_redirection(arg):
            return False
        if after_options:
            if not saw_pattern:
                saw_pattern = True
                continue
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in _GREP_PATTERN_OPTIONS:
            skip_next_is_pattern = True
            saw_pattern = True
            continue
        if arg in _GREP_PATTERN_FILE_OPTIONS:
            skip_next_is_file = True
            skip_next_file_sets_pattern = True
            continue
        if arg in _GREP_FILTER_FILE_OPTIONS:
            skip_next_is_file = True
            skip_next_file_sets_pattern = False
            continue
        if arg in _GREP_SKIP_NEXT_OPTIONS:
            skip_next_is_value = True
            continue
        if arg.startswith("--"):
            # Long options: --file=VALUE, --regexp=VALUE, --fixed-strings, etc.
            if "=" in arg:
                key, _, value = arg.partition("=")
                if key in _GREP_PATTERN_FILE_OPTIONS:
                    if not _read_only_lookup_target_is_safe(value, allow_dirs=False, home_dir=home_dir):
                        return False
                    saw_pattern = True
                elif key in _GREP_FILTER_FILE_OPTIONS:
                    if not _read_only_lookup_target_is_safe(value, allow_dirs=False, home_dir=home_dir):
                        return False
                elif key in _GREP_PATTERN_OPTIONS:
                    saw_pattern = True
            # Long options without = are already handled above by exact match.
            continue
        if arg.startswith("-") and arg != "-":
            # Combined short options: check for -f or -e in the cluster.
            body = arg[1:]
            # Handle -fFILE (file operand attached) and -ePATTERN (pattern attached).
            for i, ch in enumerate(body):
                if ch == "f":
                    file_arg = body[i + 1 :]
                    if file_arg:
                        if not _read_only_lookup_target_is_safe(file_arg, allow_dirs=False, home_dir=home_dir):
                            return False
                        saw_pattern = True
                    else:
                        skip_next_is_file = True
                        skip_next_file_sets_pattern = True
                    break
                elif ch == "e":
                    saw_pattern = True
                    break
            continue
        # Positional argument: first one is the pattern, rest are file operands.
        if not saw_pattern:
            saw_pattern = True
        else:
            if not _read_only_lookup_target_is_safe(arg, allow_dirs=False, home_dir=home_dir):
                return False
    return True


def _read_only_lookup_arg_is_redirection(arg: str) -> bool:
    if arg in {">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|", "<", "0<"}:
        return True
    return _split_attached_redirection_token(arg) is not None


def _read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None = None) -> bool:
    stripped = target.strip().strip("'\"")
    if stripped in {"", "."}:
        return allow_dirs
    if stripped == "-":
        return False
    if any(marker in stripped for marker in ("$", "`", "<", ">", "|", ";", "&")):
        return False
    normalized = stripped.replace("\\", "/")
    parts = [part for part in Path(normalized).parts if part not in {"", "/", "."}]
    lowered_parts = [part.lower() for part in parts]
    if not parts:
        return allow_dirs
    if target_is_known_skill_doc_path(stripped, home_dir=home_dir):
        return True
    if any(part in SOURCE_INSPECTION_SENSITIVE_PARTS for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in SOURCE_INSPECTION_BENIGN_DOTFILES for part in hidden_parts):
        return False
    if any(part in SOURCE_INSPECTION_PARTS for part in lowered_parts):
        return True
    if Path(normalized).suffix.lower() in SOURCE_INSPECTION_EXTENSIONS:
        return True
    return allow_dirs


_SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN = re.compile(
    r"\A\s*cat\s*>\s*(?P<path>'[^']+'|\"[^\"]+\"|[^\s]+)\s*<<(?P<quote>['\"])(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
    r"\s*\n(?P<body>.*?)\n(?P=label)\s*(?:\n|&&|;)\s*(?P<rest>.+)\Z",
    re.DOTALL,
)


def _looks_like_safe_graphql_query_file_workflow(command_text: str) -> bool:
    match = _SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN.match(command_text)
    if match is None:
        return False
    target_path = _strip_shell_quotes(match.group("path").strip())
    if (
        not target_path.endswith(".graphql")
        or _path_text_looks_sensitive(target_path)
        or _contains_shell_expansion(target_path)
        or not _looks_like_temporary_pr_threads_query_path(target_path)
    ):
        return False
    body = match.group("body").strip()
    if not re.search(r"\bquery\b", body) or re.search(r"\bmutation\b|\bsubscription\b", body):
        return False
    rest = match.group("rest").strip()
    if not rest.startswith("gh api graphql "):
        return False
    if re.search(r"(?:;|&|\|\||\||>|<|\n)", rest):
        return False
    rest_without_allowed_query_refs = rest
    for ref in _graphql_query_file_substitution_refs(target_path):
        rest_without_allowed_query_refs = rest_without_allowed_query_refs.replace(ref, "")
    if "$(" in rest_without_allowed_query_refs or "`" in rest_without_allowed_query_refs:
        return False
    return _graphql_workflow_rest_args_are_safe(rest, target_path)


def _strip_shell_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _contains_shell_expansion(value: str) -> bool:
    return (
        "$(" in value
        or "`" in value
        or "${" in value
        or "$'" in value
        or '$"' in value
        or re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", value) is not None
        or re.search(r"[*?\[\]{}]", value) is not None
    )


def _graphql_query_file_substitution_refs(target_path: str) -> set[str]:
    return {
        f"$(cat {target_path})",
        f'$(cat "{target_path}")',
        f"$(cat '{target_path}')",
    }


def _graphql_workflow_rest_args_are_safe(rest: str, target_path: str) -> bool:
    parts = _split_shell_parts(rest)
    if parts[:3] != ["gh", "api", "graphql"]:
        return False
    saw_query_arg = False
    index = 3
    while index < len(parts):
        token = parts[index]
        if token == "--":
            return False
        if token in {"-F", "--field", "-f", "--raw-field"}:
            if index + 1 >= len(parts):
                return False
            if not _graphql_workflow_field_arg_is_safe(parts[index + 1], target_path):
                return False
            if parts[index + 1].startswith("query="):
                saw_query_arg = True
            index += 2
            continue
        if token.startswith("--field=") or token.startswith("--raw-field="):
            value = token.split("=", 1)[1]
        elif (token.startswith("-F") and len(token) > 2) or (token.startswith("-f") and len(token) > 2):
            value = token[2:]
        else:
            return False
        if not _graphql_workflow_field_arg_is_safe(value, target_path):
            return False
        if value.startswith("query="):
            saw_query_arg = True
        index += 1
    return saw_query_arg


def _graphql_workflow_field_arg_is_safe(argument: str, target_path: str) -> bool:
    if "=" not in argument:
        return False
    name, value = argument.split("=", 1)
    if not name:
        return False
    if name == "query":
        return value in _graphql_query_file_argument_values(target_path)
    if not value or value.startswith("@"):
        return False
    return not (_contains_shell_expansion(value) or "/" in value or "\\" in value)


def _graphql_query_file_argument_values(target_path: str) -> set[str]:
    return _graphql_query_file_substitution_refs(target_path) | {f"@{target_path}"}


def _looks_like_temporary_pr_threads_query_path(path_text: str) -> bool:
    normalized = os.path.normpath(path_text.replace("\\", "/")).replace("\\", "/")
    basename = os.path.basename(normalized)
    if basename != "pr-threads-query.graphql":
        return False
    if not normalized.startswith("/"):
        return False
    if os.path.exists(normalized):
        return False
    _temp_groups: tuple[frozenset[str], ...] = (
        frozenset({"/tmp/", "/private/tmp/"}),
        frozenset({"/var/tmp/", "/private/var/tmp/"}),
        frozenset({"/var/folders/", "/private/var/folders/"}),
    )

    def _temp_group_index(lowered: str) -> int:
        for idx, group in enumerate(_temp_groups):
            if any(lowered.startswith(prefix) for prefix in group):
                return idx
        return -1

    literal_group = _temp_group_index(normalized.lower())
    if literal_group == -1:
        return False
    resolved_lowered = os.path.realpath(normalized).replace("\\", "/").lower()
    return _temp_group_index(resolved_lowered) == literal_group


def _path_text_looks_sensitive(path_text: str) -> bool:
    lowered = path_text.lower()
    return any(
        marker in lowered
        for marker in (
            ".aws/",
            ".docker/",
            ".kube/",
            ".ssh/",
            ".env",
            ".git-credentials",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "id_rsa",
        )
    )


def _contains_destructive_node_inline_eval(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "node" or command_index is None:
            continue
        if _segment_contains_destructive_node_inline_eval(segment[command_index + 1 :]):
            return True
    return False


def _find_or_fd_uses_write_or_exec_action(parts: list[str], *, home_dir: Path | None = None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if (
            command_name == "find"
            and command_index is not None
            and _find_args_use_write_or_unsafe_exec_action(segment[command_index + 1 :])
        ):
            return True
        if (
            command_name == "fd"
            and command_index is not None
            and any(fd_arg_requests_exec(arg) for arg in segment[command_index + 1 :])
            and not _fd_exec_sed_read_only_args_are_safe(segment[command_index + 1 :], home_dir=home_dir)
        ):
            return True
    return False


def _find_args_use_write_or_unsafe_exec_action(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in _FIND_PATH_VALUE_PREDICATES and index + 1 < len(args):
            index += 2
            continue
        if arg in {"-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}:
            return True
        if arg in _FIND_EXEC_ACTION_FLAGS:
            if index + 1 >= len(args):
                return True
            command_name = Path(args[index + 1]).name.lower()
            exec_args: list[str] = []
            exec_index = index + 2
            while exec_index < len(args) and args[exec_index] not in _FIND_EXEC_TERMINATOR_TOKENS:
                exec_args.append(args[exec_index])
                exec_index += 1
            is_safe_builtin = command_name in {"echo", "printf", "true", "false", "test", "["}
            is_read_only_sed = command_name == "sed" and _find_exec_sed_args_are_read_only(exec_args)
            if not is_safe_builtin and not is_read_only_sed:
                return True
            index = exec_index + 1 if exec_index < len(args) else exec_index
            continue
        index += 1
    return False


def _find_exec_sed_args_are_read_only(args: list[str]) -> bool:
    normalized_args = [_FIND_EXEC_PLACEHOLDER_TARGET if arg == "{}" else arg for arg in args]
    return _read_only_lookup_sed_args_are_safe(normalized_args, require_target=True)


def _contains_destructive_node_inline_script(script: str) -> bool:
    redacted_script = _redacted_node_inline_string_literals(script)
    member_scan_script = _redacted_node_inline_string_literals(script, preserve_bracket_member_strings=True)
    for call_name in _DESTRUCTIVE_NODE_INLINE_CALLS:
        escaped_call_name = re.escape(call_name)
        if re.search(rf"(?<![A-Za-z0-9_$'\"]){escaped_call_name}\s*(?:\?\.\s*)?\(", redacted_script):
            return True
        for base_pattern in (
            rf"\.\s*{escaped_call_name}",
            rf"\[\s*['\"]{escaped_call_name}['\"]\s*\]",
        ):
            if re.search(rf"{base_pattern}\s*(?:\?\.\s*)?(?:\)\s*)?\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*call\s*\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*apply\s*\(", member_scan_script):
                return True
    return False


def _single_node_heredoc_script(command_text: str) -> str | None:
    match = _SINGLE_NODE_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    args = match.group("args").strip()
    if args not in {"", "-"}:
        return None
    script_text = match.group("body").strip()
    return script_text or None


def _single_node_heredoc_delimiter_is_quoted(command_text: str) -> bool:
    match = _SINGLE_NODE_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return False
    args = match.group("args").strip()
    if args not in {"", "-"}:
        return False
    return bool(match.group("quote"))


def _looks_like_safe_node_generated_file_heredoc(command_text: str, script_text: str) -> bool:
    if _single_node_heredoc_script(command_text) is None:
        return False
    if _node_script_contains_non_file_generation_risk(script_text):
        return False
    if _node_script_contains_disallowed_destructive_file_call(script_text):
        return False
    write_targets = _node_write_file_targets(script_text)
    if not write_targets:
        return False
    assignments = _node_string_assignments(script_text)
    return all(_node_write_target_is_safe_generated_file(target, assignments) for target in write_targets)


def _node_script_contains_sensitive_runtime_behavior(script_text: str) -> bool:
    return _contains_destructive_node_inline_script(script_text) or _node_script_contains_non_file_generation_risk(
        script_text
    )


def _looks_like_safe_node_read_only_http_heredoc(command_text: str, script_text: str) -> bool:
    if not _single_node_heredoc_delimiter_is_quoted(command_text):
        return False
    if _NODE_READ_ONLY_HTTP_PATTERN.search(script_text) is None:
        return False
    if _NODE_MUTATING_HTTP_PATTERN.search(script_text):
        return False
    if _NODE_LOCAL_FILE_ACCESS_PATTERN.search(script_text):
        return False
    if _NODE_SENSITIVE_RUNTIME_PATTERN.search(script_text):
        return False
    return not _node_script_contains_disallowed_destructive_file_call(script_text)


def _node_script_contains_non_file_generation_risk(script_text: str) -> bool:
    lowered = script_text.lower()
    if _path_text_looks_sensitive(script_text):
        return True
    return bool(
        re.search(r"\b(?:fetch|xmlhttprequest)\s*\(", lowered)
        or re.search(r"\b(?:http|https|net|tls|dgram)\s*\.", lowered)
        or re.search(r"\brequire\s*\(\s*['\"](?:child_process|http|https|net|tls|dgram)['\"]\s*\)", lowered)
        or re.search(r"\b(?:exec|execfile|execfilesync|execsync|spawn|spawnsync|fork)\s*\(", lowered)
        or re.search(r"\b(?:eval|function)\s*\(", lowered)
    )


def _node_script_contains_disallowed_destructive_file_call(script_text: str) -> bool:
    allowed_write_calls = {"writeFile", "writeFileSync"}
    redacted_script = _redacted_node_inline_string_literals(script_text)
    member_scan_script = _redacted_node_inline_string_literals(script_text, preserve_bracket_member_strings=True)
    for call_name in _DESTRUCTIVE_NODE_INLINE_CALLS - allowed_write_calls:
        escaped_call_name = re.escape(call_name)
        if re.search(rf"(?<![A-Za-z0-9_$'\"]){escaped_call_name}\s*(?:\?\.\s*)?\(", redacted_script):
            return True
        for base_pattern in (
            rf"\.\s*{escaped_call_name}",
            rf"\[\s*['\"]{escaped_call_name}['\"]\s*\]",
        ):
            if re.search(rf"{base_pattern}\s*(?:\?\.\s*)?(?:\)\s*)?\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*call\s*\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*apply\s*\(", member_scan_script):
                return True
    return False


def _node_write_file_targets(script_text: str) -> tuple[str, ...]:
    targets: list[str] = []
    for match in re.finditer(r"(?:^|[^A-Za-z0-9_$])(?:fs\s*\.\s*)?writeFile(?:Sync)?\s*\(", script_text):
        target = _first_js_call_argument(script_text, match.end())
        if target is not None:
            targets.append(target)
    return tuple(targets)


def _first_js_call_argument(script_text: str, index: int) -> str | None:
    argument_start = index
    depth = 0
    quote: str | None = None
    escape_next = False
    while index < len(script_text):
        character = script_text[index]
        if escape_next:
            escape_next = False
            index += 1
            continue
        if character == "\\":
            escape_next = True
            index += 1
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if depth == 0:
                return script_text[argument_start:index].strip() or None
            depth -= 1
            index += 1
            continue
        if character == "," and depth == 0:
            return script_text[argument_start:index].strip() or None
        index += 1
    return None


def _node_string_assignments(script_text: str) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for _ in range(3):
        changed = False
        for line in script_text.splitlines():
            assignment = _node_string_assignment_from_line(line)
            if assignment is None:
                continue
            name, raw_value = assignment
            expanded_value = _node_expand_template_value(raw_value, assignments)
            if assignments.get(name) != expanded_value:
                assignments[name] = expanded_value
                changed = True
        if not changed:
            break
    return assignments


def _node_string_assignment_from_line(line: str) -> tuple[str, str] | None:
    stripped_line = line.strip().rstrip(";")
    for prefix in ("const ", "let ", "var "):
        if not stripped_line.startswith(prefix):
            continue
        rest = stripped_line[len(prefix) :].lstrip()
        name_end = 0
        while name_end < len(rest) and (rest[name_end].isalnum() or rest[name_end] in {"_", "$"}):
            name_end += 1
        if name_end == 0:
            return None
        name = rest[:name_end]
        remainder = rest[name_end:].lstrip()
        if not remainder.startswith("="):
            return None
        value = remainder[1:].lstrip()
        if not value:
            return None
        quote = value[0]
        if quote not in {"'", '"', "`"}:
            return None
        literal = _read_js_quoted_literal(value, quote)
        if literal is None:
            return None
        return name, literal
    return None


def _read_js_quoted_literal(value: str, quote: str) -> str | None:
    result: list[str] = []
    index = 1
    escape_next = False
    while index < len(value):
        character = value[index]
        if escape_next:
            result.append(character)
            escape_next = False
            index += 1
            continue
        if character == "\\":
            escape_next = True
            index += 1
            continue
        if character == quote:
            return "".join(result)
        result.append(character)
        index += 1
    return None


def _node_expand_template_value(value: str, assignments: dict[str, str]) -> str:
    expanded = value
    for name, assigned_value in assignments.items():
        expanded = expanded.replace("${" + name + "}", assigned_value)
    return expanded


def _node_write_target_is_safe_generated_file(target: str, assignments: dict[str, str]) -> bool:
    normalized = target.strip()
    if normalized in assignments:
        normalized = assignments[normalized]
    elif _js_string_literal_text(normalized) is not None:
        normalized = _js_string_literal_text(normalized) or ""
        normalized = _node_expand_template_value(normalized, assignments)
    else:
        return False
    if _node_generated_path_contains_shell_expansion(normalized) or _path_text_looks_sensitive(normalized):
        return False
    if "../" in normalized or normalized.startswith("../"):
        return False
    return _node_generated_path_has_safe_root(normalized) and _node_generated_path_has_safe_extension(normalized)


def _js_string_literal_text(value: str) -> str | None:
    if len(value) < 2 or value[0] != value[-1] or value[0] not in {"'", '"', "`"}:
        return None
    return value[1:-1]


def _node_generated_path_has_safe_root(path_text: str) -> bool:
    lowered = path_text.lower()
    return lowered.startswith(_SAFE_NODE_GENERATED_FILE_ROOTS)


def _node_generated_path_contains_shell_expansion(path_text: str) -> bool:
    if "$(" in path_text or "`" in path_text or "$'" in path_text or '$"' in path_text:
        return True
    if not _node_template_placeholders_are_safe_filename_fragments(path_text):
        return True
    redacted_path = _node_path_without_template_placeholders(path_text)
    if any(character in redacted_path for character in "*?[]"):
        return True
    index = 0
    while index < len(redacted_path):
        if redacted_path[index] == "$" and index + 1 < len(redacted_path):
            next_character = redacted_path[index + 1]
            if next_character.isalnum() or next_character == "_":
                return True
        index += 1
    return False


def _node_generated_path_has_safe_extension(path_text: str) -> bool:
    without_templates = _node_path_without_template_placeholders(path_text)
    extension = os.path.splitext(without_templates)[1].lower()
    return extension in _SAFE_NODE_GENERATED_FILE_EXTENSIONS


def _node_template_placeholders_are_safe_filename_fragments(path_text: str) -> bool:
    index = 0
    while index < len(path_text):
        start = path_text.find("${", index)
        if start == -1:
            return True
        end = path_text.find("}", start + 2)
        if end == -1:
            return False
        placeholder = path_text[start + 2 : end].strip()
        if not _node_template_placeholder_is_safe_filename_fragment(placeholder):
            return False
        index = end + 1
    return True


def _node_template_placeholder_is_safe_filename_fragment(placeholder: str) -> bool:
    if not placeholder.startswith("String(") or ".padStart(" not in placeholder:
        return False
    lowered = placeholder.lower()
    if any(token in lowered for token in ("process", "require", "env", "import", "fs", "path", "child")):
        return False
    numeric_prefix, _separator, padding_suffix = placeholder.partition(".padStart(")
    if any(character in numeric_prefix for character in ("'", '"', "\\", "`", "[", "]")):
        return False
    return not any(character in padding_suffix for character in ("/", "\\", "`", "[", "]"))


def _node_path_without_template_placeholders(path_text: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(path_text):
        start = path_text.find("${", index)
        if start == -1:
            result.append(path_text[index:])
            break
        result.append(path_text[index:start])
        end = path_text.find("}", start + 2)
        if end == -1:
            result.append(path_text[start:])
            break
        result.append("x")
        index = end + 1
    return "".join(result)


def _is_combined_node_inline_eval_flag(token: str) -> bool:
    return token in {"-pe", "-ep"}


def _find_command_uses_delete(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "find" or command_index is None:
            continue
        if _find_segment_uses_delete(segment[command_index + 1 :]):
            return True
    return False


def _iter_shell_command_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            continue
        current_segment.append(token)
    if current_segment:
        segments.append(current_segment)
    return segments


def _iter_shell_pipelines(parts: list[str]) -> list[list[list[str]]]:
    pipelines: list[list[list[str]]] = []
    current_pipeline: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in {"|", "|&"}:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            if current_pipeline:
                pipelines.append(current_pipeline)
                current_pipeline = []
            continue
        current_segment.append(token)
    if current_segment:
        current_pipeline.append(current_segment)
    if current_pipeline:
        pipelines.append(current_pipeline)
    return pipelines


def _shell_segment_primary_command(segment: list[str]) -> tuple[str | None, int | None]:
    index = 0
    while index < len(segment):
        redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(
            segment,
            index,
        )
        if redirect_tokens_consumed > 0:
            index += redirect_tokens_consumed
            continue
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            parsed = parse_env_wrapper(segment[index + 1 :])
            command_index = parsed.command_index
            if parsed.complete and command_index is None:
                return command_name, index
            if not parsed.complete or parsed.split_expansions or command_index is None:
                return None, None
            index += command_index + 1
            continue
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return command_name, index
    return None, None


def _leading_shell_redirection_tokens_consumed(segment: list[str], index: int) -> int:
    token = segment[index]
    redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
        token,
        next_token=segment[index + 1] if index + 1 < len(segment) else None,
    )
    if redirect_target is not None:
        return tokens_consumed
    if token in {"<<", "<<-", "<<<"}:
        return 2 if index + 1 < len(segment) else 1
    if token in {">", ">>", ">|", "0>", "0>>", "0>|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
        return 2 if index + 1 < len(segment) else 1
    if re.fullmatch(r"(?P<fd>[0-2]?)(?P<op>>\||>>|>)(?P<target>.+)", token):
        return 1
    return 0


def _segment_contains_destructive_node_inline_eval(segment_args: list[str]) -> bool:
    lowered_args = [arg.lower() for arg in segment_args]
    index = 0
    while index < len(lowered_args):
        token = lowered_args[index]
        if token == "--":
            break
        if token in _NODE_INLINE_EVAL_FLAGS and index + 1 < len(lowered_args):
            if token in {"-p", "--print"} and lowered_args[index + 1].startswith("-"):
                index += 1
                continue
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if _is_combined_node_inline_eval_flag(token) and index + 1 < len(lowered_args):
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if token.startswith("--eval="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("--print="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("-e") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token.startswith("-p") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token in _NODE_OPTION_FLAGS_WITH_VALUE and index + 1 < len(lowered_args):
            index += 2
            continue
        if not token.startswith("-"):
            break
        index += 1
    return False


def _find_segment_uses_delete(segment_args: list[str]) -> bool:
    value_taking_predicates = {
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-lname",
        "-ilname",
    }
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token in {"-exec", "-execdir", "-ok", "-okdir"}:
            index += 1
            if index < len(segment_args):
                command_name = _normalized_shell_command_name(segment_args[index])
                if command_name in _DESTRUCTIVE_SHELL_COMMANDS:
                    return True
            while index < len(segment_args) and segment_args[index] not in {";", "+"}:
                index += 1
            if index < len(segment_args):
                index += 1
            continue
        if token in value_taking_predicates and index + 1 < len(segment_args):
            index += 2
            continue
        if token == "-delete":
            return True
        index += 1
    return False


def _contains_destructive_git_command(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "git" or command_index is None:
            continue
        if _segment_uses_destructive_git_command(segment[command_index + 1 :]):
            return True
    return False


def _segment_uses_destructive_git_command(segment_args: list[str]) -> bool:
    subcommand_index = 0
    while subcommand_index < len(segment_args):
        token = segment_args[subcommand_index]
        if token == "--":
            subcommand_index += 1
            continue
        if token in {"-h", "--help", "--version"}:
            return False
        if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE and subcommand_index + 1 < len(segment_args):
            subcommand_index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _GIT_GLOBAL_OPTIONS_WITH_VALUE if option.startswith("--")):
            subcommand_index += 1
            continue
        if token.startswith("-"):
            subcommand_index += 1
            continue
        normalized_token = token.strip().lower()
        if normalized_token == "help":
            return False
        if normalized_token == "clean":
            clean_arguments = segment_args[subcommand_index + 1 :]
            return not _git_clean_is_preview(clean_arguments)
        return normalized_token in _DESTRUCTIVE_GIT_SUBCOMMANDS
    return False


def _git_clean_is_preview(arguments: list[str]) -> bool:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        normalized = argument.strip().lower()
        option_name = normalized.split("=", 1)[0]
        if option_name in {"-e", "--exclude"} and "=" not in normalized:
            index += 2
            continue
        if normalized == "--dry-run":
            return True
        if normalized.startswith("-") and not normalized.startswith("--"):
            for flag in normalized[1:]:
                if flag == "e":
                    break
                if flag == "n":
                    return True
        index += 1
    return False


def _env_split_string_payloads(parts: list[str]) -> tuple[str, ...]:
    payloads: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        env_index = _shell_segment_env_index(segment)
        if env_index is None:
            continue
        parsed = parse_env_wrapper(segment[env_index + 1 :])
        payloads.extend(expansion.payload for expansion in parsed.split_expansions if expansion.payload.strip())
    return tuple(payloads)


def _shell_segment_env_index(segment: list[str]) -> int | None:
    index = 0
    while index < len(segment):
        normalized_token = segment[index].lstrip("(").rstrip(")")
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            return index
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return None
    return None


def _contains_mutating_shell_redirection(parts: list[str]) -> bool:
    index = 0
    while index < len(parts):
        token = parts[index].strip()
        if not token:
            index += 1
            continue
        fd = ""
        target: str | None = None
        if token in {">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
            if token[0].isdigit():
                fd = token[0]
            if token.endswith(">") and index + 2 < len(parts) and parts[index + 1] == "|":
                target = parts[index + 2]
                index += 3
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        else:
            redirection = _split_attached_redirection_token(token)
            if redirection is None:
                index += 1
                continue
            prefix, fd, _op, target = redirection
            if prefix.endswith("="):
                index += 1
                continue
            if target:
                index += 1
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        if target is None:
            continue
        normalized_target = _normalized_redirect_target(target).lower()
        if fd == "2" and normalized_target in _SAFE_SHELL_REDIRECT_TARGETS:
            continue
        if normalized_target in _SAFE_SHELL_REDIRECT_TARGETS or normalized_target.startswith("&"):
            continue
        return True
    return False


def _split_attached_redirection_token(token: str) -> tuple[str, str, str, str] | None:
    for index, character in enumerate(token):
        if character != ">":
            continue
        op = _attached_redirection_operator(token, index)
        prefix = token[:index]
        if any(character.isspace() or character in {"<", ">"} for character in prefix):
            continue
        target = token[index + len(op) :]
        fd = ""
        if prefix and prefix[-1] in {"0", "1", "2"}:
            fd = prefix[-1]
            prefix = prefix[:-1]
        return prefix, fd, op, target
    return None


def _attached_redirection_operator(token: str, index: int) -> str:
    next_character = token[index + 1 : index + 2]
    if next_character == "|":
        return ">|"
    if next_character == ">":
        return ">>"
    return ">"


def _normalized_redirect_target(target: str) -> str:
    return target.strip().strip(");,").strip("'\"")


def _redacted_node_inline_string_literals(script: str, *, preserve_bracket_member_strings: bool = False) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    preserve_string_contents = False
    template_expression_depth = 0
    comment_type: str | None = None
    regex_literal = False
    regex_escape_next = False
    regex_char_class = False
    index = 0
    while index < len(script):
        character = script[index]
        if quote_char is None:
            if template_expression_depth > 0:
                if comment_type == "line":
                    result.append(character)
                    if character in {"\n", "\r"}:
                        comment_type = None
                    index += 1
                    continue
                if comment_type == "block":
                    result.append(character)
                    if character == "/" and result[-2:-1] == ["*"]:
                        comment_type = None
                    index += 1
                    continue
                if regex_literal:
                    result.append(character)
                    if regex_escape_next:
                        regex_escape_next = False
                    elif character == "\\":
                        regex_escape_next = True
                    elif character == "[" and not regex_char_class:
                        regex_char_class = True
                    elif character == "]" and regex_char_class:
                        regex_char_class = False
                    elif character == "/" and not regex_char_class:
                        regex_literal = False
                    index += 1
                    continue
                if character == "/" and index + 1 < len(script):
                    next_character = script[index + 1]
                    if next_character == "/":
                        result.append("//")
                        comment_type = "line"
                        index += 2
                        continue
                    if next_character == "*":
                        result.append("/*")
                        comment_type = "block"
                        index += 2
                        continue
                    if _js_slash_starts_regex(result):
                        result.append(character)
                        regex_literal = True
                        regex_escape_next = False
                        regex_char_class = False
                        index += 1
                        continue
                if character == "{":
                    template_expression_depth += 1
                    result.append(character)
                    index += 1
                    continue
                if character == "}":
                    template_expression_depth -= 1
                    result.append(character)
                    if template_expression_depth == 0:
                        quote_char = "`"
                        comment_type = None
                        regex_literal = False
                        regex_escape_next = False
                        regex_char_class = False
                    index += 1
                    continue
            if character in {"'", '"', "`"}:
                preserve_string_contents = (
                    preserve_bracket_member_strings and _last_non_whitespace_character(result) == "["
                )
                quote_char = character
                result.append(character)
                index += 1
                continue
            result.append(character)
            index += 1
            continue
        if escape_next:
            result.append(character if preserve_string_contents else "Q")
            escape_next = False
            index += 1
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            index += 1
            continue
        if quote_char == "`" and character == "$" and index + 1 < len(script) and script[index + 1] == "{":
            result.append("${")
            quote_char = None
            preserve_string_contents = False
            template_expression_depth = 1
            index += 2
            continue
        if character == quote_char:
            result.append(character)
            quote_char = None
            preserve_string_contents = False
            index += 1
            continue
        result.append(character if preserve_string_contents else "Q")
        index += 1
    return "".join(result)


def _last_non_whitespace_character(result: list[str]) -> str | None:
    for chunk in reversed(result):
        for character in reversed(chunk):
            if not character.isspace():
                return character
    return None


def _js_slash_starts_regex(result: list[str]) -> bool:
    previous_character = _last_non_whitespace_character(result)
    if previous_character is None:
        return True
    return previous_character in {
        "(",
        "{",
        "[",
        "=",
        ":",
        ",",
        ";",
        "!",
        "?",
        "|",
        "&",
        "+",
        "-",
        "*",
        "%",
        "^",
        "~",
    }


def _shell_command_names(command_text: str) -> tuple[str, ...]:
    return _shell_command_names_from_parts(_split_shell_parts(command_text))


def _normalized_shell_command_name(command_name: str) -> str:
    normalized_command = command_name.replace("\\", "/").strip()
    if "/" not in normalized_command:
        return normalized_command.lower()
    return normalized_command.rsplit("/", 1)[-1].lower()


def _shell_command_token_without_attached_redirection(token: str) -> str:
    normalized_token = token.lstrip("(").rstrip(")")
    for index, character in enumerate(normalized_token):
        if index == 0 or character not in {"<", ">"}:
            continue
        return normalized_token[:index]
    return normalized_token


def _redacted_shell_text_for_command_names(command_text: str) -> str:
    return re.sub(r"'[^']*'|\"[^\"]*\"", "Q", command_text)


def _split_shell_parts(command_text: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            _replace_unquoted_newlines_with_separators(command_text),
            posix=True,
            punctuation_chars=";&|",
        )
        lexer.whitespace_split = True
        parts = list(lexer)
    except ValueError:
        parts = command_text.split()
    return _merge_shell_fd_redirect_parts(parts)


def _merge_shell_fd_redirect_parts(parts: list[str]) -> list[str]:
    merged: list[str] = []
    index = 0
    while index < len(parts):
        token = parts[index]
        if index + 2 < len(parts) and re.fullmatch(r"[012]?>", token) and parts[index + 1] == "&":
            fd_prefix = token[:-1]
            redirect_target = parts[index + 2]
            merged.append(f"{fd_prefix}>&{redirect_target}" if fd_prefix else f">&{redirect_target}")
            index += 3
            continue
        merged.append(token)
        index += 1
    return merged


def _replace_unquoted_newlines_with_separators(command_text: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    for character in command_text:
        if escape_next:
            result.append(character)
            escape_next = False
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            continue
        if quote_char is None and character in {"'", '"', "`"}:
            quote_char = character
            result.append(character)
            continue
        if quote_char == character:
            quote_char = None
            result.append(character)
            continue
        if quote_char is None and character in {"\n", "\r"}:
            if not result or result[-1] != " ":
                result.append(" ")
            result.append("\n")
            result.append(_SHELL_NEWLINE_SEPARATOR)
            result.append("\n")
            continue
        result.append(character)
    return "".join(result)


def _wrapper_option_tokens_consumed(command_name: str, token: str) -> int:
    if not token.startswith("-"):
        return 1
    if command_name == "sudo":
        sudo_short_option_tokens = _sudo_short_option_tokens_consumed(token)
        if sudo_short_option_tokens is not None:
            return sudo_short_option_tokens
    exact_flags = _WRAPPER_FLAGS_WITH_VALUES.get(command_name, frozenset())
    if token in exact_flags:
        return 2
    if _wrapper_flag_has_attached_value(command_name, token):
        return 1
    return 1


def _sudo_short_option_tokens_consumed(token: str) -> int | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        if index < len(token) - 1:
            return 1
        return 2
    return 1


def _wrapper_flag_has_attached_value(command_name: str, token: str) -> bool:
    if command_name == "nice":
        return token.startswith("--adjustment=") or (token.startswith("-n") and token != "-n")
    if command_name == "stdbuf":
        return token.startswith(("--input=", "--output=", "--error=")) or (
            len(token) > 2 and token[:2] in {"-i", "-o", "-e"}
        )
    if command_name == "sudo":
        return token.startswith(
            (
                "--chdir=",
                "--chroot=",
                "--close-from=",
                "--command-timeout=",
                "--group=",
                "--host=",
                "--prompt=",
                "--role=",
                "--type=",
                "--user=",
            )
        ) or _sudo_short_option_has_attached_value(token)
    if command_name == "time":
        return token.startswith(("--format=", "--output=")) or (len(token) > 2 and token[:2] in {"-f", "-o"})
    return False


def _sudo_short_option_has_attached_value(token: str) -> bool:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return False
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        return index < len(token) - 1
    return False


def _is_shell_env_assignment_token(token: str) -> bool:
    name, separator, _ = token.partition("=")
    if separator != "=" or not name:
        return False
    if name.endswith("+"):
        name = name[:-1]
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(character.isalnum() or character == "_" for character in name[1:])


def _shell_command_names_from_parts(parts: list[str]) -> tuple[str, ...]:
    command_names: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, _command_index = _shell_segment_primary_command(segment)
        if command_name is not None:
            command_names.append(command_name)
    return tuple(command_names)


def _shell_command_scripts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or command_index is None:
            continue
        flag_payload = _shell_interpreter_command_payload(segment, command_index)
        if flag_payload is not None:
            scripts.append(flag_payload.script_text)
    return tuple(scripts)


def _contains_pytest_env_shell_script_wrapper(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or command_index is None:
            continue
        has_unsafe_env = any(
            _shell_segment_sets_env_key(segment, command_index, env_key)
            for env_key in _PYTEST_UNSAFE_ENV_KEYS | _SHELL_STARTUP_ENV_KEYS
        )
        if not has_unsafe_env:
            continue
        flag_payload = _shell_interpreter_command_payload(segment, command_index)
        if flag_payload is not None and _shell_script_targets_pytest(flag_payload.script_text):
            return True
    return False


def _shell_script_targets_pytest(script_text: str) -> bool:
    for segment in _iter_shell_command_segments(_split_shell_parts(script_text)):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return True
    return False


def _shell_command_targets_pytest(command_text: str, *, depth: int = 0) -> bool:
    """Return whether shell evaluation can reach pytest outside Guard containment."""

    if depth > 8:
        return any(
            _normalized_shell_command_name(token) in _PYTEST_COMMAND_NAMES for token in _split_shell_parts(command_text)
        )
    parts = _split_shell_parts(command_text)
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index, depth=depth):
            return True
        if command_name in _SHELL_COMMAND_STRING_INTERPRETERS:
            flag_payload = _shell_interpreter_command_payload(segment, command_index)
            if flag_payload is not None and _shell_command_targets_pytest(flag_payload.script_text, depth=depth + 1):
                return True
    return any(
        _shell_command_targets_pytest(payload, depth=depth + 1)
        for payload in _shell_command_substitution_payloads(command_text)
    )


def _script_interpreter_texts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS and not _is_script_interpreter_command(command_name):
            continue
        index = command_index + 1
        while index < len(segment):
            flag_payload = _interpreter_flag_payload(segment, index)
            if flag_payload is not None:
                scripts.append(flag_payload.script_text)
                break
            index += 1
    return tuple(scripts)


def _looks_like_benign_interpreter_wait(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if not command_names or not all(_is_script_interpreter_command(command_name) for command_name in command_names):
        return False
    scripts = _script_interpreter_texts(parts)
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_benign_wait(script_text) for script_text in scripts)


def _looks_like_read_only_shell_pipeline(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    pipelines = _iter_shell_pipelines(parts)
    if len(pipelines) != 1:
        return False
    pipeline = pipelines[0]
    if len(pipeline) < 2:
        return False
    return all(_pipeline_segment_is_read_only(segment, cwd=cwd, home_dir=home_dir) for segment in pipeline)


def _pipeline_segment_is_read_only(
    segment: list[str],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    if _is_python_interpreter_command(command_name):
        scripts = list(_script_interpreter_texts(segment))
        return bool(scripts) and all(_script_is_read_only_observer(script_text) for script_text in scripts)
    segment_text = " ".join(segment)
    return not _looks_destructive_shell_command(segment_text, cwd=cwd, home_dir=home_dir)


def _looks_like_read_only_interpreter_command(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if any(
        _is_python_interpreter_command(command_name) for command_name in command_names
    ) and _parts_use_python_module_mode(parts):
        return False
    heredoc_script = _single_interpreter_heredoc_script(command_text)
    if heredoc_script is not None:
        heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
        if heredoc_interpreter is None or not _is_read_only_observer_interpreter_command(heredoc_interpreter):
            return False
        heredoc_args = _single_interpreter_heredoc_args(command_text)
        if heredoc_args not in {"", "-"}:
            return False
        scripts = list(_script_interpreter_texts(parts))
        if scripts:
            scripts.append(heredoc_script)
            return all(_script_is_read_only_observer(script_text) for script_text in scripts)
        return _script_is_read_only_observer(heredoc_script)
    if not command_names or not all(
        _is_read_only_observer_interpreter_command(command_name) for command_name in command_names
    ):
        return False
    scripts = list(_script_interpreter_texts(parts))
    scripts.extend(_shell_heredoc_payloads(command_text))
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_read_only_observer(script_text) for script_text in scripts)


def _looks_like_safe_python_module_invocation(parts: list[str], *, cwd: Path | None = None) -> bool:
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    saw_python_module = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        segment_args = segment[command_index + 1 :]
        if _is_python_interpreter_command(command_name):
            module_root = _python_module_root_from_args(segment_args)
            unsafe_env_keys = _python_module_unsafe_env_keys(module_root)
            if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in unsafe_env_keys):
                return False
            if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
                return False
            if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
                return False
            if _python_module_may_be_shadowed_from_execution_context(
                module_root,
                cwd=cwd,
                segment=segment,
                command_index=command_index,
            ):
                return False
            if not _python_segment_runs_safe_module(segment_args, cwd=cwd):
                return False
            saw_python_module = True
            continue
        if _shell_directory_setup_segment_is_safe(command_name, segment_args):
            continue
        if command_name in _READ_ONLY_LOOKUP_FILTERS and _read_only_lookup_filter_segment_is_safe(
            command_name,
            segment_args,
        ):
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(segment_args):
            continue
        return False
    return saw_python_module


def _contains_unsafe_pytest_environment_wrapper(parts: list[str], *, cwd: Path | None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if not _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
            continue
        if command_name == "pytest":
            if not _pytest_binary_segment_is_safe(segment[command_index], segment[command_index + 1 :], cwd=cwd):
                return True
            return True
        if _is_python_interpreter_command(command_name) and _python_segment_targets_module(
            segment[command_index + 1 :],
            "pytest",
        ):
            if not _python_segment_runs_safe_module(segment[command_index + 1 :], cwd=cwd):
                return True
            return True
    return False


def _contains_pytest_process_substitution(command_text: str, parts: list[str]) -> bool:
    if "<(" not in command_text and ">(" not in command_text:
        return False
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return True
    return False


def _contains_prior_pytest_state_mutation(parts: list[str]) -> bool:
    saw_state_mutation = False
    exported_pytest_env_keys: set[str] = set()
    for segment in _iter_shell_command_segments(parts):
        if any(
            _shell_env_assignment_key(token) == "PATH" or _shell_env_assignment_key(token) in exported_pytest_env_keys
            for token in segment
            if _shell_env_assignment_key(token) is not None
        ):
            saw_state_mutation = True
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return saw_state_mutation
        if command_name in {"cd", "pushd", "popd"}:
            if not _shell_directory_setup_segment_is_safe(command_name, segment[command_index + 1 :]):
                saw_state_mutation = True
            continue
        if command_name == "set" and _shell_set_exports_assignments(segment[command_index + 1 :]):
            saw_state_mutation = True
            continue
        if command_name == "export":
            for token in segment[command_index + 1 :]:
                env_key = _shell_declared_env_key(token)
                if env_key not in {"PATH", *_PYTEST_UNSAFE_ENV_KEYS}:
                    continue
                exported_pytest_env_keys.add(env_key)
                if "=" in token:
                    saw_state_mutation = True
        if command_name in {"declare", "typeset"} and _shell_declaration_exports_env(segment[command_index + 1 :]):
            for token in segment[command_index + 1 :]:
                if token.startswith("-") or token == "--":
                    continue
                env_key = _shell_declared_env_key(token)
                if env_key not in {"PATH", *_PYTEST_UNSAFE_ENV_KEYS}:
                    continue
                exported_pytest_env_keys.add(env_key)
                if "=" in token:
                    saw_state_mutation = True
    return False


def _segment_targets_pytest(
    segment: list[str],
    command_name: str,
    command_index: int,
    *,
    depth: int = 0,
) -> bool:
    if command_name in _PYTEST_COMMAND_NAMES:
        return True
    command_args = segment[command_index + 1 :]
    if _is_pytest_python_interpreter_command(command_name):
        return _python_segment_targets_module(command_args, "pytest") or _python_inline_script_runs_pytest(command_args)
    if command_name == "uvx":
        return _argument_sequence_targets_pytest(command_args)
    runner_subcommands = _PYTEST_COMMAND_RUNNER_SUBCOMMANDS.get(command_name)
    if runner_subcommands is not None:
        return any(
            token in runner_subcommands
            and _pytest_args_from_runner_argument_sequence(command_name, command_args[index + 1 :]) is not None
            for index, token in enumerate(command_args)
        )
    if command_name in _PYTEST_EXECUTOR_COMMANDS:
        return _argument_sequence_targets_pytest(command_args)
    if command_name == "eval":
        return _shell_command_targets_pytest(" ".join(command_args), depth=depth + 1)
    if command_name == "find":
        return any(
            token in _FIND_EXEC_ACTION_FLAGS and _argument_sequence_targets_pytest(command_args[index + 1 :])
            for index, token in enumerate(command_args)
        )
    if command_name == "fd":
        return any(
            fd_arg_requests_exec(token) and _argument_sequence_targets_pytest(command_args[index + 1 :])
            for index, token in enumerate(command_args)
        )
    return False


def _argument_sequence_targets_pytest(args: list[str]) -> bool:
    return _pytest_args_from_argument_sequence(args) is not None


def _pytest_args_from_argument_sequence(args: list[str]) -> list[str] | None:
    return _pytest_args_from_argument_sequence_ignoring(args, ignored_indices=frozenset())


def _pytest_args_from_runner_argument_sequence(command_name: str, args: list[str]) -> list[str] | None:
    value_options = _PYTEST_RUNNER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    ignored_indices: set[int] = set()
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            break
        if token in value_options:
            if index + 1 >= len(args):
                return None
            ignored_indices.add(index + 1)
            index += 2
            continue
        index += 1
    positional_prefix_count = _PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS.get(command_name, 0)
    for index, token in enumerate(args):
        if index in ignored_indices or token == "--" or token.startswith("-"):
            continue
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            continue
        if positional_prefix_count:
            positional_prefix_count -= 1
            continue
        return _pytest_args_from_command_position(args, index)
    return None


def _pytest_args_from_argument_sequence_ignoring(
    args: list[str],
    *,
    ignored_indices: frozenset[int],
) -> list[str] | None:
    for index in range(len(args)):
        if index in ignored_indices:
            continue
        pytest_args = _pytest_args_from_command_position(args, index)
        if pytest_args is not None:
            return pytest_args
    return None


def _pytest_args_from_command_position(args: list[str], index: int) -> list[str] | None:
    command_token = args[index].rsplit(":", 1)[-1]
    command_name = _normalized_shell_command_name(command_token)
    if command_name in _PYTEST_COMMAND_NAMES:
        return args[index + 1 :]
    if not _is_pytest_python_interpreter_command(command_name):
        return None
    python_args = _pytest_args_from_python(args[index + 1 :])
    if python_args is not None:
        return python_args
    if _python_inline_script_runs_pytest(args[index + 1 :]):
        return []
    return None


def _python_inline_script_runs_pytest(args: list[str]) -> bool:
    for index, token in enumerate(args):
        if token in {"-c", "--command"} and index + 1 < len(args):
            return _inline_python_payload_runs_pytest(args[index + 1])
        if token.startswith("--command="):
            return _inline_python_payload_runs_pytest(token.split("=", 1)[1])
        if token.startswith("-c") and token != "-c":
            return _inline_python_payload_runs_pytest(token[2:])
        if not token.startswith("-"):
            return False
    return False


def _inline_python_payload_runs_pytest(payload: str, *, depth: int = 0) -> bool:
    if depth > 8:
        return "pytest" in payload.casefold()
    try:
        tree = ast.parse(payload, mode="exec")
    except (SyntaxError, ValueError):
        return False

    pytest_module_aliases = {"pytest"}
    pytest_main_aliases: set[str] = set()
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    runpy_aliases = {"runpy"}
    run_module_aliases: set[str] = set()
    os_aliases = {"os"}
    os_process_aliases: set[str] = set()
    subprocess_aliases = {"subprocess"}
    subprocess_process_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pytest":
                    pytest_module_aliases.add(alias.asname or "pytest")
                elif alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
                elif alias.name == "runpy":
                    runpy_aliases.add(alias.asname or "runpy")
                elif alias.name == "os":
                    os_aliases.add(alias.asname or "os")
                elif alias.name == "subprocess":
                    subprocess_aliases.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "pytest":
                pytest_main_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name in {"console_main", "main"}
                )
            elif node.module == "importlib":
                import_module_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "import_module"
                )
            elif node.module == "runpy":
                run_module_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "run_module"
                )
            elif node.module == "os":
                os_process_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name in {"popen", "system"}
                )
            elif node.module == "subprocess":
                subprocess_process_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in {"Popen", "call", "check_call", "check_output", "run"}
                )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and function.id in pytest_main_aliases:
            return True
        if isinstance(function, ast.Call) and _python_call_resolves_pytest_main(
            function,
            pytest_module_aliases=pytest_module_aliases,
            importlib_aliases=importlib_aliases,
            import_module_aliases=import_module_aliases,
        ):
            return True
        if isinstance(function, ast.Attribute) and function.attr in {"console_main", "main"}:
            if isinstance(function.value, ast.Name) and function.value.id in pytest_module_aliases:
                return True
            if isinstance(function.value, ast.Call) and _python_call_imports_pytest(
                function.value,
                importlib_aliases=importlib_aliases,
                import_module_aliases=import_module_aliases,
            ):
                return True
        if _python_call_runs_pytest_module(
            node,
            runpy_aliases=runpy_aliases,
            run_module_aliases=run_module_aliases,
        ):
            return True
        if _python_process_call_targets_pytest(
            node,
            depth=depth,
            os_aliases=os_aliases,
            os_process_aliases=os_process_aliases,
            subprocess_aliases=subprocess_aliases,
            subprocess_process_aliases=subprocess_process_aliases,
        ):
            return True
        if (
            isinstance(function, ast.Name)
            and function.id in {"eval", "exec"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and _inline_python_payload_runs_pytest(node.args[0].value, depth=depth + 1)
        ):
            return True
    return False


def _python_process_call_targets_pytest(
    node: ast.Call,
    *,
    depth: int,
    os_aliases: set[str],
    os_process_aliases: set[str],
    subprocess_aliases: set[str],
    subprocess_process_aliases: set[str],
) -> bool:
    function = node.func
    recognized = isinstance(function, ast.Name) and function.id in {
        *os_process_aliases,
        *subprocess_process_aliases,
    }
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
        recognized = recognized or (function.value.id in os_aliases and function.attr in {"popen", "system"})
        recognized = recognized or (
            function.value.id in subprocess_aliases
            and function.attr in {"Popen", "call", "check_call", "check_output", "run"}
        )
    if not recognized:
        return False

    command_node: ast.expr | None = node.args[0] if node.args else None
    if command_node is None:
        command_node = next((keyword.value for keyword in node.keywords if keyword.arg in {"args", "command"}), None)
    if isinstance(command_node, ast.Constant) and isinstance(command_node.value, str):
        return _shell_command_targets_pytest(command_node.value, depth=depth + 1)
    literal_argv = _literal_python_argv(command_node)
    return literal_argv is not None and _argument_sequence_targets_pytest(literal_argv)


def _literal_python_argv(node: ast.expr | None) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    argv: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        argv.append(element.value)
    return argv


def _python_call_resolves_pytest_main(
    node: ast.Call,
    *,
    pytest_module_aliases: set[str],
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> bool:
    if (
        not isinstance(node.func, ast.Name)
        or node.func.id != "getattr"
        or len(node.args) < 2
        or not isinstance(node.args[1], ast.Constant)
        or node.args[1].value not in {"console_main", "main"}
    ):
        return False
    target = node.args[0]
    if isinstance(target, ast.Name):
        return target.id in pytest_module_aliases
    return isinstance(target, ast.Call) and _python_call_imports_pytest(
        target,
        importlib_aliases=importlib_aliases,
        import_module_aliases=import_module_aliases,
    )


def _python_call_imports_pytest(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> bool:
    if not node.args or not isinstance(node.args[0], ast.Constant) or node.args[0].value != "pytest":
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id == "__import__" or node.func.id in import_module_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_aliases
    )


def _python_call_runs_pytest_module(
    node: ast.Call,
    *,
    runpy_aliases: set[str],
    run_module_aliases: set[str],
) -> bool:
    if (
        not node.args
        or not isinstance(node.args[0], ast.Constant)
        or node.args[0].value not in {"pytest", "pytest.__main__"}
    ):
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id in run_module_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "run_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in runpy_aliases
    )


def _shell_env_assignment_targets_key(token: str, env_key: str) -> bool:
    return _shell_env_assignment_key(token) == env_key.upper()


def _shell_env_assignment_key(token: str) -> str | None:
    if "+=" in token:
        key = token.split("+=", 1)[0]
    elif "=" in token:
        key = token.split("=", 1)[0]
    else:
        return None
    if not key:
        return None
    return key.upper()


def _shell_declared_env_key(token: str) -> str:
    assignment_key = _shell_env_assignment_key(token)
    if assignment_key is not None:
        return assignment_key
    return token.upper()


def _shell_declaration_exports_env(args: list[str]) -> bool:
    for token in args:
        if token == "--":
            return False
        if not token.startswith("-"):
            continue
        if token.startswith("+"):
            continue
        if "x" in token.lstrip("-"):
            return True
    return False


def _shell_set_exports_assignments(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return False
        if token in {"-a", "-k", "allexport", "keyword"}:
            return True
        if token == "-o":
            return index + 1 < len(args) and args[index + 1] in {"allexport", "keyword"}
        if token == "+o":
            index += 2
            continue
        if token.startswith("-") and not token.startswith("--") and any(flag in token[1:] for flag in {"a", "k"}):
            return True
        index += 1
    return False


def _looks_like_safe_pytest_binary_invocation(parts: list[str], *, cwd: Path | None) -> bool:
    saw_pytest = False
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        segment_args = segment[command_index + 1 :]
        if command_name == "pytest":
            if _shell_segment_sets_env_key(segment, command_index, "PATH"):
                return False
            if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in _PYTEST_UNSAFE_ENV_KEYS):
                return False
            if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
                return False
            if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
                return False
            if not _pytest_binary_segment_is_safe(segment[command_index], segment_args, cwd=cwd):
                return False
            saw_pytest = True
            continue
        if _shell_directory_setup_segment_is_safe(command_name, segment_args):
            continue
        if command_name in _READ_ONLY_LOOKUP_FILTERS and _read_only_lookup_filter_segment_is_safe(
            command_name,
            segment_args,
        ):
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(segment_args):
            continue
        return False
    return saw_pytest


def _contains_unsafe_pytest_binary_invocation(parts: list[str], *, cwd: Path | None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "pytest" or command_index is None:
            continue
        if _shell_segment_sets_env_key(segment, command_index, "PATH"):
            return True
        if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in _PYTEST_UNSAFE_ENV_KEYS):
            return True
        if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
            return True
        if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
            return True
        if not _pytest_binary_segment_is_safe(segment[command_index], segment[command_index + 1 :], cwd=cwd):
            return True
    return False


def _pytest_binary_segment_is_safe(command_token: str, module_args: list[str], *, cwd: Path | None) -> bool:
    if "/" in command_token or "\\" in command_token:
        return False
    if _python_module_may_be_shadowed("pytest", cwd):
        return False
    if _pytest_config_may_add_unsafe_options(cwd, module_args):
        return False
    return _pytest_module_args_are_safe(module_args)


def _shell_segment_sets_env_key(segment: list[str], command_index: int, env_key: str) -> bool:
    is_set, _value, complete = _shell_segment_explicit_env_value(segment, command_index, env_key)
    return is_set or not complete


def _shell_segment_explicit_env_value(
    segment: list[str],
    command_index: int,
    env_key: str,
) -> tuple[bool, str | None, bool]:
    normalized_env_key = env_key.upper()
    is_set = False
    value: str | None = None
    index = 0
    while index < command_index:
        token = _shell_command_token_without_attached_redirection(segment[index])
        assignment_key = _shell_env_assignment_key(token)
        if assignment_key == normalized_env_key:
            is_set = True
            value = token.split("=", 1)[1] if "=" in token else ""
            index += 1
            continue
        if _normalized_shell_command_name(token) != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if not parsed.complete:
            return is_set, value, False
        if parsed.option_effects.ignore_environment or any(
            name.upper() == normalized_env_key for name in parsed.option_effects.unset_names
        ):
            is_set = False
            value = None
        for name, assignment_value in parsed.environment_delta.assignments:
            if name.upper() == normalized_env_key:
                is_set = True
                value = assignment_value
        if parsed.command_index is None or parsed.split_expansions:
            break
        index += parsed.command_index + 1
    return is_set, value, True


def _shell_directory_setup_segment_is_safe(command_name: str, segment_args: list[str]) -> bool:
    if command_name == "popd":
        path_args = _shell_args_without_trailing_redirections(segment_args)
        return not path_args or all(not _shell_token_has_command_substitution(token) for token in path_args)
    if command_name not in {"cd", "pushd"}:
        return False
    path_args = _shell_args_without_trailing_redirections(segment_args)
    if not path_args:
        return False
    for token in path_args:
        if token in {"-", "--"}:
            continue
        if token.startswith("-"):
            return False
        if _shell_token_has_command_substitution(token):
            return False
    return True


def _shell_token_has_command_substitution(token: str) -> bool:
    if "$(" in token or "`" in token:
        return True
    return any(character in token for character in ("$", "<", ">", "|", "&", ";", "\n"))


def _python_module_root_from_args(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return None
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return None
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return module.split(".", 1)[0] or None
        if arg.startswith("-m") and len(arg) > 2:
            return arg[2:].split(".", 1)[0] or None
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return None
        index += 1
    return None


def _python_module_unsafe_env_keys(module_root: str | None) -> frozenset[str]:
    if module_root == "pytest":
        return _PYTEST_UNSAFE_ENV_KEYS
    return _PYTEST_UNSAFE_ENV_KEYS - frozenset({"PYTHONPATH"})


def _shell_args_without_trailing_redirections(args: list[str]) -> list[str]:
    trimmed = list(args)
    while trimmed and _is_shell_redirection_token(trimmed[-1]):
        trimmed.pop()
    return trimmed


def _is_shell_redirection_token(token: str) -> bool:
    if token in {"|", "|&"}:
        return True
    if _split_attached_redirection_token(token) is not None:
        return True
    return bool(re.fullmatch(r"[012]?>&?\S*", token) or re.fullmatch(r"[012]?>>?", token))


def _shell_segment_uses_env_split_string_wrapper(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if parsed.split_expansions:
            return True
        if not parsed.complete or parsed.command_index is None:
            break
        index += parsed.command_index + 1
    return False


def _shell_segment_uses_env_chdir(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if parsed.option_effects.chdir is not None:
            return True
        if not parsed.complete or parsed.command_index is None or parsed.split_expansions:
            break
        index += parsed.command_index + 1
    return False


def _shell_segment_uses_sudo_chdir(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "sudo":
            index += 1
            continue
        index += 1
        while index < command_index:
            token = segment[index]
            if token in {"-D", "--chdir"} or token.startswith(("-D", "--chdir=")):
                return True
            if not token.startswith("-"):
                break
            index += _wrapper_option_tokens_consumed("sudo", token)
    return False


def _shell_segment_uses_cwd_changing_wrapper(segment: list[str], command_index: int) -> bool:
    return _shell_segment_uses_env_chdir(segment, command_index) or _shell_segment_uses_sudo_chdir(
        segment,
        command_index,
    )


def _parts_use_python_module_mode(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None or not _is_python_interpreter_command(command_name):
            continue
        if _python_args_use_module_mode(segment[command_index + 1 :]):
            return True
    return False


def _python_args_use_module_mode(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--" or arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m" or (arg.startswith("-m") and len(arg) > 2):
            return True
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _python_segment_runs_safe_module(args: list[str], *, cwd: Path | None = None) -> bool:
    args = _shell_args_without_trailing_redirections(args)
    if not args:
        return False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return False
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return _python_module_args_are_safe(module, args[index + 2 :], cwd=cwd)
        if arg.startswith("-m") and len(arg) > 2:
            module = arg[2:]
            return _python_module_args_are_safe(module, args[index + 1 :], cwd=cwd)
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _python_segment_targets_module(args: list[str], module_root: str) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return False
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return module.split(".", 1)[0] == module_root
        if arg.startswith("-m") and len(arg) > 2:
            return arg[2:].split(".", 1)[0] == module_root
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _python_module_args_are_safe(module: str, module_args: list[str], *, cwd: Path | None = None) -> bool:
    module_root = module.split(".", 1)[0]
    if module_root not in _SAFE_PYTHON_MODULE_COMMANDS:
        return False
    if _python_module_may_be_shadowed(module_root, cwd):
        return False
    if module_root == "pytest" and _pytest_config_may_add_unsafe_options(cwd, module_args):
        return False
    if module_root == "pytest" and not _pytest_module_args_are_safe(module_args):
        return False
    mutating_subcommands = _PYTHON_MODULE_MUTATING_SUBCOMMANDS.get(module_root, frozenset())
    if _python_module_subcommand(module_root, module_args) in mutating_subcommands:
        return False
    mutating_flags = _PYTHON_MODULE_MUTATING_FLAGS.get(module_root, frozenset())
    return not any(
        arg in mutating_flags or any(arg.startswith(f"{flag}=") for flag in mutating_flags) for arg in module_args
    )


def _python_module_may_be_shadowed(module_root: str, cwd: Path | None) -> bool:
    return _python_module_may_be_shadowed_in_search_roots(module_root, [cwd] if cwd is not None else [])


def _python_module_may_be_shadowed_from_execution_context(
    module_root: str | None,
    *,
    cwd: Path | None,
    segment: list[str],
    command_index: int,
) -> bool:
    if module_root is None:
        return True
    search_roots: list[Path] = []
    if cwd is not None:
        search_roots.append(cwd)
    search_roots.extend(_pythonpath_search_roots_from_segment(segment, command_index, cwd=cwd))
    return _python_module_may_be_shadowed_in_search_roots(module_root, search_roots)


def _pythonpath_search_roots_from_segment(
    segment: list[str],
    command_index: int,
    *,
    cwd: Path | None,
) -> list[Path]:
    if cwd is None:
        return []
    search_roots: list[Path] = []
    is_set, path_value, complete = _shell_segment_explicit_env_value(
        segment,
        command_index,
        "PYTHONPATH",
    )
    if not complete or not is_set or path_value is None:
        return search_roots
    for entry in path_value.split(":"):
        normalized_entry = entry.strip()
        if not normalized_entry:
            continue
        candidate = Path(normalized_entry)
        search_roots.append(candidate if candidate.is_absolute() else cwd / candidate)
    return search_roots


def _python_module_may_be_shadowed_in_search_roots(module_root: str, search_roots: list[Path]) -> bool:
    if not search_roots:
        return True
    shadow_paths = _SAFE_PYTHON_MODULE_SHADOW_PATHS.get(module_root)
    if shadow_paths is None:
        return True
    for search_root in search_roots:
        if module_root == "pytest" and _pytest_local_entry_point_metadata_exists(search_root):
            return True
        try:
            if any((search_root / shadow_path).exists() for shadow_path in shadow_paths):
                return True
        except OSError:
            return True
    return False


def _pytest_local_entry_point_metadata_exists(cwd: Path) -> bool:
    try:
        return any(
            child.is_dir()
            and child.name.endswith((".dist-info", ".egg-info"))
            and (child / "entry_points.txt").exists()
            for child in cwd.iterdir()
        )
    except OSError:
        return True


def _pytest_config_may_add_unsafe_options(cwd: Path | None, module_args: list[str]) -> bool:
    if cwd is None:
        return True
    return _pytest_config_assessment(cwd, module_args).unsafe


def _pytest_config_assessment(cwd: Path, module_args: list[str]) -> PytestConfigAssessment:
    explicit_config_paths = _pytest_explicit_config_paths(module_args, cwd=cwd)
    if explicit_config_paths is None:
        return assess_pytest_configs(cwd, ("../invalid-pytest-config-search",))
    if explicit_config_paths:
        return assess_pytest_configs(cwd, explicit_config_paths, require_present=True)
    config_dirs = _pytest_config_search_dirs(module_args, cwd=cwd)
    if config_dirs is None:
        return assess_pytest_configs(cwd, ("../invalid-pytest-config-search",))
    candidates = tuple(
        (Path(config_dir) / config_path).as_posix()
        for config_dir in config_dirs
        for config_path in _PYTEST_OPTION_CONFIG_PATHS
    )
    return assess_selected_pytest_config(cwd, candidates)


def _pytest_explicit_config_paths(module_args: list[str], *, cwd: Path) -> tuple[str, ...] | None:
    paths: list[str] = []
    index = 0
    while index < len(module_args):
        token = module_args[index]
        path_text: str | None = None
        if token in {"-c", "--config-file"}:
            if index + 1 >= len(module_args):
                return None
            path_text = module_args[index + 1]
            index += 2
        elif token.startswith("--config-file="):
            path_text = token.split("=", 1)[1]
            index += 1
        elif token.startswith("-c="):
            path_text = token[3:]
            index += 1
        elif token.startswith("-c") and len(token) > 2:
            path_text = token[2:]
            index += 1
        else:
            index += 1
            continue
        selected_path = _pytest_selected_relative_path(path_text, cwd=cwd)
        if selected_path is None or not selected_path:
            return None
        paths.append(selected_path)
    return (paths[-1],) if paths else ()


def _pytest_config_assessment_for_command(
    command_text: str,
    *,
    cwd: Path | None,
    execution_context: ShellExecutionContext,
) -> PytestConfigAssessment:
    if cwd is None:
        return PytestConfigAssessment((), False, True, (PYTEST_CONFIG_PATH_INVALID,), None)
    assessments: list[PytestConfigAssessment] = []
    for context_segment in execution_context.segments:
        if context_segment.directory_operation is not None:
            continue
        segment = list(context_segment.tokens)
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if not _segment_targets_pytest(segment, command_name, command_index):
            continue
        segment_cwd, reason_code = validate_shell_execution_segment(execution_context, context_segment)
        if segment_cwd is None or reason_code is not None:
            assessments.append(
                PytestConfigAssessment((), False, True, (reason_code or PYTEST_CONFIG_PATH_INVALID,), None)
            )
            continue
        pytest_args = _pytest_args_from_segment(segment, command_index)
        assessments.append(
            _pytest_config_assessment(segment_cwd, pytest_args)
            if pytest_args is not None
            else PytestConfigAssessment((), False, True, (PYTEST_CONFIG_PATH_INVALID,), None)
        )
    if not assessments and _shell_command_targets_pytest(command_text):
        assessments.append(_pytest_config_assessment(cwd, []))
    return combine_pytest_config_assessments(assessments)


def _pytest_args_from_segment(segment: list[str], command_index: int) -> list[str] | None:
    command_name = _normalized_shell_command_name(segment[command_index])
    command_args = segment[command_index + 1 :]
    if command_name in _PYTEST_COMMAND_NAMES:
        return command_args
    if _is_pytest_python_interpreter_command(command_name):
        return _pytest_args_from_python(command_args)
    if command_name == "uvx" or command_name in _PYTEST_EXECUTOR_COMMANDS:
        return _pytest_args_from_argument_sequence(command_args)
    runner_subcommands = _PYTEST_COMMAND_RUNNER_SUBCOMMANDS.get(command_name)
    if runner_subcommands is not None:
        for index, token in enumerate(command_args):
            if token in runner_subcommands:
                return _pytest_args_from_runner_argument_sequence(command_name, command_args[index + 1 :])
        return None
    if command_name == "find":
        for index, token in enumerate(command_args):
            if token in _FIND_EXEC_ACTION_FLAGS:
                return _pytest_args_from_argument_sequence(command_args[index + 1 :])
        return None
    if command_name == "fd":
        for index, token in enumerate(command_args):
            if fd_arg_requests_exec(token):
                return _pytest_args_from_argument_sequence(command_args[index + 1 :])
        return None
    return None


def _pytest_args_from_python(command_args: list[str]) -> list[str] | None:
    index = 0
    while index < len(command_args):
        token = command_args[index]
        if token == "-m" and index + 1 < len(command_args):
            return command_args[index + 2 :] if command_args[index + 1].split(".", 1)[0] == "pytest" else None
        if token.startswith("-m") and len(token) > 2:
            return command_args[index + 1 :] if token[2:].split(".", 1)[0] == "pytest" else None
        if token in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        index += 1
    return None


def _pytest_config_search_dirs(module_args: list[str], *, cwd: Path) -> tuple[str, ...] | None:
    positional_args = _pytest_positional_args(module_args)
    if not positional_args:
        return ("",)
    selected_paths: list[str] = []
    for module_arg in positional_args:
        selected_path = _pytest_selected_relative_path(module_arg, cwd=cwd)
        if selected_path is None:
            return None
        if selected_path == "":
            continue
        config_root = Path(selected_path)
        if not (cwd / config_root).is_dir():
            config_root = config_root.parent
        selected_paths.append("" if str(config_root) == "." else config_root.as_posix())
    if not selected_paths:
        return ("",)
    try:
        selected_root = Path(os.path.commonpath(selected_paths))
    except ValueError:
        return None
    return _pytest_config_ancestor_dirs(selected_root)


def _pytest_selected_relative_path(module_arg: str, *, cwd: Path) -> str | None:
    path_text = module_arg.split("::", 1)[0]
    if not path_text:
        return ""
    path = Path(path_text)
    if ".." in path.parts:
        return None
    if not path.is_absolute():
        return path.as_posix()
    cwd_text = str(cwd)
    path_text = str(path)
    if path_text == cwd_text:
        return ""
    prefix = f"{cwd_text}{os.sep}"
    if not path_text.startswith(prefix):
        return None
    relative_text = path_text[len(prefix) :]
    relative_path = Path(relative_text)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        return None
    return relative_path.as_posix()


def _pytest_config_ancestor_dirs(root: Path) -> tuple[str, ...]:
    if str(root) in {"", "."}:
        return ("",)
    dirs: list[str] = []
    current = root
    while str(current) not in {"", "."}:
        dirs.append(current.as_posix())
        current = current.parent
    dirs.append("")
    return tuple(dirs)


def _pytest_positional_args(module_args: list[str]) -> tuple[str, ...]:
    positional_args: list[str] = []
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return tuple(positional_args)
        if arg in _PYTEST_SAFE_FLAGS:
            index += 1
            continue
        if arg in _PYTEST_SAFE_FLAGS_WITH_VALUES:
            index += 2
            continue
        if arg in {"-c", "--config-file"}:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _PYTEST_SAFE_FLAGS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            positional_args.append(arg)
        index += 1
    return tuple(positional_args)


def _pytest_module_args_are_safe(module_args: list[str]) -> bool:
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return False
        if arg in _PYTEST_SAFE_FLAGS:
            index += 1
            continue
        if arg in _PYTEST_SAFE_FLAGS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _PYTEST_SAFE_FLAGS_WITH_VALUES):
            index += 1
            continue
        if arg.startswith("-"):
            return False
        index += 1
    return True


def _python_module_subcommand(module_root: str, module_args: list[str]) -> str | None:
    options_with_values = _PYTHON_MODULE_OPTIONS_WITH_VALUES.get(module_root, frozenset())
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return None
        if arg in options_with_values:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_values):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return None


def _static_shell_segment_is_safe(args: list[str]) -> bool:
    return all(_static_shell_arg_is_safe(arg) for arg in args)


def _static_shell_arg_is_safe(arg: str) -> bool:
    if "`" in arg or "$(" in arg or "<(" in arg or ">(" in arg:
        return False
    return "$" not in arg.replace("$?", "")


def _contains_unmodeled_inline_interpreter_eval(
    command_text: str,
    parts: list[str],
    command_names: list[str],
) -> bool:
    heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
    if heredoc_interpreter is not None:
        return _is_unmodeled_inline_interpreter_command(heredoc_interpreter)
    if not command_names or not all(_is_script_interpreter_command(command_name) for command_name in command_names):
        return False
    if not any(_is_unmodeled_inline_interpreter_command(command_name) for command_name in command_names):
        return False
    return bool(_script_interpreter_texts(parts) or _shell_heredoc_payloads(command_text))


def _is_script_interpreter_command(command_name: str) -> bool:
    return _is_python_interpreter_command(command_name) or command_name in _UNMODELED_INLINE_INTERPRETER_COMMANDS


def _is_read_only_observer_interpreter_command(command_name: str) -> bool:
    return _is_python_interpreter_command(command_name)


def _is_unmodeled_inline_interpreter_command(command_name: str) -> bool:
    return command_name in _UNMODELED_INLINE_INTERPRETER_COMMANDS


def _is_python_interpreter_command(command_name: str) -> bool:
    normalized_name = _normalized_shell_command_name(command_name)
    return re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", normalized_name) is not None


@dataclass(frozen=True, slots=True)
class _ShellLaunchCandidate:
    tokens: tuple[str, ...]
    command_index: int
    effective_cwd: Path
    environment: dict[str, str]
    resolution_reason: str | None = None


def _python_interpreter_executable_identities(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    environment: dict[str, str] | None = None,
    workspace_root: Path | None = None,
    execution_context: ShellExecutionContext | None = None,
    depth: int = 0,
) -> tuple[dict[str, object], ...]:
    """Resolve exact Python tokens without executing candidate interpreters."""

    initial_cwd = _normalized_interpreter_cwd(cwd)
    root = _normalized_interpreter_cwd(workspace_root or cwd)
    inherited_environment = dict(os.environ if environment is None else environment)
    if depth > 8:
        return _ambiguous_python_evidence_from_tokens(
            _split_shell_parts(command_text),
            cwd=initial_cwd,
            environment=inherited_environment,
            workspace_root=root,
            home_dir=home_dir,
            reason="nested_shell_depth_exceeded",
        )

    execution_context = execution_context or model_shell_execution_context(
        command_text,
        cwd=initial_cwd,
        workspace_root=root,
    )
    evidence: list[dict[str, object]] = []
    for context_segment in execution_context.segments:
        if context_segment.directory_operation is not None:
            continue
        segment_cwd, context_reason = validate_shell_execution_segment(execution_context, context_segment)
        if segment_cwd is None or context_reason is not None:
            evidence.extend(
                _ambiguous_python_evidence_from_tokens(
                    list(context_segment.tokens),
                    cwd=initial_cwd,
                    environment=inherited_environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    reason=context_reason or "interpreter_cwd_unresolved",
                )
            )
            continue
        candidate = _shell_launch_candidate(
            list(context_segment.tokens),
            cwd=segment_cwd,
            environment=inherited_environment,
        )
        if candidate is None:
            evidence.extend(
                _ambiguous_python_evidence_from_tokens(
                    list(context_segment.tokens),
                    cwd=segment_cwd,
                    environment=inherited_environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    reason="interpreter_wrapper_unresolved",
                )
            )
            continue
        raw_token = _shell_command_token_without_attached_redirection(candidate.tokens[candidate.command_index]).strip()
        if _is_python_interpreter_command(raw_token):
            evidence.append(
                _python_interpreter_executable_identity(
                    raw_token,
                    cwd=candidate.effective_cwd,
                    environment=candidate.environment,
                    workspace_root=root,
                    home_dir=home_dir,
                    resolution_reason=candidate.resolution_reason,
                )
            )
        command_name = _normalized_shell_command_name(raw_token)
        if command_name in _SHELL_COMMAND_STRING_INTERPRETERS:
            payload = _shell_interpreter_command_payload(
                list(candidate.tokens),
                candidate.command_index,
            )
            if payload is not None:
                evidence.extend(
                    _python_interpreter_executable_identities(
                        payload.script_text,
                        cwd=candidate.effective_cwd,
                        home_dir=home_dir,
                        environment=candidate.environment,
                        workspace_root=root,
                        depth=depth + 1,
                    )
                )
    for payload in _shell_command_substitution_payloads(command_text):
        evidence.extend(
            _python_interpreter_executable_identities(
                payload,
                cwd=initial_cwd,
                home_dir=home_dir,
                environment=inherited_environment,
                workspace_root=root,
                depth=depth + 1,
            )
        )
    unique: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in evidence:
        stable_item = _without_interpreter_reuse_nonces(item)
        key = json.dumps(stable_item, sort_keys=True, separators=(",", ":"), default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return tuple(unique)


def _normalized_interpreter_cwd(cwd: Path | None) -> Path:
    candidate = cwd or Path.cwd()
    try:
        return candidate.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return candidate.expanduser().absolute()


def _shell_launch_candidate(
    tokens: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    depth: int = 0,
    resolution_reason: str | None = None,
) -> _ShellLaunchCandidate | None:
    if depth > 8:
        return None
    working = list(tokens)
    effective_environment = dict(environment)
    effective_cwd = cwd
    index = 0
    while index < len(working):
        redirected = _leading_shell_redirection_tokens_consumed(working, index)
        if redirected:
            index += redirected
            continue
        token = _shell_command_token_without_attached_redirection(working[index]).strip()
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            name, _, value = token.partition("=")
            if name.endswith("+"):
                name = name[:-1]
                value = f"{effective_environment.get(name, '')}{value}"
            effective_environment[name] = value
            index += 1
            continue
        command_name = _normalized_shell_command_name(token)
        if command_name == "env":
            parsed = parse_env_wrapper(
                working[index + 1 :],
                inherited_environment=effective_environment,
                cwd=effective_cwd,
            )
            if not parsed.complete or not parsed.executable_argv:
                return None
            parsed_environment = parsed.environment_dict()
            if parsed_environment is None or parsed.effective_cwd is None:
                return None
            path_value = parsed_environment.get("PATH")
            env_reason = resolution_reason
            if path_value is not None and ("$" in path_value or "`" in path_value):
                env_reason = "path_expression_unresolved"
            return _shell_launch_candidate(
                list(parsed.executable_argv),
                cwd=parsed.effective_cwd,
                environment=parsed_environment,
                depth=depth + 1,
                resolution_reason=env_reason,
            )
        if command_name not in _SHELL_COMMAND_WRAPPERS:
            path_value = effective_environment.get("PATH")
            final_reason = resolution_reason
            if path_value is not None and ("$" in path_value or "`" in path_value):
                final_reason = "path_expression_unresolved"
            return _ShellLaunchCandidate(
                tokens=tuple(working),
                command_index=index,
                effective_cwd=effective_cwd,
                environment=effective_environment,
                resolution_reason=final_reason,
            )
        if command_name == "sudo":
            index, effective_cwd, sudo_reason = _consume_sudo_wrapper_for_interpreter(
                working,
                index + 1,
                cwd=effective_cwd,
            )
            resolution_reason = resolution_reason or sudo_reason
            continue
        index += 1
        while index < len(working) and working[index].startswith("-"):
            wrapper_token = working[index]
            if command_name == "command" and "p" in wrapper_token.lstrip("-"):
                effective_environment["PATH"] = os.defpath
            index += _wrapper_option_tokens_consumed(command_name, wrapper_token)
    return None


def _consume_sudo_wrapper_for_interpreter(
    tokens: list[str],
    index: int,
    *,
    cwd: Path,
) -> tuple[int, Path, str | None]:
    chdir_value: str | None = None
    reason: str | None = "sudo_path_resolution_unproven"
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1, cwd, reason
        if not token.startswith("-"):
            break
        if token in {"-R", "--chroot"} or token.startswith(("-R", "--chroot=")):
            reason = "sudo_chroot_unresolved"
        if token in {"-D", "--chdir"}:
            if index + 1 >= len(tokens):
                return len(tokens), cwd, "sudo_chdir_missing"
            chdir_value = tokens[index + 1]
        elif token.startswith("--chdir="):
            chdir_value = token.split("=", 1)[1]
        elif token.startswith("-D") and token != "-D":
            chdir_value = token[2:]
        index += _wrapper_option_tokens_consumed("sudo", token)
    if chdir_value is not None:
        if not chdir_value or any(marker in chdir_value for marker in ("$", "`", "\x00")):
            return index, cwd, "sudo_chdir_unresolved"
        candidate = Path(chdir_value).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved_cwd = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return index, cwd, "sudo_chdir_unresolved"
        if not resolved_cwd.is_dir():
            return index, cwd, "sudo_chdir_unresolved"
        cwd = resolved_cwd
    return index, cwd, reason


def _ambiguous_python_evidence_from_tokens(
    tokens: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    workspace_root: Path,
    home_dir: Path | None,
    reason: str,
) -> tuple[dict[str, object], ...]:
    evidence: list[dict[str, object]] = []
    for token in tokens:
        raw_token = _shell_command_token_without_attached_redirection(token).strip()
        if not _is_python_interpreter_command(raw_token):
            continue
        evidence.append(
            _python_interpreter_executable_identity(
                raw_token,
                cwd=cwd,
                environment=environment,
                workspace_root=workspace_root,
                home_dir=home_dir,
                resolution_reason=reason,
            )
        )
    return tuple(evidence)


def _python_interpreter_executable_identity(
    raw_token: str,
    *,
    cwd: Path,
    environment: dict[str, str],
    workspace_root: Path,
    home_dir: Path | None,
    resolution_reason: str | None,
) -> dict[str, object]:
    search_path = environment.get("PATH")
    identity = build_runtime_executable_identity(raw_token, search_path=search_path, cwd=cwd)
    if resolution_reason is not None and not _interpreter_token_has_path(raw_token):
        identity = {**identity, "resolution_reason": resolution_reason, "reuse_nonce": secrets.token_hex(16)}
    trust = _python_interpreter_trust(
        raw_token,
        identity=identity,
        workspace_root=workspace_root,
        home_dir=home_dir,
        resolution_reason=resolution_reason,
    )
    return {
        "effective_cwd": str(cwd),
        "executable": identity,
        "normalized_name": _normalized_shell_command_name(raw_token),
        "raw_token": raw_token,
        "search_path_sha256": hashlib.sha256((search_path or "").encode("utf-8")).hexdigest(),
        "trust": trust,
    }


def _python_interpreter_trust(
    raw_token: str,
    *,
    identity: dict[str, object],
    workspace_root: Path,
    home_dir: Path | None,
    resolution_reason: str | None,
) -> str:
    status = str(identity.get("status") or "unknown")
    if resolution_reason is not None and not _interpreter_token_has_path(raw_token):
        return "ambiguous"
    if status in {"unresolved", "unreadable", "path_unreadable"}:
        return "missing"
    if status == "not_executable":
        return "non_executable"
    if status != "verified":
        return "ambiguous" if status in {"foreign_platform_path", "invalid_path", "path_changed"} else "unknown"
    raw_launch_path = identity.get("launch_path")
    canonical_path = identity.get("path")
    if not isinstance(raw_launch_path, str) or not isinstance(canonical_path, str):
        return "unknown"
    launch_path = Path(raw_launch_path)
    canonical = Path(canonical_path)
    try:
        guard_launch = Path(sys.executable).expanduser().absolute()
        guard_canonical = guard_launch.resolve(strict=True)
    except (OSError, RuntimeError):
        guard_launch = Path(sys.executable).expanduser().absolute()
        guard_canonical = guard_launch
    if canonical == guard_canonical and (
        launch_path in {guard_launch, guard_canonical} or launch_path.parent == guard_launch.parent
    ):
        return "trusted_guard"
    if _interpreter_path_is_within(launch_path, workspace_root):
        return "workspace_local"
    if home_dir is not None and _interpreter_path_is_within(launch_path, home_dir):
        return "user_controlled"
    if os.name == "nt":
        return "user_controlled"
    if any(
        _interpreter_path_is_within(launch_path, trusted_root) for trusted_root in _TRUSTED_INTERPRETER_INSTALL_ROOTS
    ) and _interpreter_identity_path_chain_is_stable(identity):
        return "trusted_system"
    try:
        if is_trusted_absolute_command_path(launch_path, cwd=workspace_root, home_dir=home_dir):
            return "trusted_system"
    except (OSError, RuntimeError):
        pass
    return "user_controlled"


def _interpreter_identity_path_chain_is_stable(identity: dict[str, object]) -> bool:
    path_chain = identity.get("path_chain")
    if not isinstance(path_chain, list) or not path_chain:
        return False
    for item in path_chain:
        if not isinstance(item, dict):
            return False
        mode = item.get("mode")
        if not isinstance(mode, int) or mode & 0o022:
            return False
    return True


def _interpreter_token_has_path(raw_token: str) -> bool:
    normalized = raw_token.strip()
    return (
        "/" in normalized
        or "\\" in normalized
        or bool(re.match(r"^[A-Za-z]:", normalized))
        or normalized.startswith("//")
    )


def _interpreter_path_is_within(path: Path, root: Path) -> bool:
    try:
        path.absolute().relative_to(root.absolute())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _without_interpreter_reuse_nonces(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _without_interpreter_reuse_nonces(item) for key, item in value.items() if key != "reuse_nonce"
        }
    if isinstance(value, (list, tuple)):
        return [_without_interpreter_reuse_nonces(item) for item in value]
    return value


def _is_pytest_python_interpreter_command(command_name: str) -> bool:
    return re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", command_name) is not None


def _script_is_benign_wait(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    return bool(
        re.fullmatch(r"sleep\s+\d+(?:\.\d+)?", normalized_script)
        or re.fullmatch(r"(?:import\s+time\s*;\s*)?time\.sleep\(\s*\d+(?:\.\d+)?\s*\)", normalized_script)
    )


def _script_has_aliased_risky_import(script_text: str) -> bool:
    risky_roots = {"os", "pathlib", "shutil", "subprocess"}
    try:
        parsed_script = ast.parse(script_text)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(parsed_script):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is None:
                    continue
                module_name = alias.name.split(".", 1)[0]
                if module_name in risky_roots:
                    return True
            continue
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        module_name = node.module.split(".", 1)[0]
        if module_name not in risky_roots:
            continue
        if any(alias.asname is not None for alias in node.names):
            return True
    return False


def _script_is_read_only_observer(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    if _script_is_benign_wait(normalized_script):
        return True
    if _script_has_aliased_risky_import(normalized_script):
        return False
    return not any(pattern.search(normalized_script) for pattern in _READ_ONLY_INTERPRETER_MUTATION_PATTERNS)


def _single_interpreter_heredoc_script(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    script_text = match.group("body").strip()
    return script_text or None


def _single_interpreter_heredoc_interpreter(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    interpreter = match.group("interpreter").strip()
    return interpreter or None


def _single_interpreter_heredoc_args(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    return match.group("args").strip()


@dataclass(frozen=True, slots=True)
class _InterpreterFlagPayload:
    script_text: str
    tokens_consumed: int


def _interpreter_flag_payload(parts: list[str], index: int) -> _InterpreterFlagPayload | None:
    normalized_token = parts[index].strip().lstrip("(").rstrip(")")
    if not normalized_token.startswith("-"):
        return None
    if normalized_token.startswith("--"):
        for long_flag in ("--command", "--eval", "--execute"):
            if normalized_token == long_flag:
                if index + 1 >= len(parts):
                    return None
                next_script = parts[index + 1].strip()
                if not next_script:
                    return None
                return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
            if normalized_token.startswith(f"{long_flag}="):
                attached_script = normalized_token.split("=", 1)[1].strip()
                if not attached_script:
                    return None
                return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        return None
    flag_text = normalized_token[1:]
    for flag_index, flag_name in enumerate(flag_text):
        if flag_name not in {"c", "e"}:
            continue
        attached_script = flag_text[flag_index + 1 :].strip()
        if attached_script:
            return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        if index + 1 >= len(parts):
            return None
        next_script = parts[index + 1].strip()
        if not next_script:
            return None
        return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
    return None


def _is_shell_command_flag(value: str) -> bool:
    if value == "-c":
        return True
    if not value.startswith("-"):
        return False
    flag_characters = value[1:]
    return bool(flag_characters) and set(flag_characters) <= {"c", "l"}


def _file_read_request_fingerprint(*, harness: str, tool_name: str, normalized_path: str) -> str:
    payload = {
        "harness": harness,
        "tool_name": tool_name,
        "normalized_path": normalized_path,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
