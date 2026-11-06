"""Turn redacted approval-queue rows into model-free benign false-positive gate cases.

Input is a JSON array (or JSON lines) of rows with ``harness``, ``tool_name``, ``tool_input`` (or
``command``) and ``reason_code``. Output is a JSON array of gate case entries for
``tests/fixtures/benign_false_positive_gate.json``.

Two separate things are stripped before anything is written, because an approval row is a verbatim
record of the user's own machine:

* paths and repository slugs become the generic gate tokens, and
* every remaining project, feature, file and symbol name becomes a deterministic generic stand-in,

so a case built from a real queue row carries the shape the gate measures and none of the names
that produced it.

Rows are also classified. Only commands a careful reviewer would call unambiguously read-only are
emitted, because a gate case asserts ``expect: allow`` and a mis-sorted write would assert that
Guard should let it through. Everything else is dropped unless ``--keep-unclassified`` is passed,
which is for inspecting the discarded population, not for building a fixture.

Usage:

    python scripts/approval_rows_to_gate_cases.py rows.json \\
        --existing tests/fixtures/benign_false_positive_gate.json \\
        --reasons reasons.json > cases.json

Review the result before merging: this tool decides that a row *reads*, not that it was benign.
Then run the gate over the merged fixture. An approval queue holds both false positives and
approvals of the secrets boundary working as designed, and no static classifier here can tell the
two apart, so a generated case whose routing still interrupts is dropped rather than asserted as
``expect: allow``. Those rows belong in false-positive triage, not in a fixture that claims the
work is already quiet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SHELL_TOOLS = {"bash", "shell", "Bash", "exec_command"}
FAMILY = {"read": "read", "Read": "read", "glob": "glob", "Glob": "glob", "grep": "grep", "Grep": "grep"}
FAMILY |= {"write": "write", "Write": "write", "eval": "eval", "task": "task", "wait": "wait"}
FAMILY |= {"todo": "todo", "todo_write": "todo_write", "ls": "ls"}

_HOME = re.compile(r"(?:/Users|/home)/[^/\s'\"]+|C:\\Users\\[^\\\s'\"]+")
# Any non-hidden folder under home is treated as a project checkout; the path inside it is kept.
_PROJECT = re.compile(r"\$\{HOME\}/[A-Za-z][^/\s'\"]*(?=/|$|[\s'\"])")
# GitHub owner/repository pairs are replaced even when no --owner is given.
_GITHUB_REPO = re.compile(
    r"(github\.com[/:]|\brepos/|--repo[= ]|-R )[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?=\.git\b|[/\s'\"]|$)"
)
_TEMP = re.compile(r"(?:/private)?/tmp/[A-Za-z0-9._-]+")
# Job, run and check-run identifiers, and commit hashes that start with a digit.
_LONG_NUMBER = re.compile(r"(?<![\w.])\d{7,}(?![\w.])")
_DIGIT_HASH = re.compile(r"(?<![\w.])(?=[0-9a-f]*[a-f])\d[0-9a-f]{6,39}(?![\w.])")


def scrub(text: str, owners: list[str]) -> str:
    """Replace identifying path and name fragments with generic fixture values."""
    text = _HOME.sub("${HOME}", text)
    text = _PROJECT.sub("${WORKTREE}", text)
    text = _TEMP.sub("${PRIVATE_TMP}", text)
    text = _GITHUB_REPO.sub(r"\1o/r", text)
    text = _LONG_NUMBER.sub(lambda match: ("1234567890" * 5)[: len(match.group(0))], text)
    text = _DIGIT_HASH.sub(lambda match: ("c9cf0af96c" * 4)[: len(match.group(0))], text)
    for owner in owners:
        text = re.sub(re.escape(owner) + r"/[A-Za-z0-9._-]+", "o/r", text, flags=re.IGNORECASE)
        text = re.sub(re.escape(owner), "o", text, flags=re.IGNORECASE)
    return text


def scrub_value(value: Any, owners: list[str]) -> Any:
    if isinstance(value, str):
        return scrub(value, owners)
    if isinstance(value, list):
        return [scrub_value(item, owners) for item in value]
    if isinstance(value, dict):
        return {key: scrub_value(item, owners) for key, item in value.items()}
    return value


# --- read-only classification -------------------------------------------------------------------
#
# The classifier fails closed. A segment reads only when its verb is known and every option on it
# is one this table names as a read. An unknown verb, subcommand or option makes the row a non-read,
# so a spelling nobody listed can never turn a write into an ``expect: allow`` case.

# Verbs with no option that writes a file, changes the system or runs another program.
PLAIN_READS = {
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "grep",
    "egrep",
    "fgrep",
    "stat",
    "du",
    "df",
    "which",
    "type",
    "pwd",
    "echo",
    "printf",
    "cut",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "column",
    "comm",
    "tr",
    "nl",
    "shasum",
    "sha256sum",
    "uname",
    "whoami",
    "true",
    "false",
    "sleep",
    "diff",
    "jq",
}
# Verbs whose options must each match a named read option.
OPTION_READS: dict[str, re.Pattern[str]] = {
    "rg": re.compile(
        r"-[A-Za-z0-9]+|--(?:files|files-with-matches|files-without-match|count|line-number|"
        r"ignore-case|smart-case|fixed-strings|word-regexp|hidden|no-ignore|no-heading|heading|"
        r"with-filename|no-filename|follow|json|invert-match|only-matching|multiline|"
        r"(?:glob|iglob|type|type-not|max-count|max-depth|context|before-context|after-context|"
        r"regexp|sort|sortr)(?:=.*)?)"
    ),
    "sort": re.compile(
        r"-[bdfghinMrRsuV]+|-[kt].*|--(?:numeric-sort|reverse|unique|ignore-case|"
        r"human-numeric-sort|version-sort|(?:key|field-separator)=.*)"
    ),
    "uniq": re.compile(r"-[cdiu]+|--(?:count|repeated|ignore-case|unique)"),
}
# ``uniq IN OUT`` writes OUT, so it may name one input at most.
MAX_OPERANDS = {"uniq": 1, "cd": 1}

FIND_FLAGS = {"-L", "-H", "-P", "-E", "-x", "-s"}
FIND_TESTS = {
    "-print",
    "-print0",
    "-prune",
    "-not",
    "-o",
    "-a",
    "-or",
    "-and",
    "!",
    "(",
    ")",
    "-empty",
    "-follow",
    "-depth",
    "-xdev",
    "-ls",
    "-true",
    "-false",
    "-nouser",
    "-nogroup",
    "-readable",
}
FIND_TESTS_WITH_ARGUMENT = {
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-type",
    "-maxdepth",
    "-mindepth",
    "-newer",
    "-newermt",
    "-newerct",
    "-newerat",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-size",
    "-perm",
    "-user",
    "-group",
    "-regex",
    "-iregex",
    "-links",
    "-lname",
    "-ilname",
    "-uid",
    "-gid",
}

GIT_GLOBAL_WITH_ARGUMENT = {"-C"}
GIT_GLOBAL = re.compile(r"--no-pager|--git-dir=.+|--work-tree=.+|--no-optional-locks|-P")
_LOG_OPTIONS = (
    r"-\d+|-n\d*|-p|--oneline|--all|--stat|--shortstat|--numstat|--name-only|--name-status|"
    r"--graph|--decorate|--no-decorate|--follow|--reverse|--no-merges|--merges|--first-parent|"
    r"--abbrev-commit|--no-color|--date=\S+|--(?:format|pretty|since|until|after|before|author|"
    r"grep|max-count|skip|abbrev)=.+|--"
)
# Per subcommand: the options that read, and how many operands it may take (None for any).
GIT_READS: dict[str, tuple[re.Pattern[str], int | None]] = {
    "status": (
        re.compile(
            r"-[sbu]+|--short|--branch|--porcelain(?:=v[12])?|--ignored|"
            r"--untracked-files(?:=\w+)?|--long|-v|--"
        ),
        None,
    ),
    "log": (re.compile(_LOG_OPTIONS), None),
    "show": (re.compile(_LOG_OPTIONS), None),
    "diff": (
        re.compile(
            r"--stat|--cached|--staged|--check|--name-only|--name-status|--numstat|"
            r"--shortstat|--no-color|-U\d+|--unified=\d+|--"
        ),
        None,
    ),
    "rev-parse": (
        re.compile(
            r"--(?:short(?:=\d+)?|abbrev-ref|show-toplevel|git-dir|"
            r"git-common-dir|is-inside-work-tree|verify|quiet|absolute-git-dir|"
            r"symbolic-full-name)|-q"
        ),
        None,
    ),
    "rev-list": (re.compile(r"--count|--all|--max-count=\d+|-n\d*|--left-right|--"), None),
    "merge-base": (re.compile(r"--is-ancestor|--all|--fork-point|--octopus"), None),
    "describe": (re.compile(r"--tags|--always|--long|--exact-match|--abbrev=\d+"), None),
    "cat-file": (re.compile(r"-[pets]"), 2),
    "ls-files": (
        re.compile(
            r"-[cdmoisz]+|--(?:cached|deleted|modified|others|stage|"
            r"exclude-standard|error-unmatch|full-name)|--"
        ),
        None,
    ),
    "ls-tree": (re.compile(r"-[rdtlz]+|--(?:name-only|full-tree|full-name|long)"), None),
    "shortlog": (re.compile(r"-[sne]+|--(?:summary|numbered|email|all)"), None),
    "for-each-ref": (re.compile(r"--(?:format|sort|count|contains|merged|points-at)=.+"), None),
    "symbolic-ref": (re.compile(r"--short|-q|--quiet"), 1),
    "count-objects": (re.compile(r"-[vH]+"), 0),
    "grep": (
        re.compile(
            r"-[lLnicewEFIhHvz]+|--(?:cached|untracked|no-index|count|"
            r"files-with-matches|line-number|ignore-case|word-regexp)|-e|--"
        ),
        None,
    ),
    "branch": (
        re.compile(
            r"-[arv]+|-vv|--(?:list|show-current|all|remotes|verbose)|"
            r"--(?:merged|no-merged|contains|format|sort)(?:=.+)?"
        ),
        0,
    ),
    "config": (
        re.compile(
            r"--(?:get|get-all|list|show-origin|show-scope|null|global|local|"
            r"system)|-l|-z"
        ),
        1,
    ),
    "blame": (re.compile(r"-L\S*|-[wsle]+|--porcelain|--line-porcelain"), None),
}
# Subcommands that read only in one listed form: ``git stash`` alone pushes a stash.
GIT_READ_FORMS: dict[str, dict[str, re.Pattern[str]]] = {
    "stash": {"list": re.compile(r"--oneline|-\d+"), "show": re.compile(r"--stat|-p|--name-only")},
    "worktree": {"list": re.compile(r"--porcelain|-v|--verbose")},
    "remote": {"": re.compile(r"-v|--verbose"), "get-url": re.compile(r"--all")},
    "tag": {"": re.compile(r"-l|--list|-n\d*|--(?:sort|contains|merged|points-at)=.+")},
    "reflog": {"": re.compile(_LOG_OPTIONS), "show": re.compile(_LOG_OPTIONS)},
}

GH_READS = {
    "pr": {"view", "list", "diff", "checks", "status"},
    "issue": {"view", "list", "status"},
    "run": {"view", "list"},
    "release": {"view", "list"},
    "workflow": {"view", "list"},
    "repo": {"view", "list"},
    "label": {"list"},
    "auth": {"status"},
}
GH_OPTIONS = re.compile(
    r"--(?:json|jq|repo|limit|state|author|label|branch|head|base|search|template|job|attempt|"
    r"comments|log|log-failed|name-only|patch|required|exit-status|verbose)(?:=.+)?|-[qRLsbtc]"
)
GH_API_OPTIONS = re.compile(r"--paginate|--slurp|--jq(?:=.+)?|-q|-i|--include")

REDIRECT_WRITE = re.compile(r">|<<")
HARMLESS_REDIRECT = re.compile(r"(?<!\S)(?:\d?>&\d|&?\d?>\s*/dev/null)(?![^\s;&|])")
SECRET = re.compile(
    r"\b(secret|password|passwd|token|credential|apikey|api_key|private[-_]key|id_rsa|keychain)\b"
    r"|\.env\b|/\.ssh|/\.aws|/\.gnupg",
    re.IGNORECASE,
)
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SUBSHELL = re.compile(r"\$\(|`|<\(")
MAX_SEGMENTS = 6


def segments(command: str) -> list[str]:
    return [part.strip() for part in re.split(r"&&|\|\||;|\||&|\n", command) if part.strip()]


def _options_read(words: list[str], allowed: re.Pattern[str], max_operands: int | None) -> bool:
    operands = 0
    for word in words:
        if word.startswith("-") and word != "-":
            if not allowed.fullmatch(word):
                return False
        else:
            operands += 1
    return max_operands is None or operands <= max_operands


def _find_reads(words: list[str]) -> bool:
    rest = words[1:]
    while rest and rest[0] in FIND_FLAGS:
        rest = rest[1:]
    index = 0
    while index < len(rest):
        word = rest[index]
        if word in FIND_TESTS_WITH_ARGUMENT:
            index += 2
            continue
        if (word.startswith("-") or word in {"!", "(", ")"}) and word not in FIND_TESTS:
            return False
        index += 1
    return True


def _git_reads(words: list[str]) -> bool:
    rest = words[1:]
    while rest and rest[0].startswith("-"):
        if rest[0] in GIT_GLOBAL_WITH_ARGUMENT and len(rest) > 1:
            rest = rest[2:]
        elif GIT_GLOBAL.fullmatch(rest[0]):
            rest = rest[1:]
        else:
            return False
    if not rest:
        return False
    subcommand, after = rest[0], rest[1:]
    if subcommand in GIT_READS:
        allowed, max_operands = GIT_READS[subcommand]
        return _options_read(after, allowed, max_operands)
    forms = GIT_READ_FORMS.get(subcommand)
    if forms is None:
        return False
    operands = [word for word in after if not word.startswith("-")]
    # The form is the word right after the subcommand. A later operand spelled like
    # one is a path or a name: ``git stash -- list`` stashes a file called ``list``.
    form = after[0] if after and after[0] in forms else ""
    if form not in forms:
        return False
    if form:
        after = after[1:]
    elif operands and not (subcommand == "tag" and {"-l", "--list"} & set(after)):
        # ``git tag NAME`` creates a tag; any other operand is not a listed read form.
        return False
    return _options_read(after, forms[form], None)


def _gh_reads(words: list[str]) -> bool:
    if len(words) < 3:
        return False
    group, action, after = words[1], words[2], words[3:]
    if group == "api":
        endpoint = [word for word in words[2:] if not word.startswith("-")]
        # Only the ``--jq``/``-q`` filter takes a value; any other operand is a second endpoint.
        operands = 0
        skip = False
        for word in words[2:]:
            if skip:
                skip = False
                continue
            if word.startswith("-"):
                if not GH_API_OPTIONS.fullmatch(word):
                    return False
                skip = word in {"-q", "--jq"}
            else:
                operands += 1
        return operands == 1 and not endpoint[0].lstrip("/").startswith("graphql")
    if action not in GH_READS.get(group, set()):
        return False
    return _options_read(after, GH_OPTIONS, None)


def reads(segment: str) -> bool:
    try:
        words = shlex.split(segment)
    except ValueError:
        return False
    if not words:
        return False
    verb = words[0]
    if verb == "cd":
        return len(words) <= 2 and not any(word.startswith("-") for word in words[1:])
    if verb in PLAIN_READS:
        return True
    if verb in OPTION_READS:
        return _options_read(words[1:], OPTION_READS[verb], MAX_OPERANDS.get(verb))
    if verb == "find":
        return _find_reads(words)
    if verb == "git":
        return _git_reads(words)
    if verb == "gh":
        return _gh_reads(words)
    return False


def reads_only(command: str) -> bool:
    """Whether every segment of ``command`` is a proven read."""
    if SECRET.search(command) or EMAIL.search(command) or SUBSHELL.search(command):
        return False
    cleaned = HARMLESS_REDIRECT.sub(" ", command)
    if REDIRECT_WRITE.search(cleaned):
        return False
    parts = segments(cleaned)
    if not parts or len(parts) > MAX_SEGMENTS:
        return False
    return all(reads(part) for part in parts)


# --- name scrubbing -----------------------------------------------------------------------------

# A private name can be two characters long -- `proj/ab`. A two-letter word is
# matched as a path component only, because a bare one is far more often a verb
# or part of a short flag bundle (`cd`, `-la`, `-rn`) than a name worth
# scrubbing, and renaming those would both corrupt the command the gate
# measures and drop most rows through `option_names`.
WORD = re.compile(r"[A-Za-z][\w.+-]{2,}|(?<=/)[A-Za-z][\w.+-]")
GENERIC = {
    # shell and tool verbs
    "git",
    "grep",
    "cat",
    "head",
    "tail",
    "find",
    "echo",
    "ls",
    "which",
    "file",
    "diff",
    "sort",
    "uniq",
    "wc",
    "awk",
    "jq",
    "env",
    "printf",
    "stat",
    "node",
    "bun",
    "tsx",
    "npm",
    "npx",
    "uv",
    "python",
    "python3",
    "pytest",
    "gh",
    "rg",
    "sed",
    "cut",
    "tr",
    "basename",
    "dirname",
    "realpath",
    "du",
    "df",
    "date",
    "xargs",
    "comm",
    "nl",
    "readlink",
    "true",
    "false",
    "sleep",
    "docker",
    # common flags and subcommands spelled as words
    "status",
    "log",
    "show",
    "branch",
    "config",
    "remote",
    "worktree",
    "stash",
    "rev-parse",
    "rev-list",
    "merge-base",
    "is-ancestor",
    "ls-tree",
    "ls-files",
    "show-current",
    "show-origin",
    "for-each-ref",
    "symbolic-ref",
    "describe",
    "blame",
    "reflog",
    "shortlog",
    "cat-file",
    "count-objects",
    "api",
    "repos",
    "runs",
    "jobs",
    "actions",
    "check-runs",
    "annotations",
    "paginate",
    "list",
    "get",
    "check",
    "install",
    "global",
    "source",
    "type",
    "tags",
    "ref",
    "oneline",
    "porcelain",
    "short",
    "cached",
    "name-only",
    "iname",
    "maxdepth",
    "include",
    "exclude",
    "glob",
    "files-with-matches",
    "rln",
    "newermt",
    "git-dir",
    "work-tree",
    "no-pager",
    "null",
    "dev",
    "not",
    "path",
    "name",
    "all",
    "main",
    "HEAD",
    "FETCH_HEAD",
    "json",
    "yaml",
    "html",
    "jsx",
    "mjs",
    "enum",
    "def",
    "export",
    "function",
    "sub",
    "the",
    "opt",
    "bin",
    "var",
    "tmp",
    "org",
    "files",
    "tools",
    "system",
    "setting",
    "settings",
    "content",
    "object.sha",
    "owner",
    "user.name",
    "user.email",
    "gpg.format",
    "attr",
    "versions",
    "work",
    "home",
    "page",
    "test",
    "tests",
    "tests__",
    "src",
    "lib",
    "app",
    "apps",
    "e2e",
    "scripts",
    "docs",
    "plans",
    "references",
    "skills",
    "logs",
    "coverage",
    "out",
    "dist",
    "build",
    "target",
    "node_modules",
    "public",
    "assets",
    "crates",
    "packages",
    "components",
    "pages",
    "fixtures",
    "contracts",
    "workers",
    "worktrees",
    "harness",
    "catalog",
    "protection",
    "billing",
    "points",
    # fixture substitution tokens
    "HOME",
    "WORKTREE",
    "PRIVATE_TMP",
    "ORG",
    "ORG_WT",
    "PARENT",
    "SCRATCH",
    "GAUNTLET_ROOT",
    "TMP_ORG",
    "TMP_ORG_WT",
    "TMP_REMOTE",
    # generic filenames the gate already uses
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "README.md",
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "uv.lock",
    "Makefile",
    "index.ts",
    "index.js",
    "main.py",
    "conftest.py",
    "settings.json",
    "config.toml",
    "zshrc",
    "gitconfig",
    "vitest",
    "VITEST",
    "postgresql",
    # public tool and vendor names
    "codex",
    "claude",
    "guard",
    "hol-guard",
    "homebrew",
    "nvm",
    "doctl",
    "github",
    "hashgraph-online",
    "stripe",
    "ga4",
    "posthog",
}
PROJECTS = ("service-api", "app-portal", "web-client", "report-lane", "other-project", "acme-plain")
FEATURES = ("report-lane", "order-intake", "usage-rollup", "signup-funnel", "audit-trail")
EXTENSIONS = {
    "sh": "run-checks.sh",
    "py": "collect.py",
    "ts": "index.ts",
    "tsx": "panel.tsx",
    "md": "notes.md",
    "json": "report.json",
    "toml": "config.toml",
    "lock": "deploy.lock",
    "d": "deploy.lock.d",
    "git": "other-project.git",
    "sql": "schema.sql",
}


def pick(options: tuple[str, ...], word: str) -> str:
    return options[hashlib.sha256(word.encode("utf-8")).digest()[0] % len(options)]


def rename(word: str) -> str:
    """A generic stand-in of the same shape as ``word``."""
    stem, _, extension = word.rpartition(".")
    if stem and extension in EXTENSIONS:
        return EXTENSIONS[extension]
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", word):
        return "resolveWorkspaceRecord"
    if re.fullmatch(r"[A-Z][a-z0-9]*(?:[A-Z][a-z0-9]*)+", word):
        return "WorkspaceRecord"
    if "_" in word and word.isupper():
        return "WORKSPACE_RECORD"
    if "_" in word:
        return "read_workspace_record"
    if re.fullmatch(r"[0-9a-f]{7,40}", word):
        return "c9cf0af96c"[: len(word)]
    if re.fullmatch(r"v[\d.]+", word):
        return word
    return pick(FEATURES if "-" in word else PROJECTS, word)


def rename_names(text: str, table: dict[str, str]) -> str:
    """Substitute whole identifier words only.

    A token that starts with ``-`` is an option or a short-flag bundle and is never touched, so
    operators, flags, quoting and redirections survive byte for byte and the command keeps the
    exact shape the gate measures.
    """

    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if word in GENERIC:
            return word
        return table.setdefault(word, rename(word))

    return "".join(token if token.startswith("-") else WORD.sub(replace, token) for token in re.split(r"(\s+)", text))


def option_names(text: str) -> bool:
    """Whether an option token carries a name that renaming would have replaced.

    ``rename_names`` leaves every ``-`` token byte for byte, so a name glued into one
    reaches the public fixture as written, with or without an ``=``: ``rg -eacmeinternal``,
    ``git blame -L:chargeAcmeCustomer`` and ``--author=acme`` all keep their name. The whole
    token is read, so any word in it that renaming would have replaced drops the row.
    """
    return any(word not in GENERIC for token in text.split() if token.startswith("-") for word in WORD.findall(token))


def rename_value(value: Any, table: dict[str, str]) -> Any:
    if isinstance(value, str):
        return rename_names(value, table)
    if isinstance(value, list):
        return [rename_value(item, table) for item in value]
    if isinstance(value, dict):
        return {key: rename_value(item, table) for key, item in value.items()}
    return value


# --- case construction --------------------------------------------------------------------------


def load_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [row for row in data if isinstance(row, dict)]


def existing_commands(path: Path) -> set[tuple[str, str]]:
    """(harness, command) pairs the gate already covers, so a mined row does not duplicate one.

    The gate replays each harness separately, so a command covered for one harness is still
    uncovered for every other.
    """
    fixture = json.loads(path.read_text(encoding="utf-8"))
    found: set[tuple[str, str]] = set()
    for case in fixture.get("cases", []):
        command = case.get("tool_input", {}).get("command")
        if isinstance(command, str):
            for harness in case.get("harnesses", []):
                found.add((harness, command.strip()))
    return found


MINED_ID = re.compile(r"observed-(?P<verb>.+)-(?P<number>\d+)")


def existing_identities(path: Path) -> Counter[str]:
    """The highest ``observed-<verb>-<n>`` the gate already holds, per verb.

    A fresh run numbers from zero, so without this the next batch emits
    ``observed-grep-01`` again and collides with the ids already committed and
    with the ``id@harness`` keys that name them elsewhere.
    """
    fixture = json.loads(path.read_text(encoding="utf-8"))
    highest: Counter[str] = Counter()
    for case in fixture.get("cases", []):
        match = MINED_ID.fullmatch(str(case.get("id", "")))
        if match is None:
            continue
        verb = match.group("verb")
        highest[verb] = max(highest[verb], int(match.group("number")))
    return highest


def payload_of(row: dict[str, Any], owners: list[str]) -> tuple[str, dict[str, Any]] | None:
    tool = str(row.get("tool_name") or row.get("tool") or "")
    tool_input = row.get("tool_input")
    if tool in SHELL_TOOLS:
        command = row.get("command") or (tool_input.get("command") if isinstance(tool_input, dict) else None)
        if not isinstance(command, str) or not command:
            return None
        return "shell", {"command": command}
    if tool in FAMILY and isinstance(tool_input, dict):
        payload = dict(tool_input)
        if "file_path" in payload and "path" not in payload:
            payload["path"] = payload.pop("file_path")
        return FAMILY[tool], payload
    return None


def verb_of(command: str) -> str:
    """The command's own name, skipping any ``cd <dir>`` segment that precedes it."""
    for part in segments(command):
        words = part.split()
        if words and words[0] != "cd" and re.fullmatch(r"[A-Za-z][\w-]*", words[0]):
            return words[0].lower()
    return "shell"


def to_case(
    row: dict[str, Any],
    owners: list[str],
    table: dict[str, str] | None = None,
    keep_unclassified: bool = False,
) -> dict[str, Any] | None:
    """A gate case for ``row`` without its id, or None when the row is not a proven read.

    Classification runs on the scrubbed command before renaming, because a stand-in name could
    hide the subcommand that writes. The observed reason code is carried as
    ``observed_reason_code`` for the reasons sidecar and is not written into the fixture.
    """
    found = payload_of(row, owners)
    if found is None:
        return None
    kind, payload = found
    payload = scrub_value(payload, owners)
    command = payload.get("command", "")
    if kind == "shell" and not keep_unclassified and (not reads_only(command) or option_names(command)):
        return None
    verb = verb_of(command) if kind == "shell" else kind
    harness = str(row.get("harness") or (row.get("harnesses") or ["omp"])[0])
    case: dict[str, Any] = {
        "verb": verb,
        "fix_area": "git" if verb == "git" else kind,
        "harnesses": [harness],
        "tool": kind,
        "tool_input": rename_value(payload, {} if table is None else table),
        "cwd": "worktree",
        "expect": "allow",
    }
    reason = row.get("reason_code") or row.get("observed_reason_code")
    if reason:
        case["observed_reason_code"] = scrub(str(reason), owners)
    return case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("rows", type=Path)
    parser.add_argument("--owner", action="append", default=[], help="private owner name to replace with o")
    parser.add_argument("--existing", type=Path, help="gate fixture whose commands are already covered")
    parser.add_argument("--reasons", type=Path, help="write {case id: observed reason code} here")
    parser.add_argument(
        "--keep-unclassified",
        action="store_true",
        help="emit rows that are not unambiguously read-only (for inspection, not for a fixture)",
    )
    args = parser.parse_args()

    covered = existing_commands(args.existing) if args.existing else set()
    table: dict[str, str] = {}
    # New ids continue after the ones the fixture already holds.
    counts: Counter[str] = existing_identities(args.existing) if args.existing else Counter()
    cases: list[dict[str, Any]] = []
    reasons: dict[str, str] = {}
    seen: set[str] = set()
    for row in load_rows(args.rows):
        case = to_case(row, args.owner, table, args.keep_unclassified)
        if case is None:
            continue
        # Deduplicate on the final, renamed payload: two originals that rename alike are one case.
        harness = case["harnesses"][0]
        signature = json.dumps([harness, case["tool"], case["tool_input"]], sort_keys=True)
        command = case["tool_input"].get("command", "")
        if signature in seen or (harness, command.strip()) in covered:
            continue
        seen.add(signature)
        verb = case.pop("verb")
        reason = case.pop("observed_reason_code", None)
        counts[verb] += 1
        identity = f"observed-{verb}-{counts[verb]:02d}"
        cases.append({"id": identity, **case})
        if reason:
            reasons[identity] = reason

    json.dump(cases, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    if args.reasons:
        args.reasons.write_text(json.dumps(reasons, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"cases={len(cases)} renamed_words={len(table)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
