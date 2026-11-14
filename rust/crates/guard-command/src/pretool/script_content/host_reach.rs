//! Programs fed on standard input that reach past the workspace.
//!
//! The workspace sandbox withholds the network and the home directory, but a
//! contained program still sees the rest of the host: it can list and read
//! system directories, enumerate and signal other processes, read the
//! clipboard or the screen, and rewrite the checkout's own Git configuration.
//! A Python program fed on standard input that asks for one of those things
//! is not one the sandbox makes safe, so it keeps its review instead of being
//! routed into containment. The screen reads the program's own source and
//! the local modules it imports:
//!
//! - imports of modules that observe or control other processes, the
//!   clipboard, the screen or the input devices (`psutil`, `pyperclip`,
//!   `PIL.ImageGrab`, `pynput`, `ctypes`, ...);
//! - calls that signal another process (`kill`, `killpg`, `pthread_kill`
//!   from `os` or `signal`, under any name they are imported as);
//! - code built at run time (`eval`, `exec`, `compile`, `__import__`, also
//!   through `builtins`, and `importlib.import_module`), which the scan
//!   cannot read;
//! - a string that names a path outside the workspace, on its own or as a
//!   word of a command line: an absolute path other than the shared temporary
//!   directory and the standard streams, the root directory, a
//!   parent-directory path, or a home-directory path;
//! - a string that names a path inside a `.git` directory;
//! - a command line, as one string or as an argument list, that signals
//!   processes (`kill`, `pkill`, `killall`) or writes Git configuration
//!   (`git config` other than a read).
//!
//! Starting a program (`subprocess`, `os.system`) is not itself a reason to
//! hold: the program runs in the same sandbox, and the command line it is
//! given is read here like any other string.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::system_files::lexical;
use super::{code_lines, Language};

const HOST_MODULES: &str = "psutil|pyperclip|pynput|pyautogui|mss|ctypes|PIL|keyboard|mouse|Xlib|Quartz|AppKit|win32api|win32gui|win32con|winreg";

/// An import statement of a module that observes or controls other
/// processes, the clipboard, the screen or the input devices. Only a
/// statement counts, at the start of a line or after `;` or `:`, so text that
/// merely mentions the import is not one.
static HOST_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?m)(?:^|[;:])[ \t]*(?:from[ \t]+(?:{HOST_MODULES})\b|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t]*)*(?:{HOST_MODULES})\b)"
    ))
    .unwrap()
});

/// `from os import kill` and its siblings, including the parenthesized form
/// spread over several lines, which make the call bare.
static SIGNAL_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\bfrom\s+(?:os|signal)\s+import\s+",
        r"(?:\([^)]*\b(?:kill|killpg|pthread_kill)\b[^)]*\)",
        r"|[\w, \t\\]*\b(?:kill|killpg|pthread_kill)\b)",
    ))
    .unwrap()
});

/// `from os import *`, after which a bare `kill(` is the signal call.
static SIGNAL_STAR_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfrom\s+(?:os|signal)\s+import\s+\*").unwrap());

static BARE_SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[^.\w])(?:kill|killpg|pthread_kill)\s*\(").unwrap());

/// A signal call on a receiver; the receiver is checked against `os`,
/// `signal` and the names they are imported as.
static SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\w+)\s*\.\s*(?:kill|killpg|pthread_kill)\s*\(").unwrap());

/// The body of an `import` statement, to find `import os as proc`.
static IMPORT_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[;:])[ \t]*import[ \t]+([^\n;#]+)").unwrap());

/// A call that runs code built at run time. `eval(` and its siblings count
/// as a bare name or through `builtins`, so a method such as
/// `pattern.compile(` or `cursor.execute(` does not.
static DYNAMIC_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?m)(?:(?:^|[^.\w]|\b(?:builtins|__builtins__)\s*\.\s*)",
        r"(?:eval|exec|__import__|compile)|\bimport_module)\s*\(",
    ))
    .unwrap()
});

/// A string literal: triple-quoted across lines, or single-line.
static STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?s)"""(.*?)"""|'''(.*?)'''|"([^"\n]*)"|'([^'\n]*)'"#).unwrap());

/// The root directory passed as the first argument of a call that reads or
/// walks a path. `'/'.join(...)` and `s.split('/')` are not such calls.
static ROOT_ARGUMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:listdir|scandir|walk|chdir|Path|PurePath|PosixPath|glob|iglob|open|join|",
        r#"rmtree|iterdir|stat|lstat|exists|isdir|access)\s*\(\s*[rbuRBU]?["']/["']"#,
    ))
    .unwrap()
});

/// An argument list that runs `git ... config`, with the arguments after it.
static GIT_CONFIG_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"["']git["']\s*,\s*(?:["'][^"'\n]*["']\s*,\s*)*?["']config["']"#,
        r#"((?:\s*,\s*["'][^"'\n]*["'])*)"#,
    ))
    .unwrap()
});

static QUOTED_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"'\n]*)["']"#).unwrap());

/// Commands that list or copy what a root-directory operand names.
const ROOT_COMMANDS: &[&str] = &[
    "ls", "find", "du", "tree", "grep", "rg", "cat", "rm", "cp", "mv", "chmod", "chown", "tar",
    "stat",
];
const SIGNAL_COMMANDS: &[&str] = &["kill", "pkill", "killall"];
const GIT_CONFIG_READS: &[&str] = &["--get", "--get-all", "--get-regexp", "--list", "-l"];

/// Absolute paths a contained program may name: the shared temporary
/// directory and the standard streams.
fn absolute_path_stays_local(path: &str) -> bool {
    let resolved = lexical(path);
    matches!(
        resolved.as_str(),
        "/tmp" | "/private/tmp" | "/dev/null" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr"
    ) || resolved.starts_with("/tmp/")
        || resolved.starts_with("/private/tmp/")
}

/// Whether one word of a string names a path outside the workspace or inside
/// a `.git` directory. A bare `~name` counts only as the whole string, so
/// prose such as `'~ approx'` does not.
fn word_reaches(word: &str, alone: bool) -> bool {
    let mut chars = word.chars();
    let first = chars.next();
    let second = chars.next();
    if first == Some('/')
        && second.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return !absolute_path_stays_local(word);
    }
    if word == ".." || word.starts_with("../") {
        return true;
    }
    if let Some(rest) = word.strip_prefix('~') {
        let name_end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
            .unwrap_or(rest.len());
        if rest[name_end..].starts_with('/') || (alone && name_end == rest.len()) {
            return true;
        }
    }
    word.split(['/', '=']).any(|part| part == ".git")
}

/// Whether one string literal reaches past the workspace: as a command line
/// that signals processes, writes Git configuration or lists the root
/// directory, or through any word that names an outside path.
fn literal_reaches(text: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    let Some(first) = words.first() else {
        return false;
    };
    if SIGNAL_COMMANDS.contains(first) {
        return true;
    }
    if *first == "git"
        && words.contains(&"config")
        && !words.iter().any(|word| GIT_CONFIG_READS.contains(word))
    {
        return true;
    }
    if ROOT_COMMANDS.contains(first) && words[1..].contains(&"/") {
        return true;
    }
    let alone = words.len() == 1;
    words.iter().any(|word| word_reaches(word, alone))
}

fn names_outside_path(code: &str) -> bool {
    STRING.captures_iter(code).any(|captures| {
        captures
            .iter()
            .skip(1)
            .flatten()
            .next()
            .is_some_and(|text| literal_reaches(text.as_str()))
    })
}

fn git_config_list_writes(code: &str) -> bool {
    GIT_CONFIG_LIST.captures_iter(code).any(|captures| {
        !QUOTED_WORD
            .captures_iter(&captures[1])
            .any(|word| GIT_CONFIG_READS.contains(&&word[1]))
    })
}

/// Names `os` and `signal` are reachable under: themselves and their
/// `import ... as` aliases.
fn signal_receivers(code: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::from(["os", "signal"]);
    for statement in IMPORT_STATEMENT.captures_iter(code) {
        let body = statement.get(1).map_or("", |body| body.as_str());
        for item in body.split(',') {
            let parts: Vec<&str> = item.split_whitespace().collect();
            if let [module, "as", alias] = parts.as_slice() {
                if matches!(*module, "os" | "signal") {
                    names.insert(alias);
                }
            }
        }
    }
    names
}

fn signals_processes(code: &str) -> bool {
    if SIGNAL_IMPORT.is_match(code)
        || (SIGNAL_STAR_IMPORT.is_match(code) && BARE_SIGNAL_CALL.is_match(code))
    {
        return true;
    }
    let receivers = signal_receivers(code);
    SIGNAL_CALL
        .captures_iter(code)
        .any(|call| receivers.contains(&call[1]))
}

/// Whether the Python `source` reaches past the workspace in a way the
/// sandbox does not take away.
pub(in crate::pretool) fn python_reaches_host(source: &str) -> bool {
    let code = code_lines(Language::Python, source);
    HOST_MODULE.is_match(&code)
        || signals_processes(&code)
        || DYNAMIC_CODE.is_match(&code)
        || ROOT_ARGUMENT.is_match(&code)
        || git_config_list_writes(&code)
        || names_outside_path(&code)
}

#[cfg(test)]
mod tests {
    use super::python_reaches_host;

    #[test]
    fn programs_that_reach_the_host_are_held() {
        for source in [
            "import psutil\nfor p in psutil.process_iter(): p.kill()\n",
            "import os, psutil\nprint(psutil.cpu_percent())\n",
            "from PIL import ImageGrab\nImageGrab.grab().save('s.png')\n",
            "import pyperclip\nprint(pyperclip.paste())\n",
            "import os\nos.kill(1, 9)\n",
            "from os import kill\nkill(1, 9)\n",
            "from os import (\n    kill,\n)\nkill(4242, 15)\n",
            "from os import *\nkill(1, 9)\n",
            "import os as proc\nproc.kill(4242, 15)\n",
            "import signal\nsignal.pthread_kill(1, 9)\n",
            "import os\nos.system('ls -a /app/')\n",
            "import os\nos.system('ls -a /')\n",
            "import os\nos.system('pkill gdm')\n",
            "import subprocess\nsubprocess.run(['kill', '-9', '1'])\n",
            "import os\nos.system('git config core.hooksPath /dev/null')\n",
            "import subprocess\nsubprocess.run(['git', 'config', 'core.hooksPath', '/dev/null'])\n",
            "import os\nos.system('git config --file .git/config core.hooksPath x')\n",
            "import subprocess\nsubprocess.run(['cat', '/etc/hosts'])\n",
            "import subprocess\nsubprocess.run('cat ../secret', shell=True)\n",
            "import os\nos.system('cat /etc/passwd /tmp/out')\n",
            "import subprocess\nsubprocess.run('cp /etc/passwd /tmp/copy', shell=True)\n",
            "import json\nprint(eval(input()))\n",
            "x = 1; exec('print(x)')\n",
            "import builtins\nbuiltins.exec(src)\n",
            "import importlib\nimportlib.import_module('socket')\n",
            "import glob\nprint(glob.glob('/app/*'))\n",
            "import glob\nprint(glob.glob('/dev/*'))\n",
            "import os\nprint(os.listdir('/'))\n",
            "import os\nprint(open(os.path.join('/', 'etc', 'passwd')).read())\n",
            "import os\nprint(open(os.path.join(\"/usr\", \"../etc/passwd\")).read())\n",
            "import os\nprint(open('../secret.txt').read())\n",
            "import os\nprint(os.listdir('..'))\n",
            "import os\nprint(open('~/notes').read())\n",
            "import os\nprint(os.path.expanduser('~'))\n",
            "import os\nprint(os.listdir('/tmp/../etc'))\n",
            "paths = '''\n/etc/passwd\n'''\n",
            "from pathlib import Path\nPath('.git/config').write_text('[core]\\nhooksPath=/dev/null\\n')\n",
            "from pathlib import Path\nprint((Path('.git') / 'config').read_text())\n",
            "import json\nprint(open(\"sub/.git/HEAD\").read())\n",
        ] {
            assert!(python_reaches_host(source), "{source}");
        }
    }

    #[test]
    fn workspace_programs_stay_contained() {
        for source in [
            "from collections import OrderedDict\nd = OrderedDict([('a', 1)])\nprint(list(d))\n",
            "import glob\nimport re\nprint(sorted(glob.glob('*.md')))\n",
            "import json\nimport re\nprint(json.dumps({'m': bool(re.match(r'a+', 'aaa'))}))\n",
            "import json\nprint(open('README.md').read())\n",
            "import re\npattern = re.compile(r'\\d+')\nprint(pattern.findall('a1'))\n",
            "import json\nprint('/'.join(['a', 'b']))\nprint('a/b'.split('/'))\n",
            "import json\nprint('a / b', x.rstrip('/'))\n",
            "import json\nprint('...')\nprint('~ approx')\n",
            "import json\nprint(\"import psutil\")\n",
            "import json\nopen('/tmp/out.json', 'w').write('{}')\n",
            "import sys\nprint('x', file=open('/dev/null', 'w'))\n",
            "import json\nprint(open('.gitignore').read())\n",
            "import json\nprint(open('.github/workflows/ci.yml').read())\n",
            "import sqlite3\ncur = sqlite3.connect(':memory:').cursor()\ncur.execute('select 1')\n",
            "import json\n# os.system('id') in a comment\nprint(1)\n",
            "from mypkg.signals import handler\nprint(handler)\n",
            "import signal\nsignal.signal(signal.SIGINT, signal.SIG_DFL)\n",
            "import subprocess\nsubprocess.run(['git', 'status'])\n",
            "import subprocess\nsubprocess.run(['git', 'config', '--get', 'user.name'])\n",
            "import os\nos.system('git status --short')\n",
            "import subprocess\np = subprocess.Popen(['sleep', '1'])\np.kill()\n",
            "import json\nprint('see https://example.invalid/docs for more')\n",
        ] {
            assert!(!python_reaches_host(source), "{source}");
        }
    }
}
