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
//!   directory and the standard streams, the root directory, a relative path
//!   that climbs above where it starts, or a home-directory path;
//! - a string that names a path inside a `.git` directory, wherever it is;
//! - a command line, as one string or as an argument list, with a command
//!   that signals processes (`kill`, `pkill`, `killall`) or writes Git
//!   configuration (`git config` other than a read). Every command of a
//!   string counts, past wrappers such as `env` or `sudo`.
//!
//! Strings are read as the value Python gives them, escapes decoded; one
//! whose value the scan cannot resolve keeps its review.
//!
//! Starting a program (`subprocess`, `os.system`) is not itself a reason to
//! hold: the program runs in the same sandbox, and the command line it is
//! given is read here like any other string.

use std::collections::BTreeSet;
use std::iter::Peekable;
use std::str::Chars;
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

/// A string literal with the word before its opening quote, which holds the
/// prefix (`r`, `b`, `f`, ...): triple-quoted across lines, or single-line
/// with backslash escapes, so `'it\'s'` is one literal.
static STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?s)(\w*)(?:"""(.*?)"""|'''(.*?)'''"#,
        r#"|"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')"#,
    ))
    .unwrap()
});

/// Calls that read or walk the path they are given first.
const PATH_CALLS: &[&str] = &[
    "listdir",
    "scandir",
    "walk",
    "chdir",
    "Path",
    "PurePath",
    "PosixPath",
    "glob",
    "iglob",
    "open",
    "join",
    "rmtree",
    "iterdir",
    "stat",
    "lstat",
    "exists",
    "isdir",
    "access",
];

/// The rest of an argument list for `git ... config`.
static GIT_CONFIG_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"["']git["']\s*,\s*(?:["'][^"'\n]*["']\s*,\s*)*?["']config["']"#,
        r#"((?:\s*,\s*["'][^"'\n]*["'])*)"#,
    ))
    .unwrap()
});

static QUOTED_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"'\n]*)["']"#).unwrap());

/// Commands that list, copy or enter what a root-directory operand names.
const ROOT_COMMANDS: &[&str] = &[
    "ls", "find", "du", "tree", "grep", "rg", "cat", "rm", "cp", "mv", "chmod", "chown", "tar",
    "stat", "cd", "pushd",
];
const SIGNAL_COMMANDS: &[&str] = &["kill", "pkill", "killall"];
const GIT_CONFIG_READS: &[&str] = &["--get", "--get-all", "--get-regexp", "--list", "-l"];
/// Words that run the command after them, with their own options.
const COMMAND_PREFIXES: &[&str] = &[
    "env", "sudo", "doas", "nohup", "exec", "command", "builtin", "time", "nice", "ionice",
    "timeout", "setsid", "stdbuf", "xargs", "!", "{",
];

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

/// Whether a relative path climbs above the directory it starts from once
/// its `..` components are applied, as `..`, `../x` and `pkg/../..` do.
fn climbs_out(path: &str) -> bool {
    let mut depth = 0usize;
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return true,
            },
            _ => depth += 1,
        }
    }
    false
}

/// Whether one word of a string names a path outside the workspace or inside
/// a `.git` directory, the latter even under the temporary directory. A bare
/// `~name` counts only as the whole string, so prose such as `'~ approx'`
/// does not.
fn word_reaches(word: &str, alone: bool) -> bool {
    word.split(['/', '=']).any(|part| part == ".git")
        || word.split('=').any(|path| path_reaches(path, alone))
}

fn path_reaches(path: &str, alone: bool) -> bool {
    let mut chars = path.chars();
    let first = chars.next();
    let second = chars.next();
    if first == Some('/')
        && second.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return !absolute_path_stays_local(path);
    }
    if let Some(rest) = path.strip_prefix('~') {
        let name_end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
            .unwrap_or(rest.len());
        return rest[name_end..].starts_with('/') || (alone && name_end == rest.len());
    }
    path.contains("..") && climbs_out(path)
}

/// Whether a word is an environment assignment such as `LC_ALL=C`.
fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The words of one shell command from the command name on, past
/// assignments and wrappers such as `env`, `sudo` or `timeout 5`.
fn command_words(command: &str) -> Vec<&str> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let mut wrapped = false;
    let mut start = 0;
    while let Some(word) = words.get(start) {
        let prefix = COMMAND_PREFIXES.contains(word);
        let skip = prefix
            || assignment(word)
            || (wrapped
                && (word.starts_with('-')
                    || word
                        .chars()
                        .all(|c| c.is_ascii_digit() || ".smhd".contains(c))));
        if !skip {
            break;
        }
        wrapped |= prefix;
        start += 1;
    }
    words[start..].to_vec()
}

/// Whether `git config` with these words only reads. Only the words before
/// `--` are options; a `--get` after it is a value.
fn git_config_reads<'a>(words: impl IntoIterator<Item = &'a str>) -> bool {
    words
        .into_iter()
        .take_while(|word| *word != "--")
        .any(|word| GIT_CONFIG_READS.contains(&word))
}

/// Whether one shell command signals processes, writes Git configuration or
/// lists the root directory.
fn command_reaches(command: &str) -> bool {
    let words = command_words(command);
    let Some(first) = words.first() else {
        return false;
    };
    let name = first.rsplit('/').next().unwrap_or(first);
    SIGNAL_COMMANDS.contains(&name)
        || (name == "git" && words.contains(&"config") && !git_config_reads(words.iter().copied()))
        || (ROOT_COMMANDS.contains(&name) && words[1..].contains(&"/"))
}

/// Whether one string value reaches past the workspace: through any shell
/// command in it that signals processes, writes Git configuration or lists
/// the root directory, or through any word that names an outside path.
fn literal_reaches(text: &str) -> bool {
    let alone = text.split_whitespace().count() == 1;
    text.split([';', '&', '|', '\n', '(', ')', '`', '{', '}'])
        .any(command_reaches)
        || text
            .split_whitespace()
            .any(|word| word_reaches(word, alone))
}

/// Reads up to `count` digits in `radix` and returns the character they
/// number.
fn escaped_char(chars: &mut Peekable<Chars<'_>>, count: usize, radix: u32) -> Option<char> {
    let mut digits = String::new();
    while digits.len() < count {
        let digit = chars.next_if(|c| c.is_digit(radix))?;
        digits.push(digit);
    }
    u32::from_str_radix(&digits, radix)
        .ok()
        .and_then(char::from_u32)
}

/// The value Python gives a string literal's body. `None` when an escape
/// names a character the scan does not resolve (`\N{...}`) or is malformed.
fn literal_value(body: &str, raw: bool) -> Option<String> {
    if raw || !body.contains('\\') {
        return Some(body.to_owned());
    }
    let mut value = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            value.push(c);
            continue;
        }
        let Some(escape) = chars.next() else {
            value.push('\\');
            break;
        };
        match escape {
            '\n' => {}
            '\\' | '\'' | '"' => value.push(escape),
            'n' => value.push('\n'),
            't' => value.push('\t'),
            'r' => value.push('\r'),
            'a' => value.push('\x07'),
            'b' => value.push('\x08'),
            'f' => value.push('\x0c'),
            'v' => value.push('\x0b'),
            'x' => value.push(escaped_char(&mut chars, 2, 16)?),
            'u' => value.push(escaped_char(&mut chars, 4, 16)?),
            'U' => value.push(escaped_char(&mut chars, 8, 16)?),
            '0'..='7' => {
                let mut code = escape.to_digit(8)?;
                for _ in 0..2 {
                    match chars.next_if(|c| c.is_digit(8)) {
                        Some(digit) => code = code * 8 + digit.to_digit(8)?,
                        None => break,
                    }
                }
                value.push(char::from_u32(code)?);
            }
            'N' => return None,
            other => {
                value.push('\\');
                value.push(other);
            }
        }
    }
    Some(value)
}

/// Whether the text before a literal ends in a call that reads or walks the
/// path it is given first, as in `os.listdir(`.
fn path_call_before(before: &str) -> bool {
    let Some(rest) = before.trim_end().strip_suffix('(') else {
        return false;
    };
    let rest = rest.trim_end();
    let name_start = rest
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_alphanumeric() || *c == '_')
        .last()
        .map_or(rest.len(), |(index, _)| index);
    PATH_CALLS.contains(&&rest[name_start..])
}

/// Whether the text after a literal adds another string to it, as in
/// `'/' + 'etc/passwd'`. The caller asks only for a literal that starts the
/// sum, so `'a' + '/' + 'b'` is not a root path.
fn joined_to_literal(after: &str) -> bool {
    after
        .trim_start()
        .strip_prefix('+')
        .map(|rest| rest.trim_start_matches(|c: char| c.is_whitespace() || "rbufRBUF".contains(c)))
        .is_some_and(|rest| rest.starts_with(['"', '\'']))
}

/// Whether any string literal in `code` reaches past the workspace, read as
/// the value Python gives it. A literal whose value the scan cannot resolve
/// counts, as does the root directory passed to a path call or joined to
/// another literal.
fn names_outside_path(code: &str) -> bool {
    STRING.captures_iter(code).any(|captures| {
        let Some(word) = captures.get(1) else {
            return false;
        };
        let prefix = word.len() <= 2 && word.as_str().chars().all(|c| "rbufRBUF".contains(c));
        let raw = prefix && word.as_str().contains(['r', 'R']);
        let Some(body) = captures.iter().skip(2).flatten().next() else {
            return false;
        };
        let Some(value) = literal_value(body.as_str(), raw) else {
            return true;
        };
        if value == "/" {
            let end = captures.get(0).map_or(code.len(), |whole| whole.end());
            let before = &code[..word.start()];
            return path_call_before(before)
                || (!before.trim_end().ends_with('+') && joined_to_literal(&code[end..]));
        }
        literal_reaches(&value)
    })
}

fn git_config_list_writes(code: &str) -> bool {
    GIT_CONFIG_LIST.captures_iter(code).any(|captures| {
        let words: Vec<&str> = QUOTED_WORD
            .captures_iter(&captures[1])
            .filter_map(|word| word.get(1).map(|word| word.as_str()))
            .collect();
        !git_config_reads(words)
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
            "import os\nos.system('true; pkill gdm')\n",
            "import os\nos.system('sleep 1 && kill -9 1')\n",
            "import os\nos.system('env kill 1')\n",
            "import os\nos.system('sudo -n timeout 5 killall python')\n",
            "import os\nos.system('cd / && ls')\n",
            "import os\nos.system('echo $(kill 1)')\n",
            "import os\nos.system('true; git config core.hooksPath x')\n",
            "import os\nos.system('git config -- user.email --get')\n",
            "import subprocess\nsubprocess.run(['git', 'config', '--', 'user.email', '--get'])\n",
            "print('it\\'s', open('/etc/passwd').read())\n",
            "print(open(\"\\x2fetc/passwd\").read())\n",
            "print(open('\\057etc/passwd').read())\n",
            "print(open('\\u002fetc/passwd').read())\n",
            "print(open('\\N{SOLIDUS}etc/passwd').read())\n",
            "import os\nprint(os.listdir('\\x2f'))\n",
            "print(open('/' + 'etc/passwd').read())\n",
            "import os\nprint(os.listdir(r'/'))\n",
            "print(open('/tmp/project/.git/config').read())\n",
            "import os\nprint(os.listdir('pkg/../..'))\n",
            "import os\nprint(open('a/./../../b').read())\n",
            "import os\nos.system('cat --file=../secret')\n",
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
            "import json\nprint('it\\'s fine', open('README.md').read())\n",
            "import json\nprint(r'\\d+\\.\\w', 'a\\tb\\n')\n",
            "import json\nprint(open('pkg/../README.md').read())\n",
            "import json\nprint('a' + '/' + 'b', base + '/' + name)\n",
            "import json\nprint('Usage: tool (skill list)')\n",
            "import subprocess\nsubprocess.run(['git', 'config', '--get', 'user.name', '--'])\n",
            "import os\nos.system('git status; git log -1')\n",
            "import json\nprint(open('/tmp/scratch/out.txt').read())\n",
        ] {
            assert!(!python_reaches_host(source), "{source}");
        }
    }
}
