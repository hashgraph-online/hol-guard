//! Programs fed on standard input that reach past the workspace.
//!
//! The workspace sandbox withholds the network and the home directory, but a
//! contained program still sees the rest of the host: it can list and read
//! system directories, enumerate and signal other processes, read the
//! clipboard or the screen, and rewrite the checkout's own Git configuration.
//! A Python program fed on standard input that asks for one of those things
//! is not one the sandbox makes safe, so it keeps its review instead of being
//! routed into containment. The screen reads the program's own source:
//!
//! - modules that observe or control other processes, the clipboard, the
//!   screen or the input devices (`psutil`, `pyperclip`, `PIL.ImageGrab`,
//!   `pynput`, `ctypes`, ...);
//! - calls that signal another process (`os.kill`, `os.killpg`);
//! - code built at run time (`eval`, `exec`, `compile`, `__import__`,
//!   `importlib.import_module`), which the scan cannot read;
//! - a path outside the workspace written in a string, on its own or as a
//!   word of a command line: an absolute path other than the shared temporary
//!   directory and the standard streams, a parent-directory path, or a
//!   home-directory path;
//! - a quoted path into the checkout's `.git` directory.
//!
//! Starting a program (`subprocess`, `os.system`) is not itself a reason to
//! hold: the program runs in the same sandbox, and the paths it is given are
//! read here like any other string.

use std::sync::LazyLock;

use regex::Regex;

use super::system_files::lexical;
use super::{code_lines, Language};

/// An import of a module that observes or controls other processes, the
/// clipboard, the screen or the input devices.
static HOST_MODULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:import|from)\s+[\w., ]*?\b",
        r"(?:psutil|pyperclip|pynput|pyautogui|mss|ctypes|PIL|",
        r"keyboard|mouse|Xlib|Quartz|AppKit|win32api|win32gui|win32con|winreg)\b",
    ))
    .unwrap()
});

/// `from os import kill`, which makes the call below bare.
static OS_SIGNAL_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfrom\s+os\s+import\s+[\w, ()]*\b(?:kill|killpg)\b").unwrap());

/// A call that signals another process or runs code built at run time.
/// `eval(` and its siblings count only as a bare name, so a method such as
/// `pattern.compile(` or `cursor.execute(` does not.
static HOST_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:\bos\s*\.\s*(?:kill|killpg)",
        r"|(?:^|[^.\w])(?:eval|exec|__import__|compile)",
        r"|\bimport_module)\s*\(",
    ))
    .unwrap()
});

/// A path that leaves the workspace by its first character, at the start of
/// a string or after a space inside one (a word of a command line): absolute
/// (`/` then a name or a dot), a parent directory, or the home directory.
static OUTSIDE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"["'`](?:[^"'`\n]*\s)?"#,
        r#"((?:/[A-Za-z0-9_.]|\.\.(?:/|["'`\s])|~[\w.-]*(?:/|["'`]))[^"'`\s]*)"#,
    ))
    .unwrap()
});

/// A quoted path whose components include `.git`.
static GIT_DIRECTORY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](?:[^"'`\s]*/)?\.git(?:/[^"'`\s]*)?["'`]"#).unwrap());

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

fn names_outside_path(code: &str) -> bool {
    OUTSIDE_PATH.captures_iter(code).any(|captures| {
        let path = captures[1].trim_end_matches(['"', '\'', '`', ' ', '\t']);
        !path.starts_with('/') || !absolute_path_stays_local(path)
    })
}

/// Whether the Python `source` fed on standard input reaches past the
/// workspace in a way the sandbox does not take away.
pub(in crate::pretool) fn python_reaches_host(source: &str) -> bool {
    let code = code_lines(Language::Python, source);
    HOST_MODULE.is_match(&code)
        || OS_SIGNAL_IMPORT.is_match(&code)
        || HOST_CALL.is_match(&code)
        || names_outside_path(&code)
        || GIT_DIRECTORY.is_match(&code)
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
            "import os\nos.system('ls -a /app/')\n",
            "import subprocess\nsubprocess.run(['cat', '/etc/hosts'])\n",
            "import subprocess\nsubprocess.run('cat ../secret', shell=True)\n",
            "import json\nprint(eval(input()))\n",
            "x = 1; exec('print(x)')\n",
            "import importlib\nimportlib.import_module('socket')\n",
            "import glob\nprint(glob.glob('/app/*'))\n",
            "import glob\nprint(glob.glob('/bin/*'))\n",
            "import glob\nprint(glob.glob('/dev/*'))\n",
            "import os\nprint(open(os.path.join(\"/usr\", \"../etc/passwd\")).read())\n",
            "import os\nprint(open('../secret.txt').read())\n",
            "import os\nprint(os.listdir('..'))\n",
            "import os\nprint(open('~/notes').read())\n",
            "import os\nprint(os.listdir('/tmp/../etc'))\n",
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
            "import json\nprint('...')\nprint('~ approx')\n",
            "import json\nopen('/tmp/out.json', 'w').write('{}')\n",
            "import sys\nprint('x', file=open('/dev/null', 'w'))\n",
            "import json\nprint(open('.gitignore').read())\n",
            "import json\nprint(open('.github/workflows/ci.yml').read())\n",
            "import sqlite3\ncur = sqlite3.connect(':memory:').cursor()\ncur.execute('select 1')\n",
            "import json\n# os.system('id') in a comment\nprint(1)\n",
            "from mypkg.signals import handler\nprint(handler)\n",
            "import signal\nsignal.signal(signal.SIGINT, signal.SIG_DFL)\n",
            "import subprocess\nsubprocess.run(['git', 'status'])\n",
            "import os\nos.system('git status --short')\n",
            "import json\nprint('see https://example.invalid/docs for more')\n",
        ] {
            assert!(!python_reaches_host(source), "{source}");
        }
    }
}
