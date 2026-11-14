//! A Python program fed on standard input from a quoted heredoc.
//!
//! `python3 probe.py` runs in the workspace sandbox once its source needs
//! neither the network nor a credential store. Agents write the same probe
//! inline far more often, as `python3 << 'EOF'` or `python3 - << 'EOF'`, and
//! that spelling was held for review as soon as the program imported a
//! module, the project's own or the standard library's. The heredoc is now
//! held to the bar the script file meets. A program that needs the network,
//! names a credential store (itself or through a local module it imports),
//! declares its own source encoding, is fed to an
//! interpreter that also runs other code, or is chained to other commands,
//! keeps its review.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

const CONTAINED: (&str, &str) = ("sandbox-required", "native_workspace_containment_required");

fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-python-heredoc-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("pkg")).unwrap();
    std::fs::write(project.join("pkg/__init__.py"), "X = 1\n").unwrap();
    std::fs::write(project.join("pkg/remote.py"), "import requests\n").unwrap();
    std::fs::write(
        project.join("keys.py"),
        "print(open('/home/user/.aws/credentials').read())\n",
    )
    .unwrap();
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"pkg\"\n",
    )
    .unwrap();
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn outcome(root: &Path, command: &str) -> (String, String) {
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_probe_that_imports_modules_runs_in_the_workspace_sandbox() {
    let (root, _cleanup) = checkout("imports");
    for command in [
        "python3 << 'EOF'\nimport pkg\nprint(pkg.X)\nEOF",
        "python3 - << 'PYEOF'\nimport inspect\nimport pkg\n\nprint(inspect.getmembers(pkg))\nPYEOF",
        "python3 << 'EOF'\nfrom collections import OrderedDict\n\nd = OrderedDict([('a', 1)])\nd.move_to_end('a')\nprint(list(d))\nEOF",
        "python <<'EOF'\nimport json\nprint(json.dumps({}))\nEOF",
        "python3 << 'EOF'\nprint(1)\nEOF",
        "python3 << 'EOF'\nmarker = \" #\"; print(marker) # safe trailing comment\nEOF",
        // A continued ordinary string can still run inside the workspace.
        "python3 <<'EOF'\nmarker = \"a\\\nb\"; print(marker)\nEOF",
        "python3 <<'EOF'\nimport \\\n json\nprint(json.dumps({}))\nEOF",
        "python3 <<'EOF' | tee out.txt\nimport pkg\nprint(pkg.X)\nEOF",
        "python3 -I << 'EOF'\nimport glob\nimport re\nprint(sorted(glob.glob('pkg/*.py')))\nEOF",
        "python3 -I - <<'EOF'\nimport json\nprint(json.dumps([]))\nEOF",
        // `coding` past the second line is not an encoding declaration.
        "python3 <<'EOF'\nimport json\nprint(open('pyproject.toml', encoding='utf-8').read())\nEOF",
        "python3 <<'EOF'\nimport json\nimport sys\n# decoding note\nsys.stdout.reconfigure(encoding='utf-8')\nEOF",
    ] {
        let (action, reason) = outcome(&root, command);
        assert_eq!((action.as_str(), reason.as_str()), CONTAINED, "{command}");
    }
}

#[test]
fn a_probe_that_would_not_fit_the_sandbox_keeps_its_review() {
    let (root, _cleanup) = checkout("misfits");
    for command in [
        "python3 - <<'EOF'\nimport requests\nprint(requests.get('https://example.invalid'))\nEOF",
        "python3 - <<'EOF'\nimport urllib.request\nprint(urllib.request.urlopen('https://example.invalid'))\nEOF",
        "python3 <<'EOF'\nimport os\nprint(open(os.path.expanduser('~/.aws/credentials')).read())\nEOF",
        "python3 <<'EOF'\n# -*- coding: utf-7 -*-\nimport json\nEOF",
        "python3 <<'EOF'\n#!/usr/bin/env python3\n  # vim: set fileencoding=utf-7 :\nimport json\nEOF",
        "python3 -c 'import os' <<'EOF'\nimport pkg\nEOF",
        "python3 -i <<'EOF'\nimport pkg\nEOF",
        "python3 -I -c 'import os' <<'EOF'\nimport json\nEOF",
        // Chained to other commands, a program that imports keeps its review.
        "python3 <<'EOF'\nimport pkg\nEOF\ngit add -A",
        "python3 - <<'EOF'\nimport subprocess\nEOF\nls",
        "python3 <<'EOF' | tee out.txt; sh out.txt\nimport pkg\nEOF",
        "python3 <<'EOF' | tee $OUT\nimport pkg\nEOF",
        // A local module that needs what the sandbox withholds counts too.
        "python3 <<'EOF'\nfrom pkg import remote\nEOF",
        "python3 - <<'EOF'\nimport pkg.remote\nEOF",
        "python3 <<'EOF'\nimport keys\nEOF",
        "python3 <<'EOF'\nif True: import socket\nEOF",
        // A hash inside a string must not erase the executable suffix.
        "python3 <<'EOF'\nmarker = \" #\"; import socket\nEOF",
        "python3 <<'EOF'\nprint(1) #\rimport socket\nEOF",
        // A bare CR can reframe the encoding declaration as Python's second
        // physical line even when the heredoc parser split only on LF.
        "python3 <<'EOF'\n# first comment\r# coding: utf-7\n+AGk-mport socket\nEOF",
        // Source scanning and the interpreter must agree on line boundaries.
        "python3 - <<'EOF'\nimport json\rprint(json.dumps({}))\nEOF",
        // A builtins-only probe must not bypass the physical-line check.
        "python3 <<'EOF'\nprint(1)\rprint(2)\nEOF",
        "python3 <<'EOF'\nmarker = \" #\"; from urllib import request\nEOF",
        // Python joins this continued string before interpreting the semicolon.
        // The comment's unmatched quote must not hide the network import.
        "python3 <<'EOF'\nmarker = \"a\\\nb\"; import socket # \"\nEOF",
        "python3 <<'EOF'\nimport \\\n socket\nEOF",
        "python3 <<'EOF'\nimport so\\\ncket\nEOF",
        "python3 <<'EOF'\nfrom \\\n socket import create_connection\nEOF",
        "python3 <<'EOF'\nprint(1) #\\\nimport socket\nEOF",
        "python3 <<'EOF'\nmarker = \" #\"; print(open('/home/user/.aws/credentials').read())\nEOF",
    ] {
        let (action, _) = outcome(&root, command);
        assert!(
            action != "allow" && action != "sandbox-required",
            "{command}: {action}"
        );
    }
}
