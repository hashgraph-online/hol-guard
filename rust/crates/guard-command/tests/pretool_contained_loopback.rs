//! Node source that only serves and fetches on literal loopback ports, inline
//! or a script in the workspace, runs in the workspace sandbox, which grants
//! exactly those ports. A remote host, a host other than loopback or every
//! address, an administrative port or a port chosen at run time without a
//! literal fallback keeps the review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONTAINED: &str = "native_workspace_containment_required";

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
            .join("../../target/contained-loopback-tests")
            .join(format!(
                "run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        for (relative, text) in [
            ("package.json", "{\"name\":\"game\",\"type\":\"commonjs\",\"scripts\":{\"test\":\"node --test\"}}\n"),
            ("index.html", "<!doctype html><script src=\"game.js\"></script>\n"),
            ("game.js", "module.exports = { score: (rows) => rows.length };\n"),
            ("game.test.js", "const test = require('node:test');\nconst assert = require('node:assert');\nconst { score } = require('./game.js');\ntest('score', () => assert.equal(score([1]), 1));\n"),
            ("server.js", "require('node:http').createServer((q, r) => r.end('ok')).listen(3000, '127.0.0.1');\n"),
            ("src/server.js", "const http = require('node:http');\nconst { page } = require('./page');\nconst PORT = 4173;\nhttp.createServer((q, r) => r.end(page())).listen(PORT, '127.0.0.1', () => {\n  console.log(`listening on http://127.0.0.1:${PORT}/`);\n});\n"),
            ("src/page.js", "module.exports = { page: () => '<!doctype html><title>todo</title>' };\n"),
            ("src/open.js", "const http = require('node:http');\nconst PORT = 4173;\nhttp.createServer((q, r) => r.end('ok')).listen(PORT, () => console.log(`up on ${PORT}`));\n"),
            ("src/env.js", "const http = require('node:http');\nconst PORT = process.env.PORT || 3000;\nhttp.createServer((q, r) => r.end('ok')).listen(PORT, '127.0.0.1');\n"),
            ("src/todo-server.js", "const { createServer } = require('node:http');\nfunction startServer(port = Number(process.env.PORT ?? 3000)) {\n  return createServer((q, r) => r.end(new URL(q.url, 'http://localhost').pathname)).listen(port);\n}\nstartServer().on('listening', () => console.log(`http://localhost:${process.env.PORT ?? 3000}`));\n"),
            ("src/bare-env.js", "require('node:http').createServer((q, r) => r.end('ok')).listen(process.env.PORT);\n"),
            ("src/lan.js", "require('node:http').createServer((q, r) => r.end('ok')).listen(3000, '192.168.1.5');\n"),
            ("src/remote.js", "const http = require('node:http');\nhttp.createServer((q, r) => r.end('ok')).listen(3000, '127.0.0.1');\nfetch('https://example.com/');\n"),
            ("src/keys.js", "const fs = require('node:fs');\nconst http = require('node:http');\nconst key = fs.readFileSync(process.env.HOME + '/.ssh/id_ed25519');\nhttp.createServer((q, r) => r.end(key)).listen(3000, '127.0.0.1');\n"),
        ] {
            let path = project.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        }
        let home = root.canonicalize().unwrap();
        let project = project.canonicalize().unwrap();
        Self { home, project }
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

/// The static file server an agent starts to look at the page it built.
const STATIC_SERVER: &str = "node --test && node -e \"const http=require('node:http'),fs=require('node:fs'),path=require('node:path');const types={'.html':'text/html','.js':'text/javascript','.css':'text/css'};http.createServer((q,r)=>{const p=path.join(process.cwd(),q.url==='/'?'index.html':q.url);fs.readFile(p,(e,b)=>{r.writeHead(e?404:200,{'Content-Type':types[path.extname(p)]||'application/octet-stream'});r.end(e?'not found':b)})}).listen(4173,'127.0.0.1')\"";
/// The same server checking its own pages once it listens.
const SELF_CHECK: &str = "node --test game.test.js && node -e 'const http=require(\"node:http\"),fs=require(\"node:fs\");http.createServer((q,r)=>{fs.readFile(\".\"+q.url,(e,b)=>{r.writeHead(e?404:200);r.end(b)})}).listen(8765,\"127.0.0.1\",async()=>{for(const p of [\"/index.html\",\"/game.js\"]){const res=await fetch(\"http://127.0.0.1:8765\"+p);console.log(p,res.status)}process.exit(0)})'";
/// A smoke test that starts the project's server and requests its root.
const SPAWNED_SERVER: &str = "node --input-type=module -e 'import { spawn } from \"node:child_process\"; import assert from \"node:assert/strict\"; const child = spawn(process.execPath, [\"server.js\"], { stdio: \"inherit\" }); await new Promise((resolve) => setTimeout(resolve, 500)); const response = await fetch(\"http://127.0.0.1:3000/\"); assert.equal(response.status, 200); child.kill()'";

#[test]
fn loopback_servers_and_smoke_tests_run_in_the_sandbox() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [STATIC_SERVER, SELF_CHECK, SPAWNED_SERVER] {
            let result = fixture.classify(harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    (result.minimum_action.as_str(), result.reason_code.as_str()),
                    ("sandbox-required", CONTAINED),
                    "{harness}: {command}: {}",
                    result.reason
                );
            }
        }
    }
}

#[test]
fn other_addresses_and_ports_keep_their_review() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            STATIC_SERVER.replace("4173", "2375"),
            STATIC_SERVER.replace("4173", "4781"),
            STATIC_SERVER.replace("4173", "7392"),
            SPAWNED_SERVER.replace("127.0.0.1:3000", "127.0.0.1:54321"),
            STATIC_SERVER.replace("4173", "0"),
            STATIC_SERVER.replace("4173,'127.0.0.1'", "process.env.PORT,'127.0.0.1'"),
            STATIC_SERVER.replace("'127.0.0.1'", "'127.0.0.2'"),
            SELF_CHECK.replace("http://127.0.0.1:8765", "https://example.com"),
            SPAWNED_SERVER.replace("127.0.0.1:3000", "127.0.0.1:2375"),
            SPAWNED_SERVER.replace(
                "child.kill()",
                "await fetch(\"https://example.com/\"); child.kill()",
            ),
            "node -e \"const net=require('node:net');net.connect(80,process.argv[1])\" example.com"
                .into(),
            "node -e \"fetch('http://127.0.0.2:3000/')\"".into(),
            "node -e \"require('node:http').get('http://127.0.0.1:3000/')\"".into(),
        ] {
            let result = fixture.classify(harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_eq!(
                result.minimum_action, "review",
                "{harness}: {command}: {}",
                result.reason_code
            );
            assert_ne!(result.reason_code, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn a_local_module_too_large_to_read_keeps_the_review() {
    let fixture = Fixture::new();
    let filler = format!("// {}\n", "x".repeat(300 * 1024));
    std::fs::write(
        fixture.project.join("big.js"),
        filler + "module.exports = () => fetch('https://example.com/');\n",
    )
    .unwrap();
    let command = "node -e \"require('./big.js'); fetch('http://127.0.0.1:3000/')\"";
    for harness in ["omp", "claude-code", "codex"] {
        let result = fixture.classify(harness, command);
        assert_eq!(
            result.minimum_action, "review",
            "{harness}: {}",
            result.reason_code
        );
        assert_ne!(result.reason_code, CONTAINED, "{harness}");
    }
}

#[test]
fn workspace_scripts_serving_on_loopback_run_in_the_sandbox() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "node server.js",
            "node src/server.js",
            "echo serving && node src/server.js",
            "node src/open.js",
            "node src/env.js",
            "node src/todo-server.js",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(Number(process.env.PORT)||3000)\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(4173)\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(4173,()=>console.log('up'))\"",
            "node -e \"const PORT=4173;require('node:http').createServer((q,r)=>r.end('ok')).listen(PORT)\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(4173,'0.0.0.0')\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(process.env.PORT||3000)\"",
        ] {
            let result = fixture.classify(harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    (result.minimum_action.as_str(), result.reason_code.as_str()),
                    ("sandbox-required", CONTAINED),
                    "{harness}: {command}: {}",
                    result.reason
                );
            }
        }
    }
}

/// A server is contained on its port whatever host it names; one with a
/// port the sandbox does not grant, a host other than loopback or every
/// address, or other network use keeps the review, inline or as a script.
#[test]
fn servers_on_other_ports_or_hosts_and_scripts_using_other_network_keep_their_review() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "node src/bare-env.js",
            "node src/lan.js",
            "node src/remote.js",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(Number(process.env.PORT))\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(4173,'example.com')\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(6379,'127.0.0.1')\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end('ok')).listen(80,'127.0.0.1')\"",
        ] {
            let result = fixture.classify(harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_eq!(
                result.minimum_action, "review",
                "{harness}: {command}: {}",
                result.reason_code
            );
            assert_ne!(result.reason_code, CONTAINED, "{harness}: {command}");
        }
        // A server that serves a credential store is never contained.
        let result = fixture.classify(harness, "node src/keys.js");
        assert_ne!(result.decision, "allow", "{harness}");
        assert_ne!(result.reason_code, CONTAINED, "{harness}");
    }
}

/// Inline source that reads its port from the environment earns the grant;
/// one that also reads the whole environment or another variable keeps the
/// sensitive-access review.
#[test]
fn inline_servers_reading_more_of_the_environment_keep_the_sensitive_review() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "node -e \"require('node:http').createServer((q,r)=>r.end(JSON.stringify(process.env))).listen(Number(process.env.PORT)||3000)\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end(process.env.GITHUB_TOKEN)).listen(process.env.PORT||3000)\"",
            "node -e \"require('node:http').createServer((q,r)=>r.end(process.env[q.url.slice(1)])).listen(3000)\"",
        ] {
            let result = fixture.classify(harness, command);
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("review", "native_sensitive_access_review"),
                "{harness}: {command}"
            );
        }
    }
}
