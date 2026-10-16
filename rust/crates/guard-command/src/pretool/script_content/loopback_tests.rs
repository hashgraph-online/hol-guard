use std::collections::BTreeSet;

use super::super::{code_lines, Language};
use super::node_loopback_ports;

/// A static file server an agent starts to look at the page it built.
const STATIC_SERVER: &str = "const http=require('node:http'),fs=require('node:fs'),path=require('node:path');const types={'.html':'text/html','.js':'text/javascript','.css':'text/css'};http.createServer((q,r)=>{const p=path.join(process.cwd(),q.url==='/'?'index.html':q.url);fs.readFile(p,(e,b)=>{r.writeHead(e?404:200,{'Content-Type':types[path.extname(p)]||'application/octet-stream'});r.end(e?'not found':b)})}).listen(4173,'127.0.0.1')";
/// The same server checking its own pages once it listens.
const SELF_CHECK: &str = "const http=require(\"node:http\"),fs=require(\"node:fs\");http.createServer((q,r)=>{fs.readFile(\".\"+q.url,(e,b)=>{r.writeHead(e?404:200);r.end(b)})}).listen(8765,\"127.0.0.1\",async()=>{for(const p of [\"/index.html\",\"/game.js\"]){const res=await fetch(\"http://127.0.0.1:8765\"+p);console.log(p,res.status)}process.exit(0)})";
/// A smoke test that starts the project's server and requests its root.
const SPAWNED_SERVER: &str = "import { spawn } from \"node:child_process\"; import assert from \"node:assert/strict\"; const child = spawn(process.execPath, [\"server.js\"], { stdio: \"inherit\" }); await new Promise((resolve) => setTimeout(resolve, 500)); const response = await fetch(\"http://127.0.0.1:3000/\"); assert.equal(response.status, 200); child.kill()";

/// These judge with no home, so Guard's whole default daemon range stays
/// closed.
fn ports(source: &str) -> Option<BTreeSet<u16>> {
    node_loopback_ports(&code_lines(Language::Node, source), None)
}

fn program_ports(sources: &[String]) -> Option<BTreeSet<u16>> {
    super::program_ports(sources, None)
}

fn inline_loopback_ports(command: &[String]) -> Vec<u16> {
    super::inline_loopback_ports(command, None)
}

fn set(ports: &[u16]) -> Option<BTreeSet<u16>> {
    Some(ports.iter().copied().collect())
}

#[test]
fn loopback_servers_and_fetches_name_their_ports() {
    assert_eq!(ports(STATIC_SERVER), set(&[4173]));
    assert_eq!(ports(SELF_CHECK), set(&[8765]));
    assert_eq!(ports(SPAWNED_SERVER), set(&[3000]));
    assert_eq!(
        ports("const response = await fetch('http://localhost:3001/');\nconsole.log(response.status);\n"),
        set(&[3001])
    );
    assert_eq!(
        ports("import { createServer } from 'node:http';\ncreateServer((q, r) => r.end('ok')).listen(3001, 'localhost');\n"),
        set(&[3001])
    );
}

#[test]
fn other_network_use_keeps_the_review() {
    for source in [
        // Administrative loopback ports.
        "await fetch('http://127.0.0.1:2375/containers/json')",
        "await fetch('http://localhost:4781/approve')",
        "require('node:http').createServer().listen(9229, '127.0.0.1')",
        // Local data stores and brokers: the grant is raw TCP for the whole
        // contained tree, so a spawned child could speak their own protocol.
        "await fetch('http://127.0.0.1:5432/')",
        "await fetch('http://localhost:3306/')",
        "await fetch('http://127.0.0.1:27018/')",
        "await fetch('http://127.0.0.1:9092/')",
        // Every port a kube control-plane component binds, not only the three
        // this list used to name.
        "await fetch('http://127.0.0.1:10252/healthz')",
        // Code evaluated at run time, which this scan cannot follow.
        "await fetch('http://127.0.0.1:3000/'); eval(\"require('node:net').connect(3000, '127.0.0.1')\")",
        "await fetch('http://127.0.0.1:3000/'); (0, eval)('1')",
        "await fetch('http://127.0.0.1:3000/'); eval?.('1')",
        "const F = Function; F('return 1')(); await fetch('http://127.0.0.1:3000/')",
        "[].constructor.constructor('return 1')(); await fetch('http://127.0.0.1:3000/')",
        "await fetch('http://127.0.0.1:3000/'); new Function('return 1')()",
        "const name = 'node:net'; require(name); await fetch('http://127.0.0.1:3000/')",
        "require('node:vm'); await fetch('http://127.0.0.1:3000/')",
        "const s = \"require('node:net')\"; await fetch('http://127.0.0.1:3000/')",
        // Guard's daemon on a fixed or ephemeral port, and ports no dev
        // server conventionally binds.
        "await fetch('http://127.0.0.1:7392/v1/requests?status=pending')",
        "await fetch('http://127.0.0.1:54321/v1/requests')",
        "require('node:http').createServer().listen(9000, '127.0.0.1')",
        // Registered service ports as a class.
        "await fetch('http://127.0.0.1:631/')",
        "await fetch('http://localhost:22/')",
        // Hosts other than loopback.
        "await fetch('https://example.com/')",
        "await fetch('http://example.com:80/')",
        "await fetch('http://127.0.0.2:8080/')",
        "await fetch('http://localhost.example.com:8080/')",
        "await fetch('http://127.0.0.1:3000/'); await fetch('https://example.com/')",
        "const http = require('http');\nhttp.createServer().listen(3000, '127.0.0.1');\nawait fetch('http://example.com/');\n",
        // Dynamic ports and hosts.
        "const http = require('http');\nhttp.createServer().listen(0, '127.0.0.1');\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT, '127.0.0.1');\n",
        "const http = require('http');\nhttp.createServer().listen(3000);\n",
        "const http = require('http');\nhttp.createServer().listen(3000, '0.0.0.0');\n",
        "const host = process.argv[2];\nawait fetch('http://' + host + ':3000/');\n",
        "const url = process.env.URL;\nawait fetch(url);\n",
        "await fetch(`http://127.0.0.1:${process.env.PORT}/`)",
        // Other network modules and HTTP clients.
        "const net = require('net');\nconst host = process.argv[2];\nnet.connect(80, host);\n",
        "import https from 'node:https';\nhttps.get('https://127.0.0.1:3000/');\n",
        "const http = require('http');\nhttp.get('http://127.0.0.1:3000/');\n",
        "const http = require('http');\nconst client = http;\nclient.get('http://127.0.0.1:3000/');\n",
        "const { request } = require('node:http');\nrequest('http://127.0.0.1:3000/').end();\n",
        "new WebSocket('ws://127.0.0.1:3000/')",
        // An import the binding forms do not name.
        "console.log(require('http').STATUS_CODES[200])",
        // A credential store alongside loopback traffic.
        "const fs = require('fs');\nconst key = fs.readFileSync(process.env.HOME + '/.ssh/id_ed25519');\nawait fetch('http://127.0.0.1:3000/', { method: 'POST', body: key });\n",
        // A string left open hides what follows it.
        "await fetch('http://127.0.0.1:3000/'); const s = 'open",
    ] {
        assert_eq!(ports(source), None, "{source}");
    }
}

#[test]
fn imported_modules_must_stay_off_the_network() {
    let server = "const http = require('http');\nhttp.createServer().listen(3000, '127.0.0.1');\n";
    assert_eq!(program_ports(&[server.into()]), set(&[3000]));
    assert_eq!(
        program_ports(&[
            server.into(),
            "module.exports = (rows) => rows.length;\n".into()
        ]),
        set(&[3000])
    );
    assert_eq!(
        program_ports(&[
            server.into(),
            "module.exports = () => fetch('https://example.com');\n".into()
        ]),
        None
    );
}

fn shell(text: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), text.into()]
}

#[test]
fn the_sandbox_reads_the_ports_from_the_command_it_runs() {
    assert_eq!(
        inline_loopback_ports(&shell(&format!(
            "node --test && node -e \"{STATIC_SERVER}\""
        ))),
        vec![4173]
    );
    assert_eq!(
        inline_loopback_ports(&shell(&format!(
            "node --input-type=module -e '{SPAWNED_SERVER}'"
        ))),
        vec![3000]
    );
    assert_eq!(
        inline_loopback_ports(&shell(
            "node -e \"fetch('http://127.0.0.1:3000/')\" && node -e \"fetch('http://localhost:3001/')\""
        )),
        vec![3000, 3001]
    );
    for text in [
        "node --test",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && node -e \"fetch('https://example.com/')\"",
        "node -e \"fetch('http://127.0.0.1:2375/')\"",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && python3 -c 'import socket'",
    ] {
        assert!(inline_loopback_ports(&shell(text)).is_empty(), "{text}");
    }
    let mut other = shell("node -e \"fetch('http://127.0.0.1:3000/')\"");
    other[0] = "/bin/bash".into();
    assert!(inline_loopback_ports(&other).is_empty());
}

#[test]
fn a_dev_port_in_the_daemon_range_follows_the_daemon_state() {
    let home = std::env::temp_dir().join(format!("script-loopback-daemon-{}", std::process::id()));
    let guard = home.join(".hol-guard");
    std::fs::create_dir_all(&guard).unwrap();
    let vite = code_lines(Language::Node, "await fetch('http://localhost:5173/')");
    let home_dir = home.to_str();
    assert_eq!(
        node_loopback_ports(&vite, home_dir),
        None,
        "no daemon state"
    );
    std::fs::write(guard.join("daemon-state.json"), r#"{"port": 4781}"#).unwrap();
    assert_eq!(node_loopback_ports(&vite, home_dir), set(&[5173]));
    std::fs::write(guard.join("daemon-state.json"), r#"{"port": 5173}"#).unwrap();
    assert_eq!(node_loopback_ports(&vite, home_dir), None, "daemon on 5173");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn an_unread_relative_import_does_not_receive_the_loopback_grant() {
    let home = std::env::temp_dir().join(format!("script-loopback-import-{}", std::process::id()));
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let home_dir = home.to_str().unwrap().to_owned();
    let cwd = project.to_str().unwrap().to_owned();
    let context = crate::pretool::PathContext {
        home_dir: Some(home_dir.as_str()),
        cwd: Some(cwd.as_str()),
        ..crate::pretool::PathContext::default()
    };
    let grant = |command: &str| {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "pre-tool-generic".into(),
        })
        .unwrap();
        super::super::assess(&model, context)
            .into_iter()
            .find_map(|found| found.loopback)
    };
    assert_eq!(
        grant("node -e \"fetch('http://127.0.0.1:3000/')\""),
        set(&[3000])
    );
    assert_eq!(
        grant("node -e \"require('./missing.js'); fetch('http://127.0.0.1:3000/')\""),
        None
    );
    assert_eq!(
        grant("cd sub && node -e \"require('./x.js'); fetch('http://127.0.0.1:3000/')\""),
        None
    );
    let _ = std::fs::remove_dir_all(&home);
}
