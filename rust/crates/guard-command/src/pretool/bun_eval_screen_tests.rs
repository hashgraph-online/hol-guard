use super::reads_only;

#[test]
fn file_reads_and_prints_pass_the_screen() {
    for program in [
        "const fs = require('fs'); const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); console.log(pkg.name, fs.readdirSync('.').length, fs.existsSync('bun.lock'), fs.statSync('package.json').size)",
        "console.log(require('fs').readdirSync('.'))",
        "require('node:fs').existsSync('bun.lock')",
        "require(\"fs\").statSync('package.json').size",
        "const { readFile } = require('fs/promises'); console.log((await readFile('README.md', 'utf8')).length)",
        "const path = require('path'); console.log(path.join(process.cwd(), 'src'))",
        "process.stdout.write(require('fs').readFileSync('package.json', 'utf8'))",
        "console.log(`${Bun.version} on ${process.platform}/${process.arch}`)",
        "console.log(Bun.revision, process.versions.bun)",
        "const names = ['a.json', 'b.json']; console.log(names.length, [1, 2][0])",
        "console.log(JSON.parse(require('fs').readFileSync('package.json', 'utf8'))['name'])",
    ] {
        assert!(reads_only(program), "{program}");
    }
}

#[test]
fn capability_markers_fail_the_screen() {
    for program in [
        "",
        "   ",
        // Network.
        "console.log(await (await fetch('https://example.com')).text())",
        "new WebSocket('wss://example.com')",
        "new XMLHttpRequest()",
        "require('http').get('http://example.com')",
        "require('https')",
        "require('net').connect(80, 'example.com')",
        "require('dgram')",
        // Processes and native code.
        "Bun.spawn(['sh', '-c', 'id'])",
        "Bun.spawnSync(['id'])",
        "require('child_process').execSync('id')",
        "require('worker_threads')",
        "require('bun:ffi')",
        "require('bun:sqlite')",
        "$`id`",
        "await $ `id`",
        "process.binding('spawn_sync')",
        "process.dlopen(module, 'x.node')",
        "process.kill(1)",
        "new Worker('x.js')",
        // Environment and process state.
        "console.log(process.env.GH_TOKEN)",
        "console.log(Bun.env)",
        "console.log(import.meta.env)",
        "const { env } = process; console.log(env)",
        "const p = process; console.log(p)",
        "console.log(require('fs').readFileSync('/proc/self/environ', 'utf8'))",
        // Code generation and reaching the global object.
        "console.log(Bun.version.constructor('return 1')())",
        "''.constructor.constructor('return process')()",
        "new Function('return 1')()",
        "eval('1')",
        "await import('fs')",
        "import fs from 'fs'",
        "console.log(globalThis.Bun.env)",
        "console.log(global.process)",
        "console.log(this)",
        "Reflect.get(Bun, 'env')",
        "Object.getPrototypeOf(async function () {})",
        "setTimeout('1', 0)",
        "console.log(B\\u0075n.env)",
        // Other Bun members, including file access through Bun.
        "await Bun.write('out.txt', 'x')",
        "console.log(Bun.file('package.json'))",
        "console.log(Bun)",
        "const b = Bun; console.log(b.version)",
        "Bun['spawn'](['id'])",
        // Writes outside the destructive-call list.
        "require('fs').writeFileSync('x', 'y')",
        "require('fs').writeSync(1, 'x')",
        "require('fs').createWriteStream('x')",
        "require('fs').symlinkSync('a', 'b')",
        "require('fs').cpSync('a', 'b')",
        "require('fs').openSync('x', 'w')",
        // Computed or dynamic names.
        "const fs = require('fs'); fs['write' + 'FileSync']('x', 'y')",
        "const fs = require('fs'); const k = 'unlinkSync'; fs[k]('x')",
        "const name = 'fs'; require(name)",
        "require('o' + 's')",
        "require.resolve('fs')",
        // Credential paths.
        "console.log(require('fs').readFileSync('.env', 'utf8'))",
        "console.log(require('fs').readFileSync('.ssh/id_rsa', 'utf8'))",
        // Modules outside the read-only set.
        "require('os').userInfo()",
        "require('vm').runInThisContext('1')",
    ] {
        assert!(!reads_only(program), "{program}");
    }
    assert!(!reads_only(&format!(
        "console.log({})",
        "1+".repeat(2100) + "1"
    )));
}
