use super::{loopback_browser_program, loopback_url};

#[test]
fn loopback_urls_are_exact_hosts_without_userinfo() {
    for url in [
        "http://localhost:4173",
        "http://localhost:4173/",
        "http://127.0.0.1:8080/game?x=1#top",
        "https://[::1]:3000/",
        "http://LOCALHOST",
    ] {
        assert!(loopback_url(url), "{url}");
    }
    for url in [
        "file:///etc/passwd",
        "https://example.com/",
        "http://localhost.example.com/",
        "http://localhost@example.com/",
        "http://user@localhost/",
        "http://127.0.0.1.nip.io/",
        "http://localhost:/",
        "http://localhost:99999999/",
        "http://localhost\\@example.com/",
        "http://0.0.0.0:4173/",
        "javascript:alert(1)",
        "http://local host/",
    ] {
        assert!(!loopback_url(url), "{url}");
    }
}

#[test]
fn observed_dev_server_checks_are_accepted() {
    for code in [
        "const tab = await browser.open({name:'skybound',url:'http://localhost:4173'}); display(await tab.title()); display(await tab.observe()); await tab.screenshot();",
        "const tab=browser.tab('skybound'); await tab.reload(); await tab.click('#start'); await tab.waitFor(300); await tab.press('Space'); await tab.waitFor(1800); const state=await tab.evaluate(()=>({score:document.querySelector('#score').textContent,overlay:document.querySelector('#overlay').className,canvas:document.querySelector('canvas').getContext('2d')!==null})); display(state); display(await tab.errors());",
        "const tab=await browser.open({name:'skybound-check',url:'http://localhost:4173'}); await tab.waitForSelector('#start'); await tab.click('#start'); await tab.press('Space'); await tab.waitFor(1800); display(await tab.evaluate(()=>({score:document.querySelector('#score').textContent,overlay:document.querySelector('#overlay').className,canvas:!!document.querySelector('canvas').getContext('2d')}))); display(await tab.errors());",
        "const t=await browser.open({name:'skybound-check',url:'http://localhost:4173'}); display(await t.title()); display(await t.observe()); display(await t.errors());",
        "const tab = browser.tab('t'); display(await tab.evaluate(() => { const items = document.querySelectorAll('li'); return items.length >= 1 && items[0].textContent === 'a'; }));",
        "const tab = await browser.open({url: 'http://127.0.0.1:5173/', viewport: {width: 800, height: 600}, wait_until: 'load'});\nawait tab.fill('#name', 'Ada');\nawait tab.evaluate(async (n) => { const el = document.querySelector('#out'); return el ? el.textContent + n : null; }, 2);\nconsole.log(await tab.console({level: 'error'}));\nawait tab.goto('http://localhost:5173/about');\nawait tab.scroll(0, -200);\nawait tab.close()",
    ] {
        assert!(loopback_browser_program(code, None), "{code}");
    }
}

#[test]
fn visibility_checks_pauses_and_negated_reads_are_accepted() {
    for code in [
        "const tab = await browser.open({name:'sky-hop-smoke',url:'http://localhost:4173',wait_until:'networkidle'}); console.log(await tab.title(), await tab.text('header')); console.log((await tab.screenshot({selector:'.game-frame'})).length); await tab.click('#game'); console.log('overlay hidden:', await tab.isVisible('.overlay')); await tab.close();",
        "const tab = await browser.open({name:'sky-hop-smoke',url:'http://localhost:4173'}); console.log(await tab.title(), await tab.text('header')); await tab.screenshot({selector:'.game-frame'}); await tab.click('#game'); console.log('overlay hidden:', !(await tab.isVisible('.overlay'))); await tab.close();",
        "const tab = await browser.open({name:'sky-hop-smoke',url:'http://127.0.0.1:4173/'}); console.log(await tab.title(), await tab.text('header')); await tab.screenshot({selector:'.game-frame'}); await tab.click('#game'); console.log('overlay hidden:', !(await tab.isVisible('.overlay'))); await tab.close();",
        "const tab=browser.tab('sky-hop-smoke'); await tab.click('.overlay'); console.log('started overlay hidden',!(await tab.isVisible('.overlay'))); console.log('errors',await tab.errors()); await tab.close();",
        "const tab=await browser.open({name:'sky-hop-smoke2',url:'http://127.0.0.1:4173/'}); await tab.press('Space'); await new Promise(r=>setTimeout(r,100)); console.log('overlay hidden after flap',!(await tab.isVisible('.overlay')),'errors',await tab.errors()); await tab.close();",
        "const tab = browser.tab('t'); await new Promise((resolve) => setTimeout(resolve, 250)); display(await tab.count('li'), await tab.attr('#start', 'disabled'), !!(await tab.isEnabled('#start')), await tab.isChecked('#mute'));",
    ] {
        assert!(loopback_browser_program(code, None), "{code}");
    }
}

#[test]
fn other_hosts_options_and_node_code_stay_reviewed() {
    for code in [
        // Not a loopback page, or no URL at all.
        "const tab = await browser.open({url:'file:///etc/passwd'}); display(await tab.title());",
        "const tab = await browser.open({url:'https://example.com/'}); display(await tab.title());",
        "const tab = await browser.open({url:'http://localhost.evil.com/'}); display(await tab.title());",
        "const tab = await browser.open({url:'http://x@localhost/'}); display(await tab.title());",
        "const tab = await browser.open({name:'x'}); display(await tab.title());",
        // Options that attach another browser, load code or files, or relax checks.
        "const tab = await browser.open({url:'http://localhost:1', app:{relay:true}});",
        "const tab = await browser.open({url:'http://localhost:1', app:{cdp_url:'http://127.0.0.1:9222'}});",
        "const tab = await browser.open({url:'http://localhost:1', init_scripts:['x']});",
        "const tab = await browser.open({url:'http://localhost:1', downloads:'.'});",
        "const tab = await browser.open({url:'http://localhost:1', allow_file_access:true});",
        "const tab = await browser.open({url:'http://localhost:1', persist:true});",
        "const tab = await browser.open({url:'http://localhost:1', url:'https://example.com'});",
        // Tab methods outside the modeled set, or non-literal arguments.
        "const tab = browser.tab('t'); await tab.goto('https://example.com/');",
        "const tab = browser.tab('t'); await tab.screenshot({path:'/tmp/x.png'});",
        "const tab = browser.tab('t'); await tab.run(() => 1);",
        "const tab = browser.tab('t'); await tab.cookies();",
        "const tab = browser.tab('t'); await tab.click(process.env.HOME);",
        "const tab = browser.tab('t'); await tab.evaluate(() => 1, process.env);",
        // The page function must be passed, not run in the agent process.
        "const tab = browser.tab('t'); await tab.evaluate((()=>require('child_process'))());",
        "const tab = browser.tab('t'); await tab.evaluate(() => {}());",
        "const tab = browser.tab('t'); await tab.evaluate(function(){ return 1; });",
        "const tab = browser.tab('t'); await tab.evaluate((a = require('fs')) => a);",
        // Node-level code around the browser calls.
        "const fs = require('fs'); const tab = browser.tab('t'); await tab.title();",
        "import fs from 'fs'; const tab = browser.tab('t');",
        "const tab = browser.tab('t'); await fetch('https://example.com');",
        "const tab = browser.tab('t'); display(process.env);",
        "const tab = browser.tab('t'); display(`${process.env.HOME}`);",
        "const tab = browser.tab('t'); // comment\nawait tab.title();",
        "const tab = browser.tab('t'); await tab.evaluate(() => 1 / 2);",
        "const tab = browser.tab('t'); await tab.evaluate(() => fetch('https://example.com/'));",
        "const tab = browser.tab('t'); await tab.evaluate('document.title');",
        "const tab = browser.tab('t'); await tab.evaluate(() => { location.href = 'x'; });",
        "const tab = browser.tab('t'); await tab.evaluate(() => { document.title = 'x'; });",
        "const tab = browser.tab('t'); await tab.evaluate(() => window['fe' + 'tch']);",
        "const tab = browser.tab('t'); await tab.evaluate(() => document['loc' + 'ation']);",
        "const tab = browser.tab('t'); await tab.evaluate(() => document.defaultView);",
        "const tab = browser.tab('t'); await tab.evaluate(() => document.querySelector('a').getAttribute('x') + 'https://example.com');",
        "const tab = browser.tab('t'); await tab.evaluate(() => { document.body.innerHTML = '<img>'; });",
        "const tab = browser.tab('t'); await tab.evaluate(() => this);",
        "const tab = browser.tab('t'); await tab.evaluate(() => { const a = document.links; a.x = 1; });",
        "const tab = browser.tab('t'); await tab.title()\n(globalThis.x = 1)",
        // Visibility reads, pauses and value forms with anything but literals.
        "const tab = browser.tab('t'); await tab.isVisible(process.env.HOME);",
        "const tab = browser.tab('t'); await tab.attr('#a');",
        "const tab = browser.tab('t'); await new Promise(r => setTimeout(() => require('fs'), 1));",
        "const tab = browser.tab('t'); await new Promise(r => setTimeout(r, process.env.MS));",
        "const tab = browser.tab('t'); await new Promise(r => setTimeout(q, 1));",
        "const tab = browser.tab('t'); await new Promise(r => setTimeout(r, 1)).then(require);",
        "const tab = browser.tab('t'); await new Function('return process')();",
        "const tab = browser.tab('t'); await new Promise(process => setTimeout(process, 1));",
        "const tab = browser.tab('t'); display((await tab.title()).constructor);",
        "const tab = browser.tab('t'); display((await tab.title()).length());",
        "const tab = browser.tab('t'); display((process).length);",
        "const tab = browser.tab('t'); display(!process.env);",
        "const tab = browser.tab('t'); display(!(await tab.title()) + 1);",
        "await other.title();",
        "display('no browser');",
        "",
    ] {
        assert!(!loopback_browser_program(code, None), "{code}");
    }
}

const SERVER_WAIT: &str = "let r; for (let i=0;i<20;i++){ try {r=await fetch('http://localhost:3000/');break} catch {await new Promise(x=>setTimeout(x,100))}}; if(!r) throw Error('server did not start'); const html=await r.text(); const data=await (await fetch('http://localhost:3000/api/todos')).json(); display({status:r.status,title:html.includes('<title>My Todos</title>'),todoList:data})";

const PAGE_RUN: &str = "const tab=browser.tab('flappy'); display(await tab.run(async({page})=>{await page.click('#game'); const started=await page.evaluate(()=>document.querySelector('#game').getContext('2d')!==null); await page.keyboard.press('Space'); return {started,canvas:await page.$eval('#game',e=>[e.width,e.height]),errors:[]};})); display(await tab.errors()); await tab.close();";

#[test]
fn local_server_waits_and_page_runs_are_accepted() {
    for code in [
        SERVER_WAIT,
        PAGE_RUN,
        "const r = await fetch('http://127.0.0.1:8080/health', {method: 'GET'}); display(r.ok, await r.json());",
        "const tab = browser.tab('t'); await tab.run(async ({page}) => { await page.goto('http://localhost:4173/'); await page.waitForSelector('#app', {timeout: 5000}); await page.hover('#a'); return await page.title(); });",
    ] {
        assert!(loopback_browser_program(code, None), "{code}");
    }
}

#[test]
fn other_requests_and_page_methods_stay_reviewed() {
    for (base, from, to) in [
        (
            SERVER_WAIT,
            "http://localhost:3000/api/todos",
            "https://example.com/api/todos",
        ),
        (SERVER_WAIT, "/')", "/', {method:'POST',body:'x'})"),
        (SERVER_WAIT, "/')", "/', {headers:{a:'b'}})"),
        (SERVER_WAIT, "/')", "/', {method:'DELETE'})"),
        (
            SERVER_WAIT,
            "Error('server did not start')",
            "Error(process.env.HOME)",
        ),
        (SERVER_WAIT, "let r; ", ""),
        (
            SERVER_WAIT,
            "localhost:3000/api",
            "127.0.0.1:2375/containers",
        ),
        (SERVER_WAIT, "localhost:3000/api", "localhost:9229/json"),
        (SERVER_WAIT, "localhost:3000/api", "localhost:4781/api"),
        (
            SERVER_WAIT,
            "/todos",
            "/todos?k=0123456789abcdef0123456789abcdef01234567",
        ),
        (
            PAGE_RUN,
            "page.click('#game')",
            "page.goto('http://127.0.0.1:9222/json')",
        ),
        (SERVER_WAIT, "i<20", "i<n"),
        (SERVER_WAIT, "i<20", "i<101"),
        (SERVER_WAIT, "i<20", "i<20.5"),
        (
            SERVER_WAIT,
            "i=0;i<20",
            "i=9007199254740992;i<9007199254740994",
        ),
        (
            PAGE_RUN,
            "page.click('#game')",
            "page.goto('https://example.com/')",
        ),
        (
            PAGE_RUN,
            "page.click('#game')",
            "page.exposeFunction('f', () => 1)",
        ),
        (PAGE_RUN, "page.click('#game')", "page.setContent('<p>')"),
        (PAGE_RUN, "page.click('#game')", "page.cookies()"),
        (
            PAGE_RUN,
            "page.click('#game')",
            "page.addScriptTag({url: 'http://localhost:1/a.js'})",
        ),
        (PAGE_RUN, "page.click('#game')", "page.context().newPage()"),
        (PAGE_RUN, "page.click('#game')", "page.evaluate('fetch(1)')"),
        (PAGE_RUN, "errors:[]", "page"),
        (PAGE_RUN, "async({page})", "async({page, context})"),
    ] {
        let code = base.replacen(from, to, 1);
        assert_ne!(code, base, "{from}");
        assert!(!loopback_browser_program(&code, None), "{code}");
    }
    for code in [
        "let r; break; r = await fetch('http://localhost:3000/');",
        "s = await fetch('http://localhost:3000/');",
        "for (let a=0;a<100;a++){ for (let b=0;b<100;b++){ await fetch('http://localhost:3000/') } }",
        "const r = await fetch('http://localhost:3000/'); display(r.headers);",
        "const r = await fetch('http://localhost:3000/'); const t = await r.arrayBuffer(); display(t);",
        "const r = await fetch('http://localhost:3000/'); for (let i=0;i<3;i++){ require('fs') }",
        "const r = await fetch('http://localhost:3000/'); try {} catch (e) { display(e) }",
        "const page = 1; await fetch('http://localhost:3000/');",
        "const tab = browser.tab('t'); await page.click('#a');",
    ] {
        assert!(!loopback_browser_program(code, None), "{code}");
    }
}
