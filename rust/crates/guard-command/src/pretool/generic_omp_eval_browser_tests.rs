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
        assert!(loopback_browser_program(code), "{code}");
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
        "await other.title();",
        "display('no browser');",
        "",
    ] {
        assert!(!loopback_browser_program(code), "{code}");
    }
}
