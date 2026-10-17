#![cfg(unix)]

//! Oh My Pi `eval` programs that only compute in memory are read by content;
//! anything that reaches further keeps its review.

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use serde_json::json;

fn allowed(session: &Session, language: &str, code: &str) -> bool {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "eval", "tool_input": {
            "language": language, "code": code, "title": "Probe", "timeout": 60, "reset": false}}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    )
    .minimum_action
        == "allow"
}

#[test]
fn pure_python_is_allowed_and_reaching_python_is_reviewed() {
    let s = session("omp-eval-pure-py");
    assert!(allowed(
        &s,
        "py",
        "import shutil\nfor n in ['node', 'git']:\n    print(n, shutil.which(n))\n"
    ));
    assert!(allowed(
        &s,
        "py",
        "import re\nprint(re.findall(r'\\d+', 'a1b22'))\n"
    ));
    for code in [
        "import subprocess\nsubprocess.run(['ls'])",
        "import os\nprint(os.environ)",
        "import shutil\nshutil.rmtree('x')",
        "print(open('/etc/hosts').read())",
        "print(f'{1+1}')",
        "list(map(bash, ['ls']))",
    ] {
        assert!(!allowed(&s, "py", code), "{code}");
    }
}

#[test]
fn browser_driving_and_module_attribute_chains_are_reviewed() {
    let s = session("omp-eval-browser");
    let cwd = s.org.to_str().unwrap();
    for code in [
        format!("const tab = await browser.open({{name:'t', url:'file://{cwd}/index.html'}}); await tab.close();"),
        String::from("const tab = await browser.open({name:'t', url:'https://example.com/'});"),
        String::from("const tab = browser.tab('t'); await tab.goto('https://example.com/');"),
        String::from("const tab = await browser.open({url:'http://localhost:4173', app:{relay:true}});"),
        String::from("const tab = browser.tab('t'); await tab.evaluate((()=>require('child_process'))());"),
    ] {
        assert!(!allowed(&s, "js", &code), "{code}");
    }
    for code in [
        "import shlex\nshlex.os.system('id')",
        "import dataclasses\nprint(dataclasses.copy.types.FunctionType)",
        "import fnmatch\nprint(fnmatch.re.enum.bltns.getattr)",
        "import enum\nprint((enum).bltns.getattr)",
        "import enum\nm = enum\nprint(m.bltns.getattr)",
        "from enum import bltns as b\nprint(b)",
        "import enum\nprint(enum.bltns.getattr)",
        "from shlex import os as o\no.execvp('sh', ['sh', '-c', 'id'])",
        "import typing\ntyping.sys.modules['os'].system('id')",
        "import collections\ncollections._sys.exit(0)",
        "import dataclasses\ndataclasses.sys.modules['os'].system('id')",
        "import shlex\nprint('{0.os.environ}'.format(shlex))",
        "import operator, shlex\nprint(operator.attrgetter('os')(shlex))",
    ] {
        assert!(!allowed(&s, "py", code), "{code}");
    }
}

#[test]
fn loopback_browser_checks_are_allowed() {
    let s = session("omp-eval-loopback-browser");
    for code in [
        "const tab = await browser.open({name:'skybound',url:'http://localhost:4173'}); display(await tab.title()); display(await tab.observe()); await tab.screenshot();",
        "const tab=browser.tab('skybound'); await tab.reload(); await tab.click('#start'); await tab.waitFor(300); await tab.press('Space'); const state=await tab.evaluate(()=>({score:document.querySelector('#score').textContent,canvas:document.querySelector('canvas').getContext('2d')!==null})); display(state); display(await tab.errors());",
        "let r; for (let i=0;i<20;i++){ try {r=await fetch('http://localhost:3000/');break} catch {await new Promise(x=>setTimeout(x,100))}}; if(!r) throw Error('server did not start'); const html=await r.text(); const data=await (await fetch('http://localhost:3000/api/todos')).json(); display({status:r.status,title:html.includes('<title>My Todos</title>'),todoList:data})",
        "const tab=browser.tab('flappy'); display(await tab.run(async({page})=>{await page.click('#game'); const started=await page.evaluate(()=>document.querySelector('#game').getContext('2d')!==null); await page.keyboard.press('Space'); return {started,canvas:await page.$eval('#game',e=>[e.width,e.height]),errors:[]};})); display(await tab.errors()); await tab.close();",
    ] {
        assert!(allowed(&s, "js", code), "{code}");
    }
    // The same calls written in Python are not modeled.
    assert!(!allowed(
        &s,
        "py",
        "tab = browser.tab('skybound')\nprint(tab.title())"
    ));
}
