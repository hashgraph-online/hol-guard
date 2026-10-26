//! Local-server waits and `TAB.run` page scripts for the browser eval parser
//! in `generic_omp_eval_browser.rs`: loopback `fetch` GETs and their reads,
//! counted retry loops, `try`/`catch`, `if (!NAME) throw Error('...')`, and a
//! `TAB.run(async ({page}) => {...})` body limited to modeled `page` calls.

use super::lex::{Token, RESERVED};
use super::Parser;
use crate::pretool::curl_reads::loopback_url;

/// Most passes a retry loop may make.
const MAX_LOOP_COUNT: u32 = 100;

impl Parser {
    /// Whether `name` may be bound: not reserved, not the run callback's
    /// `page`, and not already bound.
    pub(super) fn fresh(&self, name: &str) -> bool {
        !RESERVED.contains(&name)
            && name != "page"
            && !self.tabs.contains(name)
            && !self.values.contains(name)
            && !self.responses.contains(name)
            && !self.unset.contains(name)
    }

    /// Whether `url` reaches a local dev server under the same port and
    /// secret rules as a loopback `curl` read. Unlike the isolated browser,
    /// `fetch` runs in the eval host, and `page.goto` can hand the page's
    /// markup back through `page.content()`.
    fn dev_server_url(&self, url: &str) -> bool {
        loopback_url(url, self.home_dir.as_deref())
    }

    /// `fetch('LOOPBACK_URL')`, optionally with `{method: 'GET'}`, after its
    /// `await`.
    pub(super) fn fetch_call(&mut self) -> Option<()> {
        self.keyword("fetch")?;
        self.punct('(')?;
        let url = self.string()?;
        if !self.dev_server_url(&url) {
            return None;
        }
        if self.eat_punct(',') {
            self.punct('{')?;
            if !self.eat_punct('}') {
                self.keyword("method")?;
                self.punct(':')?;
                if self.string()? != "GET" {
                    return None;
                }
                self.eat_punct(',');
                self.punct('}')?;
            }
        }
        self.browser_calls += 1;
        self.punct(')')
    }

    /// `NAME = await fetch(...)` onto a `let` name or an earlier response.
    pub(super) fn assign_fetch(&mut self, name: String) -> Option<()> {
        self.punct('=')?;
        self.keyword("await")?;
        self.fetch_call()?;
        self.unset.remove(&name);
        self.responses.insert(name);
        Some(())
    }

    /// What follows `await` in a value: a `page` call inside `TAB.run`, a
    /// loopback `fetch`, a response body read, or a tab call.
    pub(super) fn awaited_value(&mut self) -> Option<()> {
        match self.peek()?.clone() {
            Token::Ident(word) if word == "page" && self.in_run => self.page_call(),
            Token::Ident(word) if word == "fetch" => self.fetch_call(),
            Token::Ident(word) if self.responses.contains(&word) => {
                self.pos += 1;
                self.body_read()
            }
            Token::Punct('(') => {
                self.pos += 1;
                self.keyword("await")?;
                self.fetch_call()?;
                self.punct(')')?;
                self.body_read()
            }
            _ => self.tab_call(),
        }
    }

    /// `.text()` or `.json()` on a response.
    fn body_read(&mut self) -> Option<()> {
        self.punct('.')?;
        if !matches!(self.ident()?.as_str(), "text" | "json") {
            return None;
        }
        self.punct('(')?;
        self.punct(')')
    }

    /// The member read after declared name `name`: a response's `status`,
    /// `ok` or `statusText`, or a value's `length` or string search.
    pub(super) fn member(&mut self, name: &str) -> Option<()> {
        if self.responses.contains(name) {
            self.punct('.')?;
            return matches!(self.ident()?.as_str(), "status" | "ok" | "statusText").then_some(());
        }
        if !self.eat_punct('.') {
            return Some(());
        }
        match self.ident()?.as_str() {
            "length" => Some(()),
            "includes" | "startsWith" | "endsWith" => {
                self.punct('(')?;
                self.string()?;
                self.punct(')')
            }
            _ => None,
        }
    }

    /// One `key: value` entry of a displayed object, or a declared value
    /// name in shorthand.
    pub(super) fn object_entry(&mut self) -> Option<()> {
        if let (Some(Token::Ident(name)), Some(Token::Punct(',' | '}'))) =
            (self.peek(), self.tokens.get(self.pos + 1))
        {
            if !self.values.contains(name) {
                return None;
            }
            self.pos += 1;
            return Some(());
        }
        self.key()?;
        self.punct(':')?;
        self.value()
    }

    /// `{ statements }`, each ending at `;`, the brace, or the next keyword.
    fn block(&mut self) -> Option<()> {
        self.enter()?;
        self.punct('{')?;
        while !self.eat_punct('}') {
            if self.eat_punct(';') {
                continue;
            }
            self.statement()?;
            match self.peek() {
                Some(Token::Punct(';' | '}') | Token::Ident(_)) => {}
                _ => return None,
            }
        }
        self.depth -= 1;
        Some(())
    }

    /// `for (let I = A; I < B; I++) { ... }` after `for`, with integer
    /// bounds at most [`MAX_LOOP_COUNT`] apart, never inside another loop.
    pub(super) fn for_loop(&mut self) -> Option<()> {
        // A retry loop never needs nesting, which would multiply the bound.
        if self.loops > 0 {
            return None;
        }
        self.punct('(')?;
        self.keyword("let")?;
        let index = self.ident()?;
        if !self.fresh(&index) {
            return None;
        }
        self.punct('=')?;
        let Token::Num(Some(first)) = self.next()? else {
            return None;
        };
        self.punct(';')?;
        self.keyword(&index)?;
        self.punct('<')?;
        let Token::Num(Some(end)) = self.next()? else {
            return None;
        };
        if end.checked_sub(first)? > MAX_LOOP_COUNT {
            return None;
        }
        self.punct(';')?;
        self.keyword(&index)?;
        self.punct('+')?;
        self.punct('+')?;
        self.punct(')')?;
        self.loops += 1;
        self.block()?;
        self.loops -= 1;
        Some(())
    }

    /// `try { ... } catch [(NAME)] { ... }` after `try`; the error is never
    /// bound for later use.
    pub(super) fn try_block(&mut self) -> Option<()> {
        self.block()?;
        self.keyword("catch")?;
        if self.eat_punct('(') {
            let error = self.ident()?;
            if !self.fresh(&error) {
                return None;
            }
            self.punct(')')?;
        }
        self.block()
    }

    /// `if (!NAME) throw [new] Error('...')` after `if`.
    pub(super) fn if_throw(&mut self) -> Option<()> {
        self.punct('(')?;
        self.punct('!')?;
        let name = self.ident()?;
        if !(self.unset.contains(&name)
            || self.responses.contains(&name)
            || self.values.contains(&name))
        {
            return None;
        }
        self.punct(')')?;
        self.keyword("throw")?;
        if self.peek_ident("new") {
            self.pos += 1;
        }
        self.keyword("Error")?;
        self.punct('(')?;
        self.string()?;
        self.punct(')')
    }

    /// `async ({page}) => { ... }` passed to `TAB.run`, whose body may use
    /// `page` only through `page_call`.
    pub(super) fn run_callback(&mut self) -> Option<()> {
        if self.in_run {
            return None;
        }
        self.keyword("async")?;
        self.punct('(')?;
        self.punct('{')?;
        self.keyword("page")?;
        self.punct('}')?;
        self.punct(')')?;
        self.punct('=')?;
        self.punct('>')?;
        self.in_run = true;
        self.block()?;
        self.in_run = false;
        Some(())
    }

    /// `page.METHOD(args)` inside `TAB.run`, after its `await`: input,
    /// waits, reads, loopback `goto`, and in-page functions.
    pub(super) fn page_call(&mut self) -> Option<()> {
        self.keyword("page")?;
        self.punct('.')?;
        let method = self.ident()?;
        if method == "keyboard" {
            self.punct('.')?;
            if !matches!(self.ident()?.as_str(), "press" | "type" | "down" | "up") {
                return None;
            }
            self.punct('(')?;
            self.string()?;
            return self.punct(')');
        }
        self.punct('(')?;
        match method.as_str() {
            "title" | "url" | "content" => {}
            "click" | "dblclick" | "hover" | "focus" | "waitForSelector" => {
                self.string()?;
                if self.eat_punct(',') {
                    self.options()?;
                }
            }
            "type" | "fill" => {
                self.string()?;
                self.punct(',')?;
                self.string()?;
            }
            "goto" => {
                let url = self.string()?;
                if !self.dev_server_url(&url) {
                    return None;
                }
                if self.eat_punct(',') {
                    self.options()?;
                }
            }
            "evaluate" | "$eval" | "$$eval" => {
                if method != "evaluate" {
                    self.string()?;
                    self.punct(',')?;
                }
                self.page_function()?;
                while self.eat_punct(',') {
                    self.literal()?;
                }
            }
            "waitForTimeout" => matches!(self.next()?, Token::Num(_)).then_some(())?,
            _ => return None,
        }
        self.punct(')')
    }
}
