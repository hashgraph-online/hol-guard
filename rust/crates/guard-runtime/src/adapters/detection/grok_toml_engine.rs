//! The byte-exact editor behind the Grok user-config merge. It edits the text of
//! a config whose `permission`, `compat` and `hooks` settings sit in explicit
//! `[table]` sections, splicing lines the way tomlkit lays them out (blank lines
//! before new headers, kept comments, array separators) while a parsed copy of
//! the document tracks the meaning. Any other layout is `Fail::Unsupported`,
//! and the caller falls back to the semantic editor.

use std::collections::{BTreeMap, BTreeSet};

use toml::Table;

use super::grok_toml_scan::{
    arr_append, arr_remove, headers, line_end, parse_groups, render_groups, toml_str, value_end,
    Header,
};
use super::grok_user_config::{Editor, Fail, Res, MANAGED_DENY_RULES};

type Key = Vec<String>;

fn under(path: &[String], prefix: &[&str]) -> bool {
    path.len() >= prefix.len() && path.iter().zip(prefix).all(|(a, b)| a == b)
}

fn is_path(path: &[String], target: &[&str]) -> bool {
    path.len() == target.len() && under(path, target)
}

struct Region {
    start: usize,
    end: usize,
    first: Header,
}

struct Loc {
    ls: usize,
    le: usize,
    vs: usize,
    ve: usize,
}

enum ArrayOp {
    Remove(usize),
    Append(String),
}

/// Where the value starts when `line` is `key = value`, quoted key allowed.
fn key_value_start(line: &str, key: &str) -> Option<usize> {
    let rest = line.trim_start_matches([' ', '\t']);
    let (quoted, rest) = match rest.strip_prefix('"') {
        Some(inner) => (true, inner),
        None => (false, rest),
    };
    let rest = rest.strip_prefix(key)?;
    let rest = if quoted {
        rest.strip_prefix('"')?
    } else {
        rest
    };
    let value = rest
        .trim_start_matches([' ', '\t'])
        .strip_prefix('=')?
        .trim_start_matches([' ', '\t']);
    Some(line.len() - value.len())
}

/// Where the value starts on any `name = value` line that is not a comment.
fn assigned_value_start(line: &str) -> Option<usize> {
    if line.trim_start_matches([' ', '\t']).starts_with('#') {
        return None;
    }
    let eq = line.find('=')? + 1;
    Some(eq + line[eq..].len() - line[eq..].trim_start_matches([' ', '\t']).len())
}

fn rules_text() -> String {
    MANAGED_DENY_RULES.map(toml_str).join(", ")
}

pub(crate) struct Eng {
    t: String,
    sem: Table,
    nulls: BTreeSet<Key>,
    anchors: BTreeMap<String, usize>,
    attached: BTreeSet<usize>,
    fake: BTreeSet<usize>,
    order: BTreeMap<String, usize>,
    aot_events: BTreeSet<String>,
}

impl Eng {
    pub(crate) fn new(text: &str, sem: Table) -> Self {
        let mut order = BTreeMap::new();
        let mut aot_events = BTreeSet::new();
        for header in headers(text) {
            if header.aot && header.path.len() == 2 && header.path[0] == "hooks" {
                let next = order.len();
                order.entry(header.path[1].clone()).or_insert(next);
                aot_events.insert(header.path[1].clone());
            }
        }
        Eng {
            t: text.to_string(),
            sem,
            nulls: BTreeSet::new(),
            anchors: BTreeMap::new(),
            attached: BTreeSet::new(),
            fake: BTreeSet::new(),
            order,
            aot_events,
        }
    }

    /// Replace `a..b` and keep every tracked offset pointing at the same text.
    fn splice(&mut self, a: usize, b: usize, new: &str) {
        self.t.replace_range(a..b, new);
        let shift = new.len() as isize - (b - a) as isize;
        let moved = |set: &BTreeSet<usize>| -> BTreeSet<usize> {
            set.iter()
                .filter(|p| **p >= b || **p < a)
                .map(|p| {
                    if *p >= b {
                        (*p as isize + shift) as usize
                    } else {
                        *p
                    }
                })
                .collect()
        };
        self.attached = moved(&self.attached);
        self.fake = moved(&self.fake);
        for at in self.anchors.values_mut().filter(|at| **at > a) {
            *at = a.max((*at as isize + shift).max(0) as usize);
        }
    }

    fn hs(&self) -> Vec<Header> {
        headers(&self.t)
    }

    /// The span of every header under `prefix`; they must sit together.
    fn region(&self, prefix: &[&str]) -> Res<Option<Region>> {
        let hs = self.hs();
        let found: Vec<usize> = (0..hs.len())
            .filter(|i| under(&hs[*i].path, prefix))
            .collect();
        let (Some(&first), Some(&last)) = (found.first(), found.last()) else {
            return Ok(None);
        };
        if found.len() != last - first + 1 {
            return Err(Fail::Unsupported);
        }
        let end = hs.get(last + 1).map_or(self.t.len(), |h| h.pos);
        let start = hs[first].pos;
        Ok(Some(Region {
            start: if self.attached.contains(&start) {
                start - 1
            } else {
                start
            },
            end: if self.attached.contains(&end) {
                end - 1
            } else {
                end
            },
            first: hs[first].clone(),
        }))
    }

    /// The span of the explicit `[path]` section, up to the next header.
    fn section(&self, path: &[&str]) -> Option<(usize, usize)> {
        let hs = self.hs();
        let at = hs.iter().position(|h| is_path(&h.path, path) && !h.aot)?;
        Some((hs[at].pos, hs.get(at + 1).map_or(self.t.len(), |h| h.pos)))
    }

    fn kv(&self, table: &[&str], key: &str) -> Res<Option<Loc>> {
        let (a, b) = self.section(table).ok_or(Fail::Unsupported)?;
        let bytes = self.t.as_bytes();
        let mut p = line_end(bytes, a);
        while p < b {
            let eol = line_end(bytes, p);
            if let Some(start) = key_value_start(&self.t[p..eol], key) {
                let (vs, ve) = (p + start, value_end(bytes, p + start));
                return Ok(Some(Loc {
                    ls: p,
                    le: line_end(bytes, ve),
                    vs,
                    ve,
                }));
            }
            p = match assigned_value_start(&self.t[p..eol]).map(|n| p + n) {
                Some(vs) if matches!(bytes.get(vs), Some(b'[' | b'{' | b'"' | b'\'')) => {
                    line_end(bytes, value_end(bytes, vs))
                }
                _ => eol,
            };
        }
        Ok(None)
    }

    /// Whether the text before `pos` ends in a blank line.
    fn prev_blank(&self, pos: usize) -> bool {
        let head = &self.t[..pos];
        if head.is_empty() {
            return false;
        }
        let mut lines = head.rsplit('\n');
        let last = lines.next().unwrap_or("");
        let line = if last.is_empty() {
            lines.next().unwrap_or("")
        } else {
            last
        };
        line.trim_matches([' ', '\t', '\r']).is_empty()
    }

    fn container_nonempty(&self, prefix: &[&str], pos: usize) -> Res<bool> {
        let key: Key = prefix.iter().map(|part| part.to_string()).collect();
        if self.nulls.contains(&key) {
            return Ok(true);
        }
        if prefix.is_empty() {
            return Ok(pos > 0);
        }
        Ok(match self.region(prefix)? {
            None => false,
            Some(r) if is_path(&r.first.path, prefix) && !r.first.aot => {
                r.end > line_end(self.t.as_bytes(), r.first.pos)
            }
            Some(_) => true,
        })
    }

    /// Append a table chunk under `parent`, or at the end when `parent` is absent.
    fn insert_table(&mut self, parent: &[&str], chunk: &str) -> Res<()> {
        let region = if parent.is_empty() {
            None
        } else {
            self.region(parent)?
        };
        let parent: &[&str] = if region.is_some() { parent } else { &[] };
        let pos = region.as_ref().map_or(self.t.len(), |r| r.end);
        let nonempty = self.container_nonempty(parent, pos)?;
        let anchored = region.is_none() && self.anchors.values().any(|at| *at == pos);
        let blank = nonempty && (!self.prev_blank(pos) || anchored);
        let before = self.t.len();
        self.splice(
            pos,
            pos,
            &format!("{}{chunk}", if blank { "\n" } else { "" }),
        );
        if region.is_some() {
            let grown = self.t.len() - before;
            for at in self.anchors.values_mut().filter(|at| **at == pos) {
                *at += grown;
            }
        }
        if blank {
            self.attached.insert(pos + 1);
            if pos > 0 && self.t.as_bytes()[pos - 1] != b'\n' {
                self.fake.insert(pos + 1);
            }
        }
        Ok(())
    }

    fn put(&mut self, pos: usize, chunk: &str) {
        let lead = if pos > 0 && self.t.as_bytes()[pos - 1] != b'\n' {
            "\n"
        } else {
            ""
        };
        self.splice(pos, pos, &format!("{lead}{chunk}"));
    }

    /// Add `line` after the last non-blank line of the `[table]` section.
    fn insert_kv(&mut self, table: &[&str], line: &str) -> Res<()> {
        let (a, b) = self.section(table).ok_or(Fail::Unsupported)?;
        let bytes = self.t.as_bytes();
        let mut end = line_end(bytes, a);
        let mut q = end;
        while q < b {
            let eol = line_end(bytes, q);
            if !self.t[q..eol]
                .trim_matches([' ', '\t', '\r', '\n'])
                .is_empty()
            {
                end = eol;
            }
            q = eol;
        }
        if self.fake.remove(&end) {
            self.splice(end - 1, end - 1, &format!("\n{line}\n"));
            return Ok(());
        }
        let pre = if end == 0 || self.t[..end].ends_with('\n') {
            ""
        } else {
            "\n"
        };
        let child = end == b
            && self.hs().iter().any(|h| {
                h.pos == b && under(&h.path, table) && h.path.len() > table.len() && !h.aot
            });
        let added = format!("{pre}{line}\n");
        self.splice(end, end, &added);
        for at in self.anchors.values_mut().filter(|at| **at == end) {
            *at += added.len();
        }
        let key: Key = table.iter().map(|part| part.to_string()).collect();
        if child && !self.nulls.contains(&key) {
            let at = b + added.len();
            self.splice(at, at, "\n");
            self.attached.insert(at + 1);
        }
        Ok(())
    }

    fn array_edit(&mut self, table: &[&str], key: &str, op: ArrayOp) -> Res<()> {
        let loc = self.kv(table, key)?.ok_or(Fail::Unsupported)?;
        if self.t.as_bytes().get(loc.vs) != Some(&b'[') {
            return Err(Fail::Unsupported);
        }
        let mut groups = parse_groups(&self.t, loc.vs, loc.ve).ok_or(Fail::Unsupported)?;
        match op {
            ArrayOp::Remove(index) => arr_remove(&mut groups, index).ok_or(Fail::Unsupported)?,
            ArrayOp::Append(value) => arr_append(&mut groups, value),
        }
        self.splice(loc.vs, loc.ve, &render_groups(&groups));
        Ok(())
    }

    fn is_aot(&self, event: &str) -> bool {
        self.hs()
            .iter()
            .any(|h| h.aot && is_path(&h.path, &["hooks", event]))
    }

    /// The span of the `index`-th `[[hooks.<event>]]` element with its sub-tables.
    fn aot_elem(&self, event: &str, index: usize) -> Res<(usize, usize)> {
        let hs = self.hs();
        let elems: Vec<usize> = (0..hs.len())
            .filter(|i| hs[*i].aot && is_path(&hs[*i].path, &["hooks", event]))
            .collect();
        let k = *elems.get(index).ok_or(Fail::Unsupported)?;
        let mut j = k + 1;
        while j < hs.len()
            && under(&hs[j].path, &["hooks", event])
            && (!hs[j].aot || hs[j].path.len() != 2)
        {
            j += 1;
        }
        let end = hs.get(j).map_or(self.t.len(), |h| h.pos);
        Ok((
            hs[k].pos,
            if self.attached.contains(&end) {
                end - 1
            } else {
                end
            },
        ))
    }
}

impl Editor for Eng {
    fn sem(&self) -> &Table {
        &self.sem
    }

    fn sem_mut(&mut self) -> &mut Table {
        &mut self.sem
    }

    fn text(&self) -> String {
        self.t.clone()
    }

    fn deny_remove(&mut self, index: usize) -> Res<()> {
        self.array_edit(&["permission"], "deny", ArrayOp::Remove(index))
    }

    fn hook_remove(&mut self, event: &str, index: usize) -> Res<()> {
        if !self.is_aot(event) {
            return self.array_edit(&["hooks"], event, ArrayOp::Remove(index));
        }
        let (a, b) = self.aot_elem(event, index)?;
        self.splice(a, b, "");
        let only = self
            .sem
            .get("hooks")
            .and_then(|hooks| hooks.get(event))
            .and_then(toml::Value::as_array)
            .is_some_and(|groups| groups.len() == 1);
        if only {
            self.anchors.insert(event.to_string(), a);
        }
        Ok(())
    }

    fn compat_set(&mut self, vendor: &str, value: bool) -> Res<()> {
        let loc = self
            .kv(&["compat", vendor], "hooks")?
            .ok_or(Fail::Unsupported)?;
        self.splice(loc.vs, loc.ve, if value { "true" } else { "false" });
        Ok(())
    }

    fn compat_unset(&mut self, vendor: &str) -> Res<()> {
        let loc = self
            .kv(&["compat", vendor], "hooks")?
            .ok_or(Fail::Unsupported)?;
        self.splice(loc.ls, loc.le, "");
        self.nulls
            .insert(vec!["compat".to_string(), vendor.to_string()]);
        Ok(())
    }

    fn pop(&mut self, path: &[&str]) -> Res<()> {
        let (key, parent) = path.split_last().ok_or(Fail::Unsupported)?;
        let loc = if parent.is_empty() || self.section(parent).is_none() {
            None
        } else {
            self.kv(parent, key)?
        };
        if let Some(loc) = loc {
            self.splice(loc.ls, loc.le, "");
        } else if let Some(region) = self.region(path)? {
            self.splice(region.start, region.end, "");
        }
        self.nulls.retain(|n| !under(n, path));
        match path {
            ["hooks"] => self.anchors.clear(),
            ["hooks", event] => {
                self.anchors.remove(*event);
            }
            _ => {}
        }
        self.nulls
            .insert(parent.iter().map(|part| part.to_string()).collect());
        Ok(())
    }

    fn permission_new(&mut self) -> Res<()> {
        self.insert_table(&[], &format!("[permission]\ndeny = [{}]\n", rules_text()))
    }

    fn deny_new(&mut self) -> Res<()> {
        self.insert_kv(&["permission"], &format!("deny = [{}]", rules_text()))
    }

    fn deny_append(&mut self, rule: &str) -> Res<()> {
        self.array_edit(&["permission"], "deny", ArrayOp::Append(toml_str(rule)))
    }

    fn compat_table_new(&mut self, vendor: &str) -> Res<()> {
        self.insert_table(&["compat"], &format!("[compat.{vendor}]\nhooks = false\n"))
    }

    fn compat_hooks_new(&mut self, vendor: &str) -> Res<()> {
        self.insert_kv(&["compat", vendor], "hooks = false")
    }

    fn hook_add(&mut self, event: &str, command: &str, timeout: i64, created: bool) -> Res<()> {
        let quoted = toml_str(command);
        if !(self.aot_events.contains(event) || created) {
            let group = format!(
                "{{hooks = [{{type = \"command\", command = {quoted}, timeout = {timeout}}}]}}"
            );
            return self.array_edit(&["hooks"], event, ArrayOp::Append(group));
        }
        let chunk = format!(
            "[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = {quoted}\ntimeout = {timeout}\n"
        );
        let pos = match self.region(&["hooks", event])? {
            Some(region) => Some(region.end),
            None => match self.anchors.remove(event) {
                Some(at) => Some(at),
                None => {
                    let mut at: Vec<usize> = self.anchors.values().copied().collect();
                    at.extend(self.region(&["hooks"])?.map(|r| r.end));
                    at.into_iter().max()
                }
            },
        };
        let Some(pos) = pos else {
            return self.insert_table(&[], &chunk);
        };
        let before = self.t.len();
        self.put(pos, &chunk);
        let grown = self.t.len() - before;
        let mine = self.order.get(event).copied().unwrap_or(usize::MAX);
        for (other, at) in self.anchors.iter_mut() {
            if *at == pos && self.order.get(other).copied().unwrap_or(0) > mine {
                *at += grown;
            }
        }
        Ok(())
    }
}
