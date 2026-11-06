//! The semantic editor behind the Grok user-config merge: the fallback for a
//! config whose settings sit in layouts the byte-exact editor does not
//! reproduce (inline or dotted tables, split sections). It edits a
//! format-preserving `toml_edit` document, so comments and untouched lines
//! survive, but new text follows `toml_edit`'s layout rather than tomlkit's.

use toml::Table as Parsed;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use super::grok_user_config::{Editor, Fail, Res, MANAGED_DENY_RULES};

pub(crate) struct Semantic {
    doc: DocumentMut,
    sem: Parsed,
}

fn rules() -> Array {
    MANAGED_DENY_RULES
        .iter()
        .map(|rule| Value::from(*rule))
        .collect()
}

/// The `[{type = "command", ...}]` handler list of one catch-all group.
fn handlers(command: &str, timeout: i64) -> Array {
    let mut handler = InlineTable::new();
    handler.insert("type", Value::from("command"));
    handler.insert("command", Value::from(command));
    handler.insert("timeout", Value::from(timeout));
    std::iter::once(Value::InlineTable(handler)).collect()
}

fn take(list: &mut Array, index: usize) -> Res<()> {
    if index >= list.len() {
        return Err(Fail::Unsupported);
    }
    list.remove(index);
    Ok(())
}

impl Semantic {
    pub(crate) fn new(text: &str, sem: Parsed) -> Res<Self> {
        let doc = text.parse::<DocumentMut>().map_err(|_| Fail::Unsupported)?;
        Ok(Semantic { doc, sem })
    }

    /// The item at `path`. `Item::get_mut` would create a missing key as an
    /// empty inline table; `TableLike::get_mut` only looks.
    fn item(&mut self, path: &[&str]) -> Res<&mut Item> {
        let mut item = self.doc.as_item_mut();
        for key in path {
            item = item
                .as_table_like_mut()
                .and_then(|table| table.get_mut(key))
                .ok_or(Fail::Unsupported)?;
        }
        Ok(item)
    }

    fn list(&mut self, path: &[&str]) -> Res<&mut Array> {
        self.item(path)?.as_array_mut().ok_or(Fail::Unsupported)
    }

    fn table_like(&mut self, path: &[&str]) -> Res<&mut dyn TableLike> {
        self.item(path)?
            .as_table_like_mut()
            .ok_or(Fail::Unsupported)
    }

    /// Make `path` a table, creating implicit ones; true when it is an inline table.
    fn ensure(&mut self, path: &[&str]) -> Res<bool> {
        let mut item = self.doc.as_item_mut();
        let mut inline = false;
        for key in path {
            let table = item.as_table_like_mut().ok_or(Fail::Unsupported)?;
            if !table.contains_key(key) {
                let fresh = if inline {
                    Item::Value(Value::InlineTable(InlineTable::new()))
                } else {
                    let mut implicit = Table::new();
                    implicit.set_implicit(true);
                    Item::Table(implicit)
                };
                table.insert(key, fresh);
            }
            item = table.get_mut(key).ok_or(Fail::Unsupported)?;
            inline = inline || matches!(item, Item::Value(_));
        }
        Ok(inline)
    }
}

impl Editor for Semantic {
    fn sem(&self) -> &Parsed {
        &self.sem
    }

    fn sem_mut(&mut self) -> &mut Parsed {
        &mut self.sem
    }

    fn text(&self) -> String {
        self.doc.to_string()
    }

    fn deny_remove(&mut self, index: usize) -> Res<()> {
        take(self.list(&["permission", "deny"])?, index)
    }

    fn hook_remove(&mut self, event: &str, index: usize) -> Res<()> {
        match self.item(&["hooks", event])? {
            Item::ArrayOfTables(groups) if index < groups.len() => {
                groups.remove(index);
                Ok(())
            }
            Item::ArrayOfTables(_) => Err(Fail::Unsupported),
            other => take(other.as_array_mut().ok_or(Fail::Unsupported)?, index),
        }
    }

    fn compat_set(&mut self, vendor: &str, value: bool) -> Res<()> {
        let slot = self.item(&["compat", vendor, "hooks"])?;
        let mut flag = Value::from(value);
        if let Some(old) = slot.as_value() {
            *flag.decor_mut() = old.decor().clone();
        }
        *slot = Item::Value(flag);
        Ok(())
    }

    fn compat_unset(&mut self, vendor: &str) -> Res<()> {
        self.table_like(&["compat", vendor])?.remove("hooks");
        Ok(())
    }

    fn pop(&mut self, path: &[&str]) -> Res<()> {
        if let Some((key, parent)) = path.split_last() {
            if let Ok(table) = self.table_like(parent) {
                table.remove(key);
            }
        }
        Ok(())
    }

    fn permission_new(&mut self) -> Res<()> {
        let mut permission = Table::new();
        permission.insert("deny", Item::Value(Value::Array(rules())));
        self.table_like(&[])?
            .insert("permission", Item::Table(permission));
        Ok(())
    }

    fn deny_new(&mut self) -> Res<()> {
        let deny = Item::Value(Value::Array(rules()));
        self.table_like(&["permission"])?.insert("deny", deny);
        Ok(())
    }

    fn deny_append(&mut self, rule: &str) -> Res<()> {
        self.list(&["permission", "deny"])?.push(rule);
        Ok(())
    }

    fn compat_table_new(&mut self, vendor: &str) -> Res<()> {
        let fresh = if self.ensure(&["compat"])? {
            let mut flags = InlineTable::new();
            flags.insert("hooks", Value::from(false));
            Item::Value(Value::InlineTable(flags))
        } else {
            let mut flags = Table::new();
            flags.insert("hooks", Item::Value(Value::from(false)));
            Item::Table(flags)
        };
        self.table_like(&["compat"])?.insert(vendor, fresh);
        Ok(())
    }

    fn compat_hooks_new(&mut self, vendor: &str) -> Res<()> {
        let flag = Item::Value(Value::from(false));
        self.table_like(&["compat", vendor])?.insert("hooks", flag);
        Ok(())
    }

    fn hook_add(&mut self, event: &str, command: &str, timeout: i64, _created: bool) -> Res<()> {
        let listed = handlers(command, timeout);
        if self.item(&["hooks", event]).is_ok() {
            return match self.item(&["hooks", event])? {
                Item::ArrayOfTables(groups) => {
                    let mut group = Table::new();
                    group.insert("hooks", Item::Value(Value::Array(listed)));
                    groups.push(group);
                    Ok(())
                }
                other => {
                    let mut group = InlineTable::new();
                    group.insert("hooks", Value::Array(listed));
                    other
                        .as_array_mut()
                        .ok_or(Fail::Unsupported)?
                        .push(Value::InlineTable(group));
                    Ok(())
                }
            };
        }
        let fresh = if self.ensure(&["hooks"])? {
            let mut group = InlineTable::new();
            group.insert("hooks", Value::Array(listed));
            Item::Value(Value::Array(
                std::iter::once(Value::InlineTable(group)).collect(),
            ))
        } else {
            let mut group = Table::new();
            group.insert("hooks", Item::Value(Value::Array(listed)));
            let mut groups = ArrayOfTables::new();
            groups.push(group);
            Item::ArrayOfTables(groups)
        };
        self.table_like(&["hooks"])?.insert(event, fresh);
        Ok(())
    }
}
