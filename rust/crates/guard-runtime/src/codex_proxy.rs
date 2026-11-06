//! `_parse_guard_proxy_args`: the `--key value` grammar of a Guard MCP proxy
//! launch, as the Codex detector reads it back from a configured server.

use std::collections::HashMap;

#[derive(Default)]
pub(crate) struct ProxyArgs {
    scalars: HashMap<String, String>,
    /// Every `--arg` occurrence, in order.
    pub(crate) args: Vec<String>,
    /// Every `--server-env-key` occurrence, in order.
    pub(crate) env_keys: Vec<String>,
}

impl ProxyArgs {
    pub(crate) fn value(&self, key: &str) -> Option<&str> {
        self.scalars.get(key).map(String::as_str)
    }
}

enum Repeated {
    Arg,
    EnvKey,
}

fn repeated(key: &str) -> Option<Repeated> {
    match key {
        "arg" => Some(Repeated::Arg),
        "server-env-key" => Some(Repeated::EnvKey),
        _ => None,
    }
}

pub(crate) fn parse_proxy_args(args: &[String]) -> ProxyArgs {
    let mut parsed = ProxyArgs::default();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let Some(key_value) = token.strip_prefix("--") else {
            index += 1;
            continue;
        };
        if let Some((key, value)) = key_value.split_once('=') {
            match repeated(key) {
                Some(Repeated::Arg) => parsed.args.push(value.to_owned()),
                Some(Repeated::EnvKey) => parsed.env_keys.push(value.to_owned()),
                None => {
                    parsed.scalars.insert(key.to_owned(), value.to_owned());
                }
            }
            index += 1;
            continue;
        }
        if let Some(kind) = repeated(key_value) {
            if let Some(value) = args.get(index + 1) {
                match kind {
                    Repeated::Arg => parsed.args.push(value.clone()),
                    Repeated::EnvKey => parsed.env_keys.push(value.clone()),
                }
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        match args.get(index + 1) {
            Some(next) if !next.starts_with("--") => {
                parsed.scalars.insert(key_value.to_owned(), next.clone());
                index += 2;
            }
            _ => index += 1,
        }
    }
    parsed
}
