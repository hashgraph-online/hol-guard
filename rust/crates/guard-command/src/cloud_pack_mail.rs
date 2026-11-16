//! The `rfc822` body template: a plain-text message built from declared arguments.
//!
//! Mail APIs such as Gmail take a whole encoded message rather than separate
//! recipient fields, so a pack that passed a caller's message through would
//! send to addresses Guard never saw. This template builds the message itself
//! from the same arguments the recipient facts are read from. Every address
//! must be a bare `local@domain`, the subject is always RFC 2047 encoded and
//! the text is always base64, so no argument can add a header or a recipient.

use crate::cloud_pack::{ArgumentSpec, Template};
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Names of the arguments a message is built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailTemplate {
    pub to: String,
    pub cc: Option<String>,
    pub bcc: Option<String>,
    pub subject: String,
    pub text: String,
}

impl MailTemplate {
    /// The recipient arguments, in header order.
    pub fn recipient_arguments(&self) -> Vec<&str> {
        [Some(&self.to), self.cc.as_ref(), self.bcc.as_ref()]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    }
}

const LINE: usize = 76;
/// Raw subject bytes per encoded word: 39 bytes encode to 52 base64 characters, so a word with
/// its 12-character `=?UTF-8?B?...?=` wrapper is 64 characters, within RFC 2047's 75, and the
/// first line, `Subject: ` and one word, stays within the 78 characters RFC 5322 recommends.
const WORD_BYTES: usize = 39;

/// Check that `mail` reads a required recipient list, optional copy lists and text arguments.
pub(crate) fn validate(
    mail: &MailTemplate,
    args: &BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    let names = mail.recipient_arguments();
    let unique: BTreeSet<&str> = names
        .iter()
        .copied()
        .chain([mail.subject.as_str(), mail.text.as_str()])
        .collect();
    if unique.len() != names.len() + 2 {
        return Err("cloud_pack_template_mail_invalid");
    }
    let to_ok = matches!(
        args.get(&mail.to),
        Some(ArgumentSpec::Array { required: true, min_items, .. }) if *min_items >= 1
    );
    let copies_ok = [&mail.cc, &mail.bcc]
        .into_iter()
        .flatten()
        .all(|name| matches!(args.get(name), Some(ArgumentSpec::Array { .. })));
    let text_ok = [&mail.subject, &mail.text]
        .into_iter()
        .all(|name| matches!(args.get(name), Some(ArgumentSpec::String { .. })));
    if to_ok && copies_ok && text_ok {
        Ok(())
    } else {
        Err("cloud_pack_template_mail_invalid")
    }
}

/// Every `rfc822` template inside a body.
pub(crate) fn find(template: &Template) -> Vec<&MailTemplate> {
    let mut found = Vec::new();
    collect(template, &mut found);
    found
}

fn collect<'a>(template: &'a Template, found: &mut Vec<&'a MailTemplate>) {
    match template {
        Template::Rfc822(mail) => found.push(mail),
        Template::Object(fields) => fields.iter().for_each(|f| collect(&f.value, found)),
        Template::Array(items) => items.iter().for_each(|item| collect(item, found)),
        Template::Each { item, .. } => collect(item, found),
        Template::Keyed { value, .. } => collect(value, found),
        Template::Arg(_) | Template::Const(_) | Template::Element(_) => {}
    }
}

/// The base64url-encoded message, or `None` when an address is not a bare `local@domain`.
pub(crate) fn render(mail: &MailTemplate, args: &Map<String, Value>) -> Option<String> {
    let mut message = String::new();
    for (header, name) in [
        ("To", Some(&mail.to)),
        ("Cc", mail.cc.as_ref()),
        ("Bcc", mail.bcc.as_ref()),
    ] {
        let Some(list) = name.and_then(|name| args.get(name)) else {
            continue;
        };
        let addresses = list
            .as_array()?
            .iter()
            .map(|value| value.as_str().filter(|text| bare_address(text)))
            .collect::<Option<Vec<_>>>()?;
        if addresses.is_empty() {
            continue;
        }
        message.push_str(&format!("{header}: {}\r\n", addresses.join(",\r\n ")));
    }
    if !message.starts_with("To: ") {
        return None;
    }
    let subject = args
        .get(&mail.subject)
        .and_then(Value::as_str)
        .unwrap_or("");
    let text = args.get(&mail.text).and_then(Value::as_str).unwrap_or("");
    let words = subject_words(subject)
        .iter()
        .map(|word| format!("=?UTF-8?B?{}?=", STANDARD.encode(word.as_bytes())))
        .collect::<Vec<_>>();
    message.push_str(&format!("Subject: {}\r\n", words.join("\r\n ")));
    message.push_str("MIME-Version: 1.0\r\n");
    message.push_str("Content-Type: text/plain; charset=\"UTF-8\"\r\n");
    message.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    let body = STANDARD.encode(text.as_bytes());
    for chunk in body.as_bytes().chunks(LINE) {
        message.push_str(std::str::from_utf8(chunk).ok()?);
        message.push_str("\r\n");
    }
    Some(URL_SAFE.encode(message.as_bytes()))
}

/// The subject cut into pieces of at most [`WORD_BYTES`] bytes on character boundaries, so
/// each encoded word stays within RFC 2047's 75 characters and every folded line stays short.
fn subject_words(subject: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut rest = subject;
    while rest.len() > WORD_BYTES {
        let mut cut = WORD_BYTES;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        let (word, tail) = rest.split_at(cut);
        words.push(word);
        rest = tail;
    }
    words.push(rest);
    words
}

/// `local@domain` with an atom-text local part and a DNS domain: no names, brackets, spaces or separators.
fn bare_address(text: &str) -> bool {
    let Some((local, domain)) = text.rsplit_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b));
    local_ok && crate::cloud_pack_validate::valid_host(&domain.to_ascii_lowercase())
}
