//! An in-memory provider for acceptance tests (feature `testkit`).
//!
//! `FakeProvider` answers scripted responses by path and records every request it is asked to
//! carry, after the same host, path and credential checks the HTTPS client makes. Nothing here
//! opens a socket. It is never part of a release build.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

use crate::client::{
    checked_url, ProviderLimits, ProviderRequest, ProviderResponse, ProviderTransport,
};
use crate::ProviderClientError;

/// One request the fake saw. The key is kept only as a match flag, never as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: &'static str,
    pub url: String,
    pub header: String,
    pub key_matched: bool,
    pub body: Option<String>,
    pub limits: ProviderLimits,
}

/// A scripted answer: a response, or a failure the client would report.
pub type Scripted = Result<ProviderResponse, ProviderClientError>;

/// The fake provider.
pub struct FakeProvider {
    pinned_hosts: Vec<String>,
    expected_key: String,
    scripts: RefCell<BTreeMap<String, VecDeque<Scripted>>>,
    requests: RefCell<Vec<RecordedRequest>>,
}

impl FakeProvider {
    /// A fake pinned to `pinned_hosts` that expects `expected_key` in the credential header.
    pub fn new(pinned_hosts: &[&str], expected_key: &str) -> Self {
        Self {
            pinned_hosts: pinned_hosts.iter().map(|host| (*host).to_owned()).collect(),
            expected_key: expected_key.to_owned(),
            scripts: RefCell::new(BTreeMap::new()),
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Queue `answer` for the next request to `path`.
    pub fn script(&self, path: &str, answer: Scripted) {
        self.scripts
            .borrow_mut()
            .entry(path.to_owned())
            .or_default()
            .push_back(answer);
    }

    /// Queue a JSON answer with `status` for the next request to `path`.
    pub fn script_json(&self, path: &str, status: u16, body: &str) {
        self.script(
            path,
            Ok(ProviderResponse {
                status,
                body: body.as_bytes().to_vec(),
            }),
        );
    }

    /// Every request carried so far, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.borrow().clone()
    }
}

impl ProviderTransport for FakeProvider {
    fn send(
        &self,
        request: &ProviderRequest,
        limits: ProviderLimits,
    ) -> Result<ProviderResponse, ProviderClientError> {
        let url = checked_url(request, &self.pinned_hosts)?;
        self.requests.borrow_mut().push(RecordedRequest {
            method: request.method.as_str(),
            url,
            header: request.header.clone(),
            key_matched: request.key.as_str() == self.expected_key,
            body: request.body.clone(),
            limits,
        });
        let answer = self
            .scripts
            .borrow_mut()
            .get_mut(&request.path)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(ProviderClientError::Transport))?;
        if answer.body.len() as u64 > limits.max_response_bytes {
            return Err(ProviderClientError::ResponseTooLarge);
        }
        if (300..400).contains(&answer.status) {
            return Err(ProviderClientError::Transport);
        }
        Ok(answer)
    }
}
