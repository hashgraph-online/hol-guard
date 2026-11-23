//! The evidence table and its indexes: a mirror of `evidence_schema_statement`
//! and `evidence_index_statements` in `store_evidence.py`. A parity test on
//! the Python side holds the copies equal.

pub(super) const EVIDENCE_TABLE: &str = r##"create table if not exists guard_evidence (
  evidence_id     text not null primary key,
  action_id       text not null default '',
  request_id      text not null default '',
  harness         text not null default '',
  workspace       text not null default '',
  signal_id       text not null default '',
  category        text not null default '',
  severity        text not null default '',
  confidence      real not null default 0.0,
  summary         text not null default '',
  details_json    text not null default '{}',
  action_identity text,
  created_at      text not null
)"##;

pub(super) const EVIDENCE_IDENTITY_COLUMN: [(&str, &str); 1] = [("action_identity", "text")];

pub(super) const EVIDENCE_INDEXES: [&str; 11] = [
    "create index if not exists idx_evidence_created on guard_evidence(created_at desc)",
    "create index if not exists idx_evidence_request on guard_evidence(request_id)",
    "create index if not exists idx_evidence_action on guard_evidence(action_id)",
    "create index if not exists idx_evidence_category_severity on guard_evidence(category, severity)",
    "create index if not exists idx_evidence_harness_workspace on guard_evidence(harness, workspace)",
    "create index if not exists idx_evidence_identity on guard_evidence(action_identity)",
    "create index if not exists idx_evidence_request_created on guard_evidence(request_id, created_at desc)",
    "create index if not exists idx_evidence_identity_created on guard_evidence(action_identity, created_at desc)",
    "create index if not exists idx_evidence_harness_created on guard_evidence(harness, created_at desc)",
    "create index if not exists idx_evidence_category_severity_created on guard_evidence(category, severity, created_at desc)",
    "create index if not exists idx_evidence_harness_category_severity_created on guard_evidence(harness, category, severity, created_at desc)",
];
