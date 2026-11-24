//! The Review outbox schema statements `review_event_outbox_schema_statements`
//! in `store_review_event_outbox_schema.py` runs: the event, cursor and
//! request-sequence tables, their indexes, the OAuth-source guard, and the
//! wake-generation table and triggers. Each statement is the Python text byte
//! for byte; `tests/test_native_schema_review_outbox_parity.py` holds the
//! copies equal.

pub(super) const OUTBOX_STATEMENTS: [&str; 13] = [
    r##"
        create table if not exists guard_review_outbox_events (
          stream_sequence integer primary key autoincrement,
          event_id text not null unique,
          local_request_id text not null,
          request_sequence integer not null,
          event_type text not null,
          event_schema_version integer not null,
          payload_json text not null,
          payload_hash text not null,
          occurred_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text,
          binding_status text not null check(binding_status in ('ready', 'quarantined')),
          quarantine_reason text,
          acknowledged_at text,
          attempt_count integer not null default 0,
          next_attempt_at text,
          last_error text,
          unique(local_request_id, request_sequence)
        )
        "##,
    r##"
        create table if not exists guard_review_outbox_cursors (
          oauth_source text not null,
          oauth_subject_hash text not null,
          workspace_id text not null,
          machine_id text not null,
          machine_installation_id text not null,
          acknowledged_stream_sequence integer not null default 0,
          updated_at text not null,
          primary key (
            oauth_source, oauth_subject_hash, workspace_id,
            machine_id, machine_installation_id
          )
        )
        "##,
    r##"
        create table if not exists guard_review_outbox_request_sequences (
          local_request_id text primary key,
          last_sequence integer not null check(last_sequence > 0),
          updated_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text
        )
        "##,
    r##"
        create index if not exists idx_guard_review_outbox_ready
        on guard_review_outbox_events (
          oauth_source, oauth_subject_hash, workspace_id, machine_id,
          machine_installation_id, binding_status, next_attempt_at, stream_sequence
        )
        "##,
    r##"
        create index if not exists idx_guard_review_outbox_request
        on guard_review_outbox_events (local_request_id, request_sequence)
        "##,
    r##"
        create index if not exists idx_guard_review_outbox_quarantine
        on guard_review_outbox_events (binding_status, quarantine_reason, stream_sequence)
        "##,
    r##"
        create index if not exists idx_guard_review_outbox_empty_payload_digest
        on guard_review_outbox_events (payload_hash) where payload_hash = ''
        "##,
    r##"
        create trigger if not exists guard_approval_oauth_source_immutable
        before update of oauth_source on approval_requests
        when old.oauth_source is not null and new.oauth_source is not old.oauth_source
        begin
          select raise(abort, 'approval OAuth source is immutable');
        end
        "##,
    r##"
        create table if not exists guard_review_outbox_wake_state (
          singleton integer primary key check(singleton = 1),
          generation integer not null
        )
        "##,
    r##"
        insert or ignore into guard_review_outbox_wake_state (singleton, generation)
        values (1, 0)
        "##,
    r##"
        create trigger if not exists guard_review_outbox_wake_after_insert
        after insert on guard_review_outbox_events
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1 where singleton = 1;
        end
    "##,
    r##"
        create trigger if not exists guard_review_outbox_wake_after_update
        after update on guard_review_outbox_events
        when old.binding_status is not new.binding_status
          or old.next_attempt_at is not new.next_attempt_at
          or old.acknowledged_at is not new.acknowledged_at
          or old.attempt_count is not new.attempt_count
          or old.payload_hash is not new.payload_hash
          or old.oauth_source is not new.oauth_source
          or old.oauth_subject_hash is not new.oauth_subject_hash
          or old.workspace_id is not new.workspace_id
          or old.machine_id is not new.machine_id
          or old.machine_installation_id is not new.machine_installation_id
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1 where singleton = 1;
        end
    "##,
    r##"
        create trigger if not exists guard_review_outbox_wake_after_delete
        after delete on guard_review_outbox_events
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1 where singleton = 1;
        end
    "##,
];
