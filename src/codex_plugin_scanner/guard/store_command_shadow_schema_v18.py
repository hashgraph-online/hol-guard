"""Frozen initial-v18 command-shadow schema profile."""

# ruff: noqa: E501

from __future__ import annotations

from typing import Final

INITIAL_V18_SCHEMA_STATEMENTS: Final = (
    """create table if not exists command_activity_shadow_evaluations (
      activity_id text primary key references command_activity(activity_id) on delete cascade,
      occurred_at text not null,
      authoritative_action text not null check (authoritative_action in ('allow', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block')),
      current_action text not null check (current_action in ('allow', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block')),
      current_disposition text not null check (current_disposition in ('silent-verified', 'silent-contained', 'workflow-authorized', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block')),
      proposed_action text not null check (proposed_action in ('allow', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block')),
      proposed_disposition text not null check (proposed_disposition in ('silent-verified', 'silent-contained', 'workflow-authorized', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block')),
      comparison text not null check (comparison in ('lowered', 'unchanged', 'strengthened')),
      proposal_version text not null check (
        length(proposal_version) between 1 and 128
        and proposal_version glob '[a-z]*'
        and proposal_version not glob '*[^a-z0-9.-]*'
      ),
      evaluator_schema_version text not null check (evaluator_schema_version in ('1.0.0', '1.1.0')),
      control_generation integer not null check (control_generation = 1),
      sample_basis_points integer not null check (sample_basis_points between 1 and 10000),
      schema_version text not null check (schema_version = 'guard.command-shadow.v1'),
      check (
        (current_action = 'allow' and current_disposition in (
          'silent-verified', 'silent-contained', 'workflow-authorized'
        )) or (current_action != 'allow' and current_disposition = current_action)
      ),
      check (
        (proposed_action = 'allow' and proposed_disposition in (
          'silent-verified', 'silent-contained', 'workflow-authorized'
        )) or (proposed_action != 'allow' and proposed_disposition = proposed_action)
      )
    ) strict""",
    """create table if not exists command_activity_shadow_cohorts (
      activity_id text not null references command_activity_shadow_evaluations(activity_id) on delete cascade,
      ordinal integer not null check (ordinal >= 0),
      cohort text not null check (cohort in ('baseline', 'cdx-060-verified-reads', 'cdx-061-contained-checks', 'cdx-062-contained-writes', 'cdx-063-task-capabilities', 'cdx-064-remote-mutation-floors', 'cdx-065-package-provenance-floors', 'cdx-066-critical-block-floors')),
      primary key (activity_id, ordinal),
      unique (activity_id, cohort)
    ) strict""",
    """create index if not exists idx_command_activity_shadow_comparison
    on command_activity_shadow_evaluations (comparison, occurred_at desc, activity_id desc)""",
    """create index if not exists idx_command_activity_shadow_cohort
    on command_activity_shadow_cohorts (cohort, activity_id)""",
    """create trigger if not exists trg_command_activity_shadow_evaluations_immutable
    before update on command_activity_shadow_evaluations
    begin select raise(abort, 'command_activity_shadow_evaluations_immutable'); end""",
    """create trigger if not exists trg_command_activity_shadow_cohorts_immutable
    before update on command_activity_shadow_cohorts
    begin select raise(abort, 'command_activity_shadow_cohorts_immutable'); end""",
    """create trigger if not exists trg_command_activity_shadow_require_activity
    before insert on command_activity_shadow_evaluations
    begin
      select case when not exists (
        select 1 from command_activity
        where activity_id = new.activity_id and occurred_at = new.occurred_at
      ) then raise(abort, 'command_activity_shadow_activity_missing') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_require_evaluation
    before insert on command_activity_shadow_cohorts
    begin
      select case when not exists (
        select 1 from command_activity_shadow_evaluations where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_evaluation_missing') end;
      select case when new.ordinal != (
        select count(*) from command_activity_shadow_cohorts where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_cohort_ordinal_invalid') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_require_comparison
    before insert on command_activity_shadow_evaluations
    begin
      select case when new.comparison != case
        when (
          case new.proposed_action
            when 'allow' then 0 when 'warn' then 1 when 'review' then 2
            when 'require-reapproval' then 3 when 'sandbox-required' then 4 else 5 end
        ) < (
          case new.current_action
            when 'allow' then 0 when 'warn' then 1 when 'review' then 2
            when 'require-reapproval' then 3 when 'sandbox-required' then 4 else 5 end
        ) then 'lowered'
        when new.proposed_action = new.current_action then 'unchanged'
        else 'strengthened'
      end then raise(abort, 'command_activity_shadow_comparison_invalid') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_delete_cohorts
    after delete on command_activity_shadow_evaluations
    begin
      delete from command_activity_shadow_cohorts where activity_id = old.activity_id;
    end""",
    """create trigger if not exists trg_command_activity_shadow_delete_evaluation
    after delete on command_activity
    begin
      delete from command_activity_shadow_evaluations where activity_id = old.activity_id;
    end""",
)

__all__ = ("INITIAL_V18_SCHEMA_STATEMENTS",)
